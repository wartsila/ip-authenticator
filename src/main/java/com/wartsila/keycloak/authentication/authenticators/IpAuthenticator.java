/*
 * Copyright 2017 Wärtsilä
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package com.wartsila.keycloak.authentication.authenticators;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.FlowStatus;
import org.keycloak.common.util.Time;
import org.keycloak.email.EmailException;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.Event;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;

import com.wartsila.keycloak.email.EmailUtil;

public class IpAuthenticator implements Authenticator {

    private static final String IP_SECRET = "ip-secret";
    private static final String IP_ADDRESS = "ip-address";
    private static final String IP_AUTHORIZE_SENT_FTL = "ip-authorize-sent.ftl";
    private static final String IP_AUTHORIZE_FTL = "ip-authorize.ftl";
    private static final Logger logger = Logger.getLogger(IpAuthenticator.class);

    @Override
    public void close() {
        // NOOP
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        if (IpAuthenticatorUtil.authenticate(context)) {
            UserModel user = context.getUser();
            String ip = getIp(context);
            String clientId = context.getAuthenticationSession().getClient().getClientId();
            infoLog(user.getUsername(), clientId, ip, "already valid IP address.");
        } else {
            Response challengeResponse = challenge(context);
            context.challenge(challengeResponse);
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        String ip = getIp(context);
        String clientId = context.getAuthenticationSession().getClient().getClientId();

        if (context.getStatus() == FlowStatus.SUCCESS) {
            infoLog(user.getUsername(), clientId, ip, "IP authentication flow status SUCCESS.");
            return;
        }

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        if (formData.containsKey("cancel")) {
            context.cancelLogin();
            infoLog(user.getUsername(), clientId, ip, "IP authentication flow cancelled.");
            return;
        }

        if (IpAuthenticatorUtil.tryAuthorize(context)) {
            infoLog(user.getUsername(), clientId, ip, "IP authorize success.");
            return;
        }

        if (formData.containsKey("continue")) {
            String secret = formData.getFirst("nonce").trim();
            if (secret.equals(context.getAuthenticationSession().getAuthNote(IP_SECRET))) {

                infoLog(user.getUsername(), clientId, ip, "IP verification success with secret \"" + secret + "\"");

                List<String> list = new ArrayList<>(user.getAttribute(IpAuthorizeConstants.VERIFIED_IP_ADDRESS));
                list.add(context.getAuthenticationSession().getAuthNote(IP_ADDRESS));
                user.setAttribute(IpAuthorizeConstants.VERIFIED_IP_ADDRESS, list);
                context.getAuthenticationSession().removeAuthNote(IP_ADDRESS);
                context.getAuthenticationSession().removeAuthNote(IP_SECRET);
                context.success();
                return;
            } else {
                infoLog(user.getUsername(), clientId, ip, "Invalid IP verification secret \"" + secret + "\"");
                context.forceChallenge(
                        context.form().setError(IpAuthorizeConstants.IP_VERIFICATION_INVALID_NONCE_MESSAGE)
                                .createForm(IP_AUTHORIZE_SENT_FTL));
                return;
            }
        }

        infoLog(user.getUsername(), clientId, ip, "IP verification required");

        String email = formData.getFirst("email");
        if (email != null && email.equalsIgnoreCase(user.getEmail())) {
            email = email.toLowerCase().trim();
            infoLog(user.getUsername(), clientId, ip, "Found user with email " + email);
            if (context.getAuthenticationSession().getAuthNote(IP_ADDRESS) != null) {
                context.forceChallenge(
                        context.form().setError(IpAuthorizeConstants.IP_VERIFICATION_EMAIL_ALREADY_SENT_MESSAGE)
                                .createForm(IP_AUTHORIZE_SENT_FTL));
                return;
            }

            String ipAddress = getIp(context);
            AuthenticationSessionModel authenticationSession = context.getAuthenticationSession();
            int validityInSecs = context.getRealm().getActionTokenGeneratedByUserLifespan();
            int absoluteExpirationInSecs = Time.currentTime() + validityInSecs;

            // We send the secret in the email in a link as a query param.
            IpAuthorizeActionToken token = new IpAuthorizeActionToken(user.getId(), absoluteExpirationInSecs,
                    authenticationSession.getId());
            token.setEmail(email);
            token.setIpAddress(ipAddress);
            token.setFlowId(context.getExecution().getFlowId());
            token.setAuthorizationExpires(authenticationExpires(context));

            String link = UriBuilder
                    .fromUri(context.getActionTokenUrl(
                            token.serialize(context.getSession(), context.getRealm(), context.getUriInfo())))
                    .build().toString();

            try {
                HashMap<String, Object> attributes = new HashMap<>();
                attributes.put("ip", ipAddress);
                attributes.put("link", link);
                attributes.put("linkExpiration", TimeUnit.SECONDS.toMinutes(validityInSecs));
                attributes.put("realmName", context.getRealm().getName());
                attributes.put("nonce", token.getActionVerificationNonce());

                EmailUtil.from(context).send(IP_AUTHORIZE_FTL, "Eniram IP verification", attributes);

                infoLog(user.getUsername(), clientId, ip, "Email with verification code " + token.getActionVerificationNonce() + " sent to " + user.getEmail());

                context.getAuthenticationSession().setAuthNote(IP_SECRET,
                        token.getActionVerificationNonce().toString().trim());
                context.getAuthenticationSession().setAuthNote(IP_ADDRESS, IpAuthorizationEntry.from(token).format());

                context.forceChallenge(
                        context.form().setSuccess(Messages.EMAIL_SENT).createForm(IP_AUTHORIZE_SENT_FTL));
            } catch (EmailException e) {
                context.getEvent().clone().event(EventType.CUSTOM_REQUIRED_ACTION)
                        .detail(Details.USERNAME, user.getUsername()).user(user).error(Errors.EMAIL_SEND_FAILED);
                Response challenge = context.form().setError(Errors.EMAIL_SEND_FAILED).createErrorPage();
                context.failure(AuthenticationFlowError.INTERNAL_ERROR, challenge);
            }
        } else {
            infoLog(user.getUsername(), clientId, ip, "Email " + email + " does not match the one on record " + user.getEmail());
            context.challenge(
                    challenge(context, f -> f.setError(IpAuthorizeConstants.IP_VERIFICATION_INVALID_EMAIL_MESSAGE)));
        }
    }

    private void infoLog(String username, String clientId, String ip, String s) {
        logger.infof("%s;%s;%s -- " + s, username, clientId, ip);
    }

    private long authenticationExpires(AuthenticationFlowContext context) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        long expiresAfter;
        if (config == null) {
            expiresAfter = IpAuthenticatorFactory.IP_AUTHORIZE_EXPIRES_SECONDS_DEFAULT_VALUE;
        } else {
            String text = config.getConfig().get(IpAuthorizeConstants.IP_AUTHORIZE_EXPIRES_SECONDS);
            if (text == null || text.isEmpty()) {
                expiresAfter = IpAuthenticatorFactory.IP_AUTHORIZE_EXPIRES_SECONDS_DEFAULT_VALUE;
            } else {
                expiresAfter = Long.valueOf(text);
            }
        }
        return System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(expiresAfter);
    }

    protected Response challenge(AuthenticationFlowContext context) {
        return challenge(context, f -> {
        });
    }

    protected Response challenge(AuthenticationFlowContext context, Consumer<LoginFormsProvider> editor) {
        LoginFormsProvider forms = context.form();
        forms.setAttribute("ip", getIp(context));
        editor.accept(forms);
        return forms.createForm(IP_AUTHORIZE_FTL);
    }

    private String getIp(AuthenticationFlowContext context) {
        return IpUtil.getIp(context.getHttpRequest(), context.getSession());
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        String email = user.getEmail();
        return email != null && !email.equals("");
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // never called
    }

    public static class IpAuthorizeEmailEvent extends Event {

    }
}
