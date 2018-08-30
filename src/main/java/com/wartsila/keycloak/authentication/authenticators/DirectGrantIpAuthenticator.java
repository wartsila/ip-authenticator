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

import static com.wartsila.keycloak.authentication.authenticators.IpAuthorizeConstants.*;
import static com.wartsila.keycloak.authentication.authenticators.IpAuthorizeConstants.IP_DEFAULT_AUTHORIZE;
import static org.keycloak.provider.ProviderConfigProperty.LIST_TYPE;
import static org.keycloak.provider.ProviderConfigProperty.ROLE_TYPE;
import static org.keycloak.provider.ProviderConfigProperty.STRING_TYPE;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.ws.rs.core.Response;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.directgrant.AbstractDirectGrantAuthenticator;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;

public class DirectGrantIpAuthenticator extends AbstractDirectGrantAuthenticator {

    public static final String AUTHENTICATOR_ID = "direct-grant-ip-authenticator";

    public static final String AUTHENTICATOR_NAME = "Direct Grant IP Authenticator";

    public static final String IP_VERIFICATION_MISSING = "verified_ip_missing_or_expired";

    private static final Logger logger = Logger.getLogger(DirectGrantIpAuthenticator.class);

    public static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED, AuthenticationExecutionModel.Requirement.DISABLED };

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        if (!IpAuthenticatorUtil.authenticate(context)) {

            UserModel user = context.getUser();
            String ip = IpUtil.getIp(context.getHttpRequest(), context.getSession());
            String clientId = context.getAuthenticationSession().getClient().getClientId();
            logger.infof("%s;%s;%s -- IP verification failed" , user.getUsername(), clientId, ip);

            context.getEvent().user(user);
            context.getEvent().error(IP_VERIFICATION_MISSING);
            Response challengeResponse = errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(),
                    IP_VERIFICATION_MISSING, "Verified IP missing or expired");
            context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
        }
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

    }

    @Override
    public String getDisplayType() {
        return AUTHENTICATOR_NAME;
    }

    @Override
    public String getReferenceCategory() {
        return "second-factor";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return true;
    }

    @Override
    public String getHelpText() {
        return "Direct Grant IP Authenticator. Note: does not handle IP verification itself, only verifies it.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {

        ProviderConfigProperty skipRole = new ProviderConfigProperty();
        skipRole.setType(ROLE_TYPE);
        skipRole.setName(SKIP_IP_AUTHORIZE_ROLE);
        skipRole.setLabel("Roles to SKIP");
        skipRole.setHelpText("Skip authenticator and return success");

        ProviderConfigProperty forceRole = new ProviderConfigProperty();
        forceRole.setType(ROLE_TYPE);
        forceRole.setName(FORCE_IP_AUTHORIZE_ROLE);
        forceRole.setLabel("Roles to FORCE");
        forceRole.setHelpText("Authenticator is run and return value depends on IP validations");

        ProviderConfigProperty skipClients = new ProviderConfigProperty();
        skipClients.setType(STRING_TYPE);
        skipClients.setName(SKIP_IP_AUTHORIZE_CLIENT);
        skipClients.setLabel("Client IDs to SKIP");
        skipClients.setHelpText("Skip authenticator for listed client IDs and return success (comma separated list).");

        ProviderConfigProperty defaultOutcome = new ProviderConfigProperty();
        defaultOutcome.setType(LIST_TYPE);
        defaultOutcome.setName(IP_DEFAULT_AUTHORIZE);
        defaultOutcome.setLabel("Fallback mode");
        defaultOutcome.setOptions(
                Stream.of(ConditionalActionMode.SKIP, ConditionalActionMode.ATTEMPTED, ConditionalActionMode.FORCE)
                        .map(Enum::toString).collect(Collectors.toList()));
        defaultOutcome
                .setHelpText(String.format("What to do in case mode could not be otherwise determined. Defaults to %s.",
                        ConditionalActionMode.defaultValue()));

        return Arrays
                .asList(skipRole, forceRole, skipClients, defaultOutcome);
    }

    @Override
    public String getId() {
        return AUTHENTICATOR_ID;
    }
}
