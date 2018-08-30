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
import java.util.List;

import javax.ws.rs.core.Response;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.authentication.actiontoken.AbstractActionTokenHander;
import org.keycloak.authentication.actiontoken.ActionTokenContext;
import org.keycloak.authentication.actiontoken.ActionTokenHandler;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.Constants;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.AuthenticationSessionProvider;
import org.keycloak.sessions.CommonClientSessionModel.ExecutionStatus;

public class IpAuthorizeActionTokenHandler extends AbstractActionTokenHander<IpAuthorizeActionToken>
        implements ActionTokenHandler<IpAuthorizeActionToken> {

    private static final Logger logger = Logger.getLogger(IpAuthorizeActionTokenHandler.class);

    public IpAuthorizeActionTokenHandler() {
        super(IpAuthorizeActionToken.TOKEN_TYPE, IpAuthorizeActionToken.class, Messages.INVALID_CODE, EventType.LOGIN,
                Errors.NOT_ALLOWED);
    }

    @Override
    public Response handleToken(IpAuthorizeActionToken token, ActionTokenContext<IpAuthorizeActionToken> tokenContext) {
        UserModel user = tokenContext.getAuthenticationSession().getAuthenticatedUser();

        String email = token.getEmail().toLowerCase();
        if (!email.equalsIgnoreCase(user.getEmail())) {
            Response response = tokenContext.getSession().getProvider(LoginFormsProvider.class)
                    .setError(IpAuthorizeConstants.IP_VERIFICIATION_FAILED_EMAIL_CHANGED_MESSAGE).createInfoPage();
            return response;
        }

        AuthenticationSessionModel authSession = tokenContext.getAuthenticationSession();

        List<String> list = new ArrayList<>(user.getAttribute(IpAuthorizeConstants.VERIFIED_IP_ADDRESS));
        list.add(IpAuthorizationEntry.from(token).format());
        user.setAttribute(IpAuthorizeConstants.VERIFIED_IP_ADDRESS, list);

        RealmModel realm = tokenContext.getRealm();
        if (tokenContext.isAuthenticationSessionFresh()) {
            AuthenticationSessionManager asm = new AuthenticationSessionManager(tokenContext.getSession());
            asm.removeAuthenticationSession(realm, authSession, true);

            AuthenticationSessionProvider authSessProvider = tokenContext.getSession().authenticationSessions();
            authSession = authSessProvider.getAuthenticationSession(realm, token.getAuthenticationSessionId());

            return tokenContext.getSession().getProvider(LoginFormsProvider.class)
                    .setSuccess(IpAuthorizeConstants.IP_VERIFICATION_SUCCESS_MESSAGE, token.getIpAddress())
                    .setAttribute(Constants.SKIP_LINK, false).createInfoPage();
        }

        authSession.setExecutionStatus(IpAuthenticatorFactory.AUTHENTICATOR_ID, ExecutionStatus.SUCCESS);

        AuthenticationFlowModel flow = realm.getBrowserFlow();
        return tokenContext.processFlow(true, authSession.getAuthNote(AuthenticationProcessor.CURRENT_FLOW_PATH), flow,
                null, new AuthenticationProcessor());
    }
}
