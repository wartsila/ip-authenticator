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

import org.keycloak.Config.Scope;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

public class IpAuthenticatorFactory implements AuthenticatorFactory {

    public static final long IP_AUTHORIZE_EXPIRES_SECONDS_DEFAULT_VALUE = 60 * 60 * 24 * 30;

    public static final String AUTHENTICATOR_ID = "ip-authenticator";

    public static final String AUTHENTICATOR_NAME = "IP Authenticator";

    @Override
    public Authenticator create(KeycloakSession session) {
        return new IpAuthenticator();
    }

    @Override
    public void init(Scope config) {
        // NOOP
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // NOOP
    }

    @Override
    public void close() {
        // NOOP
    }

    @Override
    public String getId() {
        return AUTHENTICATOR_ID;
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
    public Requirement[] getRequirementChoices() {
        return new Requirement[] { Requirement.REQUIRED, Requirement.ALTERNATIVE, Requirement.OPTIONAL,
                Requirement.DISABLED };
    }

    @Override
    public boolean isUserSetupAllowed() {
        return true;
    }

    @Override
    public String getHelpText() {
        return "Allows users to whitelist IP addresses for login through confirmation email containing secret nonce.";
    }

    public List<ProviderConfigProperty> getConfigProperties() {
        ProviderConfigProperty skipRole = new ProviderConfigProperty();
        skipRole.setType(ROLE_TYPE);
        skipRole.setName(SKIP_IP_AUTHORIZE_ROLE);
        skipRole.setLabel("Roles to SKIP");
        skipRole.setHelpText("Skip authenticator and return success");

        ProviderConfigProperty attemptRole = new ProviderConfigProperty();
        attemptRole.setType(ROLE_TYPE);
        attemptRole.setName(ATTEMPT_IP_AUTHORIZE_ROLE);
        attemptRole.setLabel("Roles to ATTEMPTED");
        attemptRole.setHelpText("Skip authenticator and return attempted");

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

        ProviderConfigProperty authenticationValiditySeconds = new ProviderConfigProperty();
        authenticationValiditySeconds.setType(ProviderConfigProperty.STRING_TYPE);
        authenticationValiditySeconds.setName(IpAuthorizeConstants.IP_AUTHORIZE_EXPIRES_SECONDS);
        authenticationValiditySeconds.setLabel(
                "How many seconds to maintain IP authorization. May be empty to permanently whitelist IP addresses.");
        authenticationValiditySeconds.setDefaultValue(String.valueOf(IP_AUTHORIZE_EXPIRES_SECONDS_DEFAULT_VALUE));

        return Arrays
                .asList(skipRole, attemptRole, forceRole, skipClients, defaultOutcome, authenticationValiditySeconds);
    }
}
