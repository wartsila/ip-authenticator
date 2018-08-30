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

import static org.keycloak.models.utils.KeycloakModelUtils.getRoleFromString;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.RoleUtils;
import org.keycloak.sessions.AuthenticationSessionModel;

public class IpAuthenticatorUtil {

    private static final Logger logger = Logger.getLogger(IpAuthenticatorUtil.class);

    public static boolean authenticate(AuthenticationFlowContext context) {
        ConditionalActionMode actionMode = checkActionMode(context);

        if (actionMode == ConditionalActionMode.SKIP) {
            context.success();
            return true;
        }

        if (actionMode == ConditionalActionMode.ATTEMPTED) {
            context.attempted();
            return true;
        }

        if (tryAuthorize(context)) {
            return true;
        }

        return false;
    }

    private static String getIp(AuthenticationFlowContext context) {
        return IpUtil.getIp(context.getHttpRequest(), context.getSession());
    }

    static boolean tryAuthorize(AuthenticationFlowContext context) {
        String ipAddress = getIp(context);
        if (context.getUser().getAttribute(IpAuthorizeConstants.VERIFIED_IP_ADDRESS).stream()
                .map(IpAuthorizationEntry::parse).anyMatch(e -> e.authorize(ipAddress))) {
            context.success();
            return true;
        } else {
            return false;
        }
    }

    private static ConditionalActionMode checkActionMode(AuthenticationFlowContext context) {

        if (context.getAuthenticatorConfig() == null) {
            /*
             * No configuration exists.
             */
            return ConditionalActionMode.defaultValue();
        }

        ConditionalActionMode actionMode = checkModeForClients(context);
        if (actionMode == ConditionalActionMode.SKIP) {
            logger.infof("Skipping IP verification check: client is disabled");
            return actionMode;
        }

        UserModel user = context.getUser();
        actionMode = checkModeForRoles(context, user);

        if (actionMode == ConditionalActionMode.NOT_CHOSEN) {
            actionMode = checkBackupRole(context);
        }

        if (actionMode == ConditionalActionMode.NOT_CHOSEN) {
            actionMode = ConditionalActionMode.defaultValue();
        }
        return actionMode;
    }

    private static ConditionalActionMode checkModeForClients(AuthenticationFlowContext context) {
        if (IpAuthenticatorUtil.shouldSkipIpVerificationForClient(context)) {
            return ConditionalActionMode.SKIP;
        } else {
            return ConditionalActionMode.NOT_CHOSEN;
        }
    }

    private static ConditionalActionMode checkBackupRole(AuthenticationFlowContext context) {
        Map<String, String> config = context.getAuthenticatorConfig().getConfig();
        String defaultAuthorize = config.get(IpAuthorizeConstants.IP_DEFAULT_AUTHORIZE);
        return Stream.of(ConditionalActionMode.values())
                .filter(mode -> mode.toString().equalsIgnoreCase(defaultAuthorize)).findFirst()
                .orElse(ConditionalActionMode.NOT_CHOSEN);
    }

    private static ConditionalActionMode checkModeForRoles(AuthenticationFlowContext context, UserModel user) {
        Map<String, String> config = context.getAuthenticatorConfig().getConfig();
        Predicate<String> predicate = anyRolePredicate(context.getRealm(), user);

        if (predicate.test(config.get(IpAuthorizeConstants.FORCE_IP_AUTHORIZE_ROLE))) {
            return ConditionalActionMode.FORCE;
        }

        if (predicate.test(config.get(IpAuthorizeConstants.SKIP_IP_AUTHORIZE_ROLE))) {
            return ConditionalActionMode.SKIP;
        }

        return ConditionalActionMode.NOT_CHOSEN;
    }

    private static Predicate<String> anyRolePredicate(RealmModel realm, UserModel user) {
        Map<String, RoleModel> roles = new HashMap<>();
        Predicate<? super String> cached = roleName -> RoleUtils.hasRole(user.getRoleMappings(),
                roles.computeIfAbsent(roleName, r -> getRoleFromString(realm, r)));
        return str -> str == null ? false : Stream.of(str.split(",")).anyMatch(cached);
    }

    /**
     * Checks if IP verification should be skipped for the client that is currently logging in.
     * @param context AuthenticationFlowContext
     * @return true if IP verification should be skipped
     */
    public static boolean shouldSkipIpVerificationForClient(AuthenticationFlowContext context) {
        Map<String, String> config = context.getAuthenticatorConfig().getConfig();
        AuthenticationSessionModel authenticationSession = context.getAuthenticationSession();
        if (authenticationSession == null || authenticationSession.getClient() == null) {
            return false;
        }
        String clientId = authenticationSession.getClient().getClientId();
        List<String> skipClients = IpAuthenticatorUtil.getSkipClients(config);
        if (skipClients.isEmpty()) {
            return false;
        }

        logger.debugf("skip clients: " + config.get(IpAuthorizeConstants.SKIP_IP_AUTHORIZE_CLIENT));
        logger.debugf("client id: " + clientId);

        for (String skipClient : skipClients) {
            if (skipClient.equalsIgnoreCase(clientId)) {
                return true;
            }
        }

        return false;
    }

    private static List<String> getSkipClients(Map<String, String> config) {
        String skipClients = config.get(IpAuthorizeConstants.SKIP_IP_AUTHORIZE_CLIENT);
        if (skipClients == null) {
            return new ArrayList<>();
        }

        return Arrays.stream(skipClients.split(","))
                .map(String::trim)
                .collect(Collectors.toList());
    }
}
