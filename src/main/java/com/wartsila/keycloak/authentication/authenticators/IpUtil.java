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

import org.jboss.logging.Logger;
import org.jboss.resteasy.spi.HttpRequest;
import org.keycloak.models.KeycloakSession;

public class IpUtil {

    private static final Logger logger = Logger.getLogger(IpUtil.class);

    /**
     * Extracts real IP from request (using X-Forwarded-For header). Falls back to remote address defined
     * in ClientConnection.
     * 
     * @param request HTTP request
     * @param session Keycloak session
     * @return Users IP address
     */
    public static String getIp(HttpRequest request, KeycloakSession session) {
        String address = getIpFromXff(request);
        if (address == null) {
            // fallback to remote address
            address = session.getContext().getConnection().getRemoteAddr();
        }

        logger.debugf("Client IP address interpreted as %s", address);
        return address;
    }

    private static String getIpFromXff(HttpRequest request) {
        String xff = request.getHttpHeaders().getHeaderString("X-Forwarded-For");
        logger.debugf("X-Forwarded-For: %s", xff);

        if (xff != null && xff.indexOf(",") > 0) {
            // if there's multiple IP's, the first one is the client IP, the rest are proxies.
            String onlyClientIp = xff.substring(0, xff.indexOf(",")).trim();
            logger.debugf("From X-Forwarded-For, interpreted %s as client IP", onlyClientIp);
            return onlyClientIp;
        }
        return xff;
    }

}
