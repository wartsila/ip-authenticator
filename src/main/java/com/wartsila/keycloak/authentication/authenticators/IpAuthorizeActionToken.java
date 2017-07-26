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

import org.keycloak.authentication.actiontoken.DefaultActionToken;

import com.fasterxml.jackson.annotation.JsonProperty;

public class IpAuthorizeActionToken extends DefaultActionToken {

    private static final long serialVersionUID = 1L;

    public static final String TOKEN_TYPE = IpAuthenticatorFactory.AUTHENTICATOR_ID;

    @JsonProperty(value = "eml")
    private String email;

    @JsonProperty(value = "ip")
    private String ipAddress;

    @JsonProperty(value = "fi")
    private String flowId;

    @JsonProperty(value = "ex")
    private long authorizationExpires;

    public IpAuthorizeActionToken(String userId, int absoluteExpirationInSecs, String authenticationSessionId) {
        super(userId, TOKEN_TYPE, absoluteExpirationInSecs, null, authenticationSessionId);
    }

    @SuppressWarnings("unused")
    private IpAuthorizeActionToken() {
        // Required to read from JWT
        super();
    }

    public String getEmail() {
        return this.email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getIpAddress() {
        return this.ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public String getFlowId() {
        return this.flowId;
    }

    public void setFlowId(String flowId) {
        this.flowId = flowId;
    }

    public long getAuthorizationExpires() {
        return this.authorizationExpires;
    }

    public void setAuthorizationExpires(long expires) {
        this.authorizationExpires = expires;
    }
}