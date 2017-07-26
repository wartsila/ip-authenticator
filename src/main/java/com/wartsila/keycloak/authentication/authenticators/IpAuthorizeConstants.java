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

/**
 * Constants
 *
 * @author ilmtee
 *
 */
public abstract class IpAuthorizeConstants {

    public static final String VERIFIED_IP_ADDRESS = "verified-ip-address";

    public static final String FORCE_IP_AUTHORIZE_ROLE = "forceIpAuthorizeRole";

    public static final String SKIP_IP_AUTHORIZE_ROLE = "skipIpAuthorizeRole";

    public static final String SKIP_IP_AUTHORIZE_CLIENT = "skipIpAuthorizeClient";

    public static final String ATTEMPT_IP_AUTHORIZE_ROLE = "attemptedItAuthorizeRole";

    public static final String IP_DEFAULT_AUTHORIZE = "defaultAuthorize";

    public static final String IP_AUTHORIZE_EXPIRES_SECONDS = "authorizationExpiresSeconds";

    public static final String IP_VERIFICATION_EMAIL_ALREADY_SENT_MESSAGE = "ipVerificationEmailAlreadySent";

    public static final String IP_VERIFICATION_INVALID_NONCE_MESSAGE = "ipVerificationInvalidNonceMessage";

    public static final String IP_VERIFICATION_INVALID_EMAIL_MESSAGE = "ipVerificiationFailedEmailMessage";

    public static final String IP_VERIFICIATION_FAILED_EMAIL_CHANGED_MESSAGE = "ipVerificiationFailedEmailChangedMessage";

    public static final String IP_VERIFICATION_SUCCESS_MESSAGE = "ipVerificationSuccessMessage";

    private IpAuthorizeConstants() {
        super();
    }

}
