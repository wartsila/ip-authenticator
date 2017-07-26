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
package com.wartsila.keycloak.email;

import java.util.Map;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailSenderProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.theme.FreeMarkerException;
import org.keycloak.theme.FreeMarkerUtil;
import org.keycloak.theme.Theme;
import org.keycloak.theme.ThemeProvider;

public class EmailUtil {

    private static final Logger logger = Logger.getLogger(EmailUtil.class);

    private final FreeMarkerUtil freeMarker;

    private final EmailSenderProvider emailSenderProvider;

    private UserModel user;

    private RealmModel realm;

    private Theme theme;

    public static EmailUtil from(AuthenticationFlowContext context) throws EmailException {
        try {
            EmailSenderProvider senderProvider = context.getSession().getProvider(EmailSenderProvider.class);

            RealmModel realm = context.getRealm();
            KeycloakSession session = context.getSession();
            ThemeProvider themeProvider = session.getProvider(ThemeProvider.class, "extending");
            Theme theme = themeProvider.getTheme(realm.getEmailTheme(), Theme.Type.EMAIL);

            return new EmailUtil(new FreeMarkerUtil(), senderProvider).setRealm(realm).setTheme(theme)
                    .setUser(context.getUser());
        } catch (Exception e) {
            throw new EmailException("Failed to template email", e);
        }
    }

    public EmailUtil(FreeMarkerUtil freeMarker, EmailSenderProvider emailSenderProvider) {
        super();
        this.freeMarker = freeMarker;
        this.emailSenderProvider = emailSenderProvider;
    }

    public void send(String template, String subject, Map<String, Object> attributes) throws EmailException {

        attributes.put("user", this.user);

        String textTemplate = String.format("text/%s", template);
        String textBody;
        try {
            textBody = this.freeMarker.processTemplate(attributes, textTemplate, this.theme);
        } catch (final FreeMarkerException e) {
            logger.debug("", e);
            textBody = null;
        }
        String htmlTemplate = String.format("html/%s", template);
        String htmlBody;
        try {
            htmlBody = this.freeMarker.processTemplate(attributes, htmlTemplate, this.theme);
        } catch (final FreeMarkerException e) {
            logger.debug("", e);
            htmlBody = null;
        }

        this.emailSenderProvider.send(this.realm.getSmtpConfig(), this.user, subject, textBody, htmlBody);
    }

    public EmailUtil setTheme(Theme theme) {
        this.theme = theme;
        return this;
    }

    public EmailUtil setRealm(RealmModel realm) {
        this.realm = realm;
        return this;
    }

    public EmailUtil setUser(UserModel user) {
        this.user = user;
        return this;
    }
}
