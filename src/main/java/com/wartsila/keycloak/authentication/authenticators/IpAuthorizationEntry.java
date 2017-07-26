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

import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.regex.Pattern;

import com.wartsila.support.IpAddressMatcher;

public class IpAuthorizationEntry {

    private static final String SEPARATOR = ";";

    private static final ZoneId ZONE = ZoneId.of("GMT");

    public static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss")
            .withZone(ZONE);

    public static IpAuthorizationEntry parse(String text) {
        IpAuthorizationEntry entry = new IpAuthorizationEntry();
        String[] parts = text.split(Pattern.quote(SEPARATOR));
        entry.setIpAddress(parts[0]);

        if (parts.length > 1) {
            entry.setValidUntil(FORMATTER.parse(parts[1], ZonedDateTime::from));
        } else {
            // Legacy
            entry.setValidUntil(Instant.ofEpochMilli(0).atZone(ZONE));
        }
        return entry;
    }

    public static IpAuthorizationEntry from(IpAuthorizeActionToken token) {
        IpAuthorizationEntry entry = new IpAuthorizationEntry();
        entry.setIpAddress(token.getIpAddress());
        entry.setValidUntil(Instant.ofEpochMilli(token.getAuthorizationExpires()).atZone(ZONE));
        return entry;
    }

    private String ipAddress;

    private ZonedDateTime validUntil;

    /**
     * Format this entry for storage.
     *
     * @return formatted value.
     */
    public String format() {
        return this.ipAddress + SEPARATOR + FORMATTER.format(this.validUntil);
    }

    public boolean authorize(String ipAddress) {
        return isNonExpired() && matches(ipAddress);
    }

    public boolean matches(String ipAddress) {
        return new IpAddressMatcher(this.ipAddress).matches(ipAddress);
    }

    public boolean isNonExpired() {
        return this.validUntil != null && this.validUntil.toInstant().isAfter(Instant.now());
    }

    public String getIpAddress() {
        return this.ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public ZonedDateTime getValidUntil() {
        return this.validUntil;
    }

    public void setValidUntil(ZonedDateTime validUntil) {
        this.validUntil = validUntil;
    }

    @Override
    public String toString() {
        return format();
    }
}
