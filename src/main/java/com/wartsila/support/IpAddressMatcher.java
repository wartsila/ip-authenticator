/*
/*
 * Copyright 2017 Wärtsilä and original authors.
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

/*
 * Adapted from org.springframework.security.web.util.matcher.IpAddressMatcher in spring-security
 * (https://projects.spring.io/spring-security/).
 *
 */
package com.wartsila.support;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;

public final class IpAddressMatcher {
    private final int nMaskBits;
    private final InetAddress requiredAddress;

    /**
     * Takes a specific IP address or a range specified using the
     * IP/Netmask (e.g. 192.168.1.0/24 or 202.24.0.0/14).
     *
     * @param ipAddress the address or range of addresses from which the request must come.
     */
    public IpAddressMatcher(String ipAddress) {

        int indexOf = ipAddress.indexOf('/');
        if (indexOf > 0) {
            ipAddress = ipAddress.substring(0, indexOf);
            this.nMaskBits = Integer.parseInt(ipAddress.substring(indexOf + 1));
        } else {
            this.nMaskBits = -1;
        }
        this.requiredAddress = parseAddress(ipAddress);
    }

    public boolean matches(String address) {
        InetAddress remoteAddress = parseAddress(address);

        if (!this.requiredAddress.getClass().equals(remoteAddress.getClass())) {
            return false;
        }

        if (this.nMaskBits < 0) {
            return remoteAddress.equals(this.requiredAddress);
        }

        byte[] remAddr = remoteAddress.getAddress();
        byte[] reqAddr = this.requiredAddress.getAddress();

        int oddBits = this.nMaskBits % 8;
        int nMaskBytes = this.nMaskBits / 8 + (oddBits == 0 ? 0 : 1);
        byte[] mask = new byte[nMaskBytes];

        Arrays.fill(mask, 0, oddBits == 0 ? mask.length : mask.length - 1, (byte) 0xFF);

        if (oddBits != 0) {
            int finalByte = (1 << oddBits) - 1;
            finalByte <<= 8 - oddBits;
            mask[mask.length - 1] = (byte) finalByte;
        }

        for (int i = 0; i < mask.length; i++) {
            if ((remAddr[i] & mask[i]) != (reqAddr[i] & mask[i])) {
                return false;
            }
        }

        return true;
    }

    private InetAddress parseAddress(String address) {
        try {
            return InetAddress.getByName(address);
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("Failed to parse address" + address, e);
        }
    }
}
