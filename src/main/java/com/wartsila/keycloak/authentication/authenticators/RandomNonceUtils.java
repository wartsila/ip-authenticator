/*
 * Copyright 2018 Wärtsilä
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

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public final class RandomNonceUtils {
    private RandomNonceUtils() {
        // utility
    }

    private static final String UPPER_CHARACTERS = "ABCDEFGHJKLMNPQRSTUVWY";
    private static final String NUMBER_CHARACTERS = "23456789";

    /**
     * List of characters to be used. only characters that don't look like each other.
     */
    private static final String PASSWORD_CHARACTERS = UPPER_CHARACTERS + NUMBER_CHARACTERS;

    private static final SecureRandom RND = new SecureRandom();

    public static String makeManualNonce() {
        int length = 4;
        synchronized (RND) {
            List<Character> array = new ArrayList<>();
            // at least one of each character class
            array.add(randomLetter(UPPER_CHARACTERS));
            array.add(randomLetter(NUMBER_CHARACTERS));
            // then randomly any character
            for (int i = 2; i < length; i++) {
                array.add(randomLetter(PASSWORD_CHARACTERS));
            }
            // finally shuffle the results so that forced character classes are randomly placed
            Collections.shuffle(array, RND);
            StringBuilder sb = new StringBuilder();
            array.forEach(sb::append);
            return sb.toString();
        }
    }

    private static char randomLetter(String characters) {
        return characters.charAt(RND.nextInt(characters.length()));
    }
}
