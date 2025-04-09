/******************************************************************************
 * Licensed to the Apache Software Foundation (ASF) under one                 *
 * or more contributor license agreements.  See the NOTICE file               *
 * distributed with this work for additional information                      *
 * regarding copyright ownership.  The ASF licenses this file                 *
 * to you under the Apache License, Version 2.0 (the                          *
 * "License"); you may not use this file except in compliance                 *
 * with the License.  You may obtain a copy of the License at                 *
 *                                                                            *
 *   http://www.apache.org/licenses/LICENSE-2.0                               *
 *                                                                            *
 * Unless required by applicable law or agreed to in writing,                 *
 * software distributed under the License is distributed on an                *
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY                     *
 * KIND, either express or implied.  See the License for the                  *
 * specific language governing permissions and limitations                    *
 * under the License.                                                         *
 ******************************************************************************/
 
package org.apache.james.jdkim.parser;

import java.util.Arrays;

public class DKIMQuotedPrintable {
    public static String dkimQuotedPrintableDecode(CharSequence input)
            throws IllegalArgumentException {
        StringBuilder sb = new StringBuilder(input.length());
        // TODO should we fail on WSP that is not part of FWS?
        // the specification in 2.6 DKIM-Quoted-Printable is not
        // clear
        int state = 0;
        int start = 0;
        int d = 0;
        boolean lastWasNL = false;
        for (int i = 0; i < input.length(); i++) {
            if (lastWasNL && input.charAt(i) != ' ' && input.charAt(i) != '\t') {
                throw new IllegalArgumentException(
                        "Unexpected LF not part of an FWS");
            }
            lastWasNL = false;
            switch (state) {
                case 0:
                    switch (input.charAt(i)) {
                        case ' ':
                        case '\t':
                        case '\r':
                        case '\n':
                            if ('\n' == input.charAt(i))
                                lastWasNL = true;
                            sb.append(input.subSequence(start, i));
                            start = i + 1;
                            // ignoring whitespace by now.
                            break;
                        case '=':
                            sb.append(input.subSequence(start, i));
                            state = 1;
                            break;
                    }
                    break;
                case 1:
                case 2:
                    if (input.charAt(i) >= '0' && input.charAt(i) <= '9'
                            || input.charAt(i) >= 'A' && input.charAt(i) <= 'F') {
                        int v = Arrays.binarySearch("0123456789ABCDEF".getBytes(),
                                (byte) input.charAt(i));
                        if (state == 1) {
                            state = 2;
                            d = v;
                        } else {
                            d = d * 16 + v;
                            sb.append((char) d);
                            state = 0;
                            start = i + 1;
                        }
                    } else {
                        throw new IllegalArgumentException(
                                "Invalid input sequence at " + i);
                    }
            }
        }
        if (state != 0) {
            throw new IllegalArgumentException(
                    "Invalid quoted printable termination");
        }
        sb.append(input.subSequence(start, input.length()));
        return sb.toString();
    }
}
