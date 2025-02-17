/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.plc4x.java.ads.api.generic.types;


import org.apache.commons.codec.binary.Hex;
import org.apache.plc4x.java.ads.api.tcp.types.TcpLength;
import org.junit.Test;

import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;


public class TcpLengthTest {
    private final byte NULL_BYTE = 0x0;

    @Test
    public void ofBytes() {
        assertEquals(0L, TcpLength.of(NULL_BYTE, NULL_BYTE, NULL_BYTE, NULL_BYTE).getAsLong());
        assertThrows(IllegalArgumentException.class, () -> TcpLength.of(NULL_BYTE, NULL_BYTE, NULL_BYTE, NULL_BYTE, NULL_BYTE));
    }

    @Test
    public void ofLong() {
        assertByte(TcpLength.of(1), "0x01000000");
        assertByte(TcpLength.of(65535), "0xffff0000");
        assertThrows(IllegalArgumentException.class, () -> TcpLength.of(-1));
        assertThrows(IllegalArgumentException.class, () -> TcpLength.of(4294967296L));
    }

    @Test
    public void ofString() {
        assertByte(TcpLength.of("1"), "0x01000000");
    }

    @Test
    public void testToString() {
        assertThat(TcpLength.of("1").toString(), containsString("longValue=1,"));
    }

    private void assertByte(TcpLength actual, String expected) {
        assertEquals(expected, "0x" + Hex.encodeHexString(actual.getBytes()));
    }

}