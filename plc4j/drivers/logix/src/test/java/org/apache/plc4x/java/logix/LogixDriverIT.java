/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.plc4x.java.logix;

import org.apache.plc4x.java.PlcDriverManager;
import org.apache.plc4x.java.api.PlcConnection;
import org.apache.plc4x.java.api.exceptions.PlcConnectionException;
import org.apache.plc4x.java.logix.readwrite.protocol.LogixProtocolLogic;
import org.apache.plc4x.java.spi.generation.SerializationException;
import org.apache.plc4x.test.driver.DriverTestsuiteRunner;
import org.assertj.core.api.Condition;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

public class LogixDriverIT {

    @Test
    public void simpleStructToANSI() throws SerializationException, IOException {
        Charset charset = StandardCharsets.US_ASCII;
        byte[] name0 = charset.encode("ZZZ_ZZZ_ZZZ").array();
        byte[] name1 = charset.encode("XXX").array();
        byte[] bytes = LogixProtocolLogic.toAnsi("ZZZ_ZZZ_ZZZ.XXX");

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        output.write(145);
        output.write(11);
        output.write(name0);
        output.write(0);
        output.write(145);
        output.write(3);
        output.write(name1);
        output.write(0);

        byte[] out = output.toByteArray();

        try {
            assert(Arrays.equals(out, bytes));
        } catch (AssertionError e) {
            fail("Structure to ANSI: " + Arrays.toString(bytes) + " != " + Arrays.toString(out));
        }

    }

    @Test
    public void simpleToANSIPadding() throws SerializationException, IOException {
        Charset charset = StandardCharsets.US_ASCII;
        byte[] name0 = charset.encode("ZZZ_ZZZ_ZZZ").array();
        byte[] bytes = LogixProtocolLogic.toAnsi("ZZZ_ZZZ_ZZZ");

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        output.write(145);
        output.write(11);
        output.write(name0);
        // Add Padding
        output.write(0);

        byte[] out = output.toByteArray();

        try {
            assert(Arrays.equals(out, bytes));
        } catch (AssertionError e) {
            fail("Structure to ANSI: " + Arrays.toString(bytes) + " != " + Arrays.toString(out));
        }
    }

}
