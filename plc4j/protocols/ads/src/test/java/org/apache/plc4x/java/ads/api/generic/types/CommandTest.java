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

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import org.junit.Test;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

public class CommandTest {

    @Test
    public void getBytes() {
        byte[] result = {(byte)0x01, (byte)0x00};
        Command command = Command.ofInt("1");
        assertThat(command.getBytes(), is(result));
    }

    @Test
    public void getByteBuf() {
        ByteBuf result = Unpooled.buffer();
        result.writeByte(0x02);
        result.writeByte(0x00);
        Command command = Command.ofInt("2");
        assertThat(command.getByteBuf(), is(result));
    }

    @Test(expected = IllegalStateException.class)
    public void getBytesUnknown() {
        Command command = Command.UNKNOWN;
        command.getBytes();
    }

    @Test(expected = IllegalStateException.class)
    public void getByteBufUnknown() {
        Command command = Command.UNKNOWN;
        command.getByteBuf();
    }
}