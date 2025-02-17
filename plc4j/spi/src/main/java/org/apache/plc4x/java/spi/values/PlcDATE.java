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
package org.apache.plc4x.java.spi.values;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import org.apache.plc4x.java.api.exceptions.PlcRuntimeException;
import org.apache.plc4x.java.spi.generation.SerializationException;
import org.apache.plc4x.java.spi.generation.WriteBuffer;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;

@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, property = "className")
public class PlcDATE extends PlcSimpleValue<LocalDate> {

    public static PlcDATE of(Object value) {
        if (value instanceof LocalDate) {
            return new PlcDATE((LocalDate) value);
        } else if (value instanceof Long) {
            return new PlcDATE(LocalDateTime.ofInstant(
                Instant.ofEpochSecond((long) value), ZoneId.systemDefault()).toLocalDate());
        }
        throw new PlcRuntimeException("Invalid value type");
    }

    @JsonCreator(mode = JsonCreator.Mode.PROPERTIES)
    public PlcDATE(@JsonProperty("value") LocalDate value) {
        super(value, true);
    }

    @JsonCreator(mode = JsonCreator.Mode.PROPERTIES)
    public PlcDATE(@JsonProperty("value") Integer value) {
        // In this case the date is the number of days since 1990-01-01
        // So we gotta add 7305 days to the value to have it relative to epoch
        // Then we also need to transform it from days to seconds by multiplying by 86400
        super(LocalDateTime.ofInstant(Instant.ofEpochSecond((value + 7305L) * 86400L),
            ZoneId.systemDefault()).toLocalDate(), true);
    }

    @JsonCreator(mode = JsonCreator.Mode.PROPERTIES)
    public PlcDATE(@JsonProperty("value") Long value) {
        super(LocalDateTime.ofInstant(Instant.ofEpochSecond(value), ZoneId.systemDefault()).toLocalDate(), true);
    }

    @Override
    @JsonIgnore
    public boolean isString() {
        return true;
    }

    @Override
    @JsonIgnore
    public String getString() {
        return value.toString();
    }

    @Override
    @JsonIgnore
    public boolean isDate() {
        return true;
    }

    @Override
    @JsonIgnore
    public LocalDate getDate() {
        return value;
    }

    @Override
    @JsonIgnore
    public String toString() {
        return String.valueOf(value);
    }

    @Override
    public void serialize(WriteBuffer writeBuffer) throws SerializationException {
        String valueString = value.toString();
        writeBuffer.writeString(getClass().getSimpleName(), valueString.getBytes(StandardCharsets.UTF_8).length * 8, StandardCharsets.UTF_8.name(), valueString);
    }

}
