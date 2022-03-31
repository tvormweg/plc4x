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

#include <stdio.h>
#include <plc4c/spi/evaluation_helper.h>
#include "alarm_message_ack_response_type.h"

// Code generated by code-generation. DO NOT EDIT.


// Parse function.
plc4c_return_code plc4c_s7_read_write_alarm_message_ack_response_type_parse(plc4c_spi_read_buffer* readBuffer, plc4c_s7_read_write_alarm_message_ack_response_type** _message) {
  uint16_t startPos = plc4c_spi_read_get_pos(readBuffer);
  plc4c_return_code _res = OK;

  // Allocate enough memory to contain this data structure.
  (*_message) = malloc(sizeof(plc4c_s7_read_write_alarm_message_ack_response_type));
  if(*_message == NULL) {
    return NO_MEMORY;
  }

  // Simple Field (functionId)
  uint8_t functionId = 0;
  _res = plc4c_spi_read_unsigned_byte(readBuffer, 8, (uint8_t*) &functionId);
  if(_res != OK) {
    return _res;
  }
  (*_message)->function_id = functionId;

  // Simple Field (numberOfObjects)
  uint8_t numberOfObjects = 0;
  _res = plc4c_spi_read_unsigned_byte(readBuffer, 8, (uint8_t*) &numberOfObjects);
  if(_res != OK) {
    return _res;
  }
  (*_message)->number_of_objects = numberOfObjects;

  // Array field (messageObjects)
  plc4c_list* messageObjects = NULL;
  plc4c_utils_list_create(&messageObjects);
  if(messageObjects == NULL) {
    return NO_MEMORY;
  }
  {
    // Count array
    uint16_t itemCount = (uint16_t) numberOfObjects;
    for(int curItem = 0; curItem < itemCount; curItem++) {
      
      uint8_t* _value = malloc(sizeof(uint8_t));
      _res = plc4c_spi_read_unsigned_byte(readBuffer, 8, (uint8_t*) _value);
      if(_res != OK) {
        return _res;
      }
      plc4c_utils_list_insert_head_value(messageObjects, _value);
    }
  }
  (*_message)->message_objects = messageObjects;

  return OK;
}

plc4c_return_code plc4c_s7_read_write_alarm_message_ack_response_type_serialize(plc4c_spi_write_buffer* writeBuffer, plc4c_s7_read_write_alarm_message_ack_response_type* _message) {
  plc4c_return_code _res = OK;

  // Simple Field (functionId)
  _res = plc4c_spi_write_unsigned_byte(writeBuffer, 8, _message->function_id);
  if(_res != OK) {
    return _res;
  }

  // Simple Field (numberOfObjects)
  _res = plc4c_spi_write_unsigned_byte(writeBuffer, 8, _message->number_of_objects);
  if(_res != OK) {
    return _res;
  }

  // Array field (messageObjects)
  {
    uint8_t itemCount = plc4c_utils_list_size(_message->message_objects);
    for(int curItem = 0; curItem < itemCount; curItem++) {

      uint8_t* _value = (uint8_t*) plc4c_utils_list_get_value(_message->message_objects, curItem);
      plc4c_spi_write_unsigned_byte(writeBuffer, 8, *_value);
    }
  }

  return OK;
}

uint16_t plc4c_s7_read_write_alarm_message_ack_response_type_length_in_bytes(plc4c_s7_read_write_alarm_message_ack_response_type* _message) {
  return plc4c_s7_read_write_alarm_message_ack_response_type_length_in_bits(_message) / 8;
}

uint16_t plc4c_s7_read_write_alarm_message_ack_response_type_length_in_bits(plc4c_s7_read_write_alarm_message_ack_response_type* _message) {
  uint16_t lengthInBits = 0;

  // Simple field (functionId)
  lengthInBits += 8;

  // Simple field (numberOfObjects)
  lengthInBits += 8;

  // Array field
  lengthInBits += 8 * plc4c_utils_list_size(_message->message_objects);

  return lengthInBits;
}

