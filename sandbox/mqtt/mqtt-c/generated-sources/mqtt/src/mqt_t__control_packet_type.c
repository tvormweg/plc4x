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

#include "mqt_t__control_packet_type.h"
#include <string.h>

// Code generated by code-generation. DO NOT EDIT.


// Create an empty NULL-struct
static const plc4c_mqtt_read_write_mqt_t__control_packet_type plc4c_mqtt_read_write_mqt_t__control_packet_type_null_const;

plc4c_mqtt_read_write_mqt_t__control_packet_type plc4c_mqtt_read_write_mqt_t__control_packet_type_null() {
  return plc4c_mqtt_read_write_mqt_t__control_packet_type_null_const;
}

// Parse function.
plc4c_return_code plc4c_mqtt_read_write_mqt_t__control_packet_type_parse(plc4c_spi_read_buffer* readBuffer, plc4c_mqtt_read_write_mqt_t__control_packet_type** _message) {
    plc4c_return_code _res = OK;

    // Allocate enough memory to contain this data structure.
    (*_message) = malloc(sizeof(plc4c_mqtt_read_write_mqt_t__control_packet_type));
    if(*_message == NULL) {
        return NO_MEMORY;
    }

    _res = plc4c_spi_read_unsigned_byte(readBuffer, 4, (uint8_t*) *_message);

    return _res;
}

plc4c_return_code plc4c_mqtt_read_write_mqt_t__control_packet_type_serialize(plc4c_spi_write_buffer* writeBuffer, plc4c_mqtt_read_write_mqt_t__control_packet_type* _message) {
    plc4c_return_code _res = OK;

    _res = plc4c_spi_write_unsigned_byte(writeBuffer, 4, *_message);

    return _res;
}

plc4c_mqtt_read_write_mqt_t__control_packet_type plc4c_mqtt_read_write_mqt_t__control_packet_type_value_of(char* value_string) {
    if(strcmp(value_string, "RESERVED") == 0) {
        return plc4c_mqtt_read_write_mqt_t__control_packet_type_RESERVED;
    }
    if(strcmp(value_string, "CONNECT") == 0) {
        return plc4c_mqtt_read_write_mqt_t__control_packet_type_CONNECT;
    }
    if(strcmp(value_string, "CONNACK") == 0) {
        return plc4c_mqtt_read_write_mqt_t__control_packet_type_CONNACK;
    }
    if(strcmp(value_string, "PUBLISH") == 0) {
        return plc4c_mqtt_read_write_mqt_t__control_packet_type_PUBLISH;
    }
    if(strcmp(value_string, "PUBACK") == 0) {
        return plc4c_mqtt_read_write_mqt_t__control_packet_type_PUBACK;
    }
    if(strcmp(value_string, "PUBREC") == 0) {
        return plc4c_mqtt_read_write_mqt_t__control_packet_type_PUBREC;
    }
    if(strcmp(value_string, "PUBREL") == 0) {
        return plc4c_mqtt_read_write_mqt_t__control_packet_type_PUBREL;
    }
    if(strcmp(value_string, "PUBCOMP") == 0) {
        return plc4c_mqtt_read_write_mqt_t__control_packet_type_PUBCOMP;
    }
    if(strcmp(value_string, "SUBSCRIBE") == 0) {
        return plc4c_mqtt_read_write_mqt_t__control_packet_type_SUBSCRIBE;
    }
    if(strcmp(value_string, "SUBACK") == 0) {
        return plc4c_mqtt_read_write_mqt_t__control_packet_type_SUBACK;
    }
    if(strcmp(value_string, "UNSUBSCRIBE") == 0) {
        return plc4c_mqtt_read_write_mqt_t__control_packet_type_UNSUBSCRIBE;
    }
    if(strcmp(value_string, "UNSUBACK") == 0) {
        return plc4c_mqtt_read_write_mqt_t__control_packet_type_UNSUBACK;
    }
    if(strcmp(value_string, "PINGREQ") == 0) {
        return plc4c_mqtt_read_write_mqt_t__control_packet_type_PINGREQ;
    }
    if(strcmp(value_string, "PINGRESP") == 0) {
        return plc4c_mqtt_read_write_mqt_t__control_packet_type_PINGRESP;
    }
    if(strcmp(value_string, "DISCONNECT") == 0) {
        return plc4c_mqtt_read_write_mqt_t__control_packet_type_DISCONNECT;
    }
    if(strcmp(value_string, "AUTH") == 0) {
        return plc4c_mqtt_read_write_mqt_t__control_packet_type_AUTH;
    }
    return -1;
}

int plc4c_mqtt_read_write_mqt_t__control_packet_type_num_values() {
  return 16;
}

plc4c_mqtt_read_write_mqt_t__control_packet_type plc4c_mqtt_read_write_mqt_t__control_packet_type_value_for_index(int index) {
    switch(index) {
      case 0: {
        return plc4c_mqtt_read_write_mqt_t__control_packet_type_RESERVED;
      }
      case 1: {
        return plc4c_mqtt_read_write_mqt_t__control_packet_type_CONNECT;
      }
      case 2: {
        return plc4c_mqtt_read_write_mqt_t__control_packet_type_CONNACK;
      }
      case 3: {
        return plc4c_mqtt_read_write_mqt_t__control_packet_type_PUBLISH;
      }
      case 4: {
        return plc4c_mqtt_read_write_mqt_t__control_packet_type_PUBACK;
      }
      case 5: {
        return plc4c_mqtt_read_write_mqt_t__control_packet_type_PUBREC;
      }
      case 6: {
        return plc4c_mqtt_read_write_mqt_t__control_packet_type_PUBREL;
      }
      case 7: {
        return plc4c_mqtt_read_write_mqt_t__control_packet_type_PUBCOMP;
      }
      case 8: {
        return plc4c_mqtt_read_write_mqt_t__control_packet_type_SUBSCRIBE;
      }
      case 9: {
        return plc4c_mqtt_read_write_mqt_t__control_packet_type_SUBACK;
      }
      case 10: {
        return plc4c_mqtt_read_write_mqt_t__control_packet_type_UNSUBSCRIBE;
      }
      case 11: {
        return plc4c_mqtt_read_write_mqt_t__control_packet_type_UNSUBACK;
      }
      case 12: {
        return plc4c_mqtt_read_write_mqt_t__control_packet_type_PINGREQ;
      }
      case 13: {
        return plc4c_mqtt_read_write_mqt_t__control_packet_type_PINGRESP;
      }
      case 14: {
        return plc4c_mqtt_read_write_mqt_t__control_packet_type_DISCONNECT;
      }
      case 15: {
        return plc4c_mqtt_read_write_mqt_t__control_packet_type_AUTH;
      }
      default: {
        return -1;
      }
    }
}

uint16_t plc4c_mqtt_read_write_mqt_t__control_packet_type_length_in_bytes(plc4c_mqtt_read_write_mqt_t__control_packet_type* _message) {
    return plc4c_mqtt_read_write_mqt_t__control_packet_type_length_in_bits(_message) / 8;
}

uint16_t plc4c_mqtt_read_write_mqt_t__control_packet_type_length_in_bits(plc4c_mqtt_read_write_mqt_t__control_packet_type* _message) {
    return 4;
}
