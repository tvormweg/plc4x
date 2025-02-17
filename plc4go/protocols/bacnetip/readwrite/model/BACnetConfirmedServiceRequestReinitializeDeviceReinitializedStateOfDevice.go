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

package model

import (
	"github.com/apache/plc4x/plc4go/internal/spi/utils"
	"github.com/pkg/errors"
)

// Code generated by code-generation. DO NOT EDIT.

// BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice is an enum
type BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice uint8

type IBACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice interface {
	Serialize(writeBuffer utils.WriteBuffer) error
}

const (
	BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice_COLDSTART                BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice = 0x0
	BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice_WARMSTART                BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice = 0x1
	BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice_ACTIVATE_CHANGES         BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice = 0x2
	BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice_STARTBACKUP              BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice = 0x3
	BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice_ENDBACKUP                BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice = 0x4
	BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice_STARTRESTORE             BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice = 0x5
	BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice_ENDRESTORE               BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice = 0x6
	BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice_ABORTRESTORE             BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice = 0x7
	BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice_VENDOR_PROPRIETARY_VALUE BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice = 0xFF
)

var BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDeviceValues []BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice

func init() {
	_ = errors.New
	BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDeviceValues = []BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice{
		BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice_COLDSTART,
		BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice_WARMSTART,
		BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice_ACTIVATE_CHANGES,
		BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice_STARTBACKUP,
		BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice_ENDBACKUP,
		BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice_STARTRESTORE,
		BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice_ENDRESTORE,
		BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice_ABORTRESTORE,
		BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice_VENDOR_PROPRIETARY_VALUE,
	}
}

func BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDeviceByValue(value uint8) BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice {
	switch value {
	case 0x0:
		return BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice_COLDSTART
	case 0x1:
		return BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice_WARMSTART
	case 0x2:
		return BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice_ACTIVATE_CHANGES
	case 0x3:
		return BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice_STARTBACKUP
	case 0x4:
		return BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice_ENDBACKUP
	case 0x5:
		return BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice_STARTRESTORE
	case 0x6:
		return BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice_ENDRESTORE
	case 0x7:
		return BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice_ABORTRESTORE
	case 0xFF:
		return BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice_VENDOR_PROPRIETARY_VALUE
	}
	return 0
}

func BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDeviceByName(value string) BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice {
	switch value {
	case "COLDSTART":
		return BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice_COLDSTART
	case "WARMSTART":
		return BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice_WARMSTART
	case "ACTIVATE_CHANGES":
		return BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice_ACTIVATE_CHANGES
	case "STARTBACKUP":
		return BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice_STARTBACKUP
	case "ENDBACKUP":
		return BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice_ENDBACKUP
	case "STARTRESTORE":
		return BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice_STARTRESTORE
	case "ENDRESTORE":
		return BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice_ENDRESTORE
	case "ABORTRESTORE":
		return BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice_ABORTRESTORE
	case "VENDOR_PROPRIETARY_VALUE":
		return BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice_VENDOR_PROPRIETARY_VALUE
	}
	return 0
}

func BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDeviceKnows(value uint8) bool {
	for _, typeValue := range BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDeviceValues {
		if uint8(typeValue) == value {
			return true
		}
	}
	return false
}

func CastBACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice(structType interface{}) BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice {
	castFunc := func(typ interface{}) BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice {
		if sBACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice, ok := typ.(BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice); ok {
			return sBACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice
		}
		return 0
	}
	return castFunc(structType)
}

func (m BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice) GetLengthInBits() uint16 {
	return 8
}

func (m BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice) GetLengthInBytes() uint16 {
	return m.GetLengthInBits() / 8
}

func BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDeviceParse(readBuffer utils.ReadBuffer) (BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice, error) {
	val, err := readBuffer.ReadUint8("BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice", 8)
	if err != nil {
		return 0, nil
	}
	return BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDeviceByValue(val), nil
}

func (e BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice) Serialize(writeBuffer utils.WriteBuffer) error {
	return writeBuffer.WriteUint8("BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice", 8, uint8(e), utils.WithAdditionalStringRepresentation(e.name()))
}

func (e BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice) name() string {
	switch e {
	case BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice_COLDSTART:
		return "COLDSTART"
	case BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice_WARMSTART:
		return "WARMSTART"
	case BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice_ACTIVATE_CHANGES:
		return "ACTIVATE_CHANGES"
	case BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice_STARTBACKUP:
		return "STARTBACKUP"
	case BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice_ENDBACKUP:
		return "ENDBACKUP"
	case BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice_STARTRESTORE:
		return "STARTRESTORE"
	case BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice_ENDRESTORE:
		return "ENDRESTORE"
	case BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice_ABORTRESTORE:
		return "ABORTRESTORE"
	case BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice_VENDOR_PROPRIETARY_VALUE:
		return "VENDOR_PROPRIETARY_VALUE"
	}
	return ""
}

func (e BACnetConfirmedServiceRequestReinitializeDeviceReinitializedStateOfDevice) String() string {
	return e.name()
}
