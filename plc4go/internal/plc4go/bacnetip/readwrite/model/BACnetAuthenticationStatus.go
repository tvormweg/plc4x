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

package model

import (
	"github.com/apache/plc4x/plc4go/internal/plc4go/spi/utils"
	"github.com/pkg/errors"
)

// Code generated by code-generation. DO NOT EDIT.

// BACnetAuthenticationStatus is an enum
type BACnetAuthenticationStatus uint8

type IBACnetAuthenticationStatus interface {
	Serialize(writeBuffer utils.WriteBuffer) error
}

const (
	BACnetAuthenticationStatus_NOT_READY                         BACnetAuthenticationStatus = 0
	BACnetAuthenticationStatus_READY                             BACnetAuthenticationStatus = 1
	BACnetAuthenticationStatus_DISABLED                          BACnetAuthenticationStatus = 2
	BACnetAuthenticationStatus_WAITING_FOR_AUTHENTICATION_FACTOR BACnetAuthenticationStatus = 3
	BACnetAuthenticationStatus_WAITING_FOR_ACCOMPANIMENT         BACnetAuthenticationStatus = 4
	BACnetAuthenticationStatus_WAITING_FOR_VERIFICATION          BACnetAuthenticationStatus = 5
	BACnetAuthenticationStatus_IN_PROGRESS                       BACnetAuthenticationStatus = 6
)

var BACnetAuthenticationStatusValues []BACnetAuthenticationStatus

func init() {
	_ = errors.New
	BACnetAuthenticationStatusValues = []BACnetAuthenticationStatus{
		BACnetAuthenticationStatus_NOT_READY,
		BACnetAuthenticationStatus_READY,
		BACnetAuthenticationStatus_DISABLED,
		BACnetAuthenticationStatus_WAITING_FOR_AUTHENTICATION_FACTOR,
		BACnetAuthenticationStatus_WAITING_FOR_ACCOMPANIMENT,
		BACnetAuthenticationStatus_WAITING_FOR_VERIFICATION,
		BACnetAuthenticationStatus_IN_PROGRESS,
	}
}

func BACnetAuthenticationStatusByValue(value uint8) BACnetAuthenticationStatus {
	switch value {
	case 0:
		return BACnetAuthenticationStatus_NOT_READY
	case 1:
		return BACnetAuthenticationStatus_READY
	case 2:
		return BACnetAuthenticationStatus_DISABLED
	case 3:
		return BACnetAuthenticationStatus_WAITING_FOR_AUTHENTICATION_FACTOR
	case 4:
		return BACnetAuthenticationStatus_WAITING_FOR_ACCOMPANIMENT
	case 5:
		return BACnetAuthenticationStatus_WAITING_FOR_VERIFICATION
	case 6:
		return BACnetAuthenticationStatus_IN_PROGRESS
	}
	return 0
}

func BACnetAuthenticationStatusByName(value string) BACnetAuthenticationStatus {
	switch value {
	case "NOT_READY":
		return BACnetAuthenticationStatus_NOT_READY
	case "READY":
		return BACnetAuthenticationStatus_READY
	case "DISABLED":
		return BACnetAuthenticationStatus_DISABLED
	case "WAITING_FOR_AUTHENTICATION_FACTOR":
		return BACnetAuthenticationStatus_WAITING_FOR_AUTHENTICATION_FACTOR
	case "WAITING_FOR_ACCOMPANIMENT":
		return BACnetAuthenticationStatus_WAITING_FOR_ACCOMPANIMENT
	case "WAITING_FOR_VERIFICATION":
		return BACnetAuthenticationStatus_WAITING_FOR_VERIFICATION
	case "IN_PROGRESS":
		return BACnetAuthenticationStatus_IN_PROGRESS
	}
	return 0
}

func BACnetAuthenticationStatusKnows(value uint8) bool {
	for _, typeValue := range BACnetAuthenticationStatusValues {
		if uint8(typeValue) == value {
			return true
		}
	}
	return false
}

func CastBACnetAuthenticationStatus(structType interface{}) BACnetAuthenticationStatus {
	castFunc := func(typ interface{}) BACnetAuthenticationStatus {
		if sBACnetAuthenticationStatus, ok := typ.(BACnetAuthenticationStatus); ok {
			return sBACnetAuthenticationStatus
		}
		return 0
	}
	return castFunc(structType)
}

func (m BACnetAuthenticationStatus) GetLengthInBits() uint16 {
	return 8
}

func (m BACnetAuthenticationStatus) GetLengthInBytes() uint16 {
	return m.GetLengthInBits() / 8
}

func BACnetAuthenticationStatusParse(readBuffer utils.ReadBuffer) (BACnetAuthenticationStatus, error) {
	val, err := readBuffer.ReadUint8("BACnetAuthenticationStatus", 8)
	if err != nil {
		return 0, nil
	}
	return BACnetAuthenticationStatusByValue(val), nil
}

func (e BACnetAuthenticationStatus) Serialize(writeBuffer utils.WriteBuffer) error {
	return writeBuffer.WriteUint8("BACnetAuthenticationStatus", 8, uint8(e), utils.WithAdditionalStringRepresentation(e.name()))
}

func (e BACnetAuthenticationStatus) name() string {
	switch e {
	case BACnetAuthenticationStatus_NOT_READY:
		return "NOT_READY"
	case BACnetAuthenticationStatus_READY:
		return "READY"
	case BACnetAuthenticationStatus_DISABLED:
		return "DISABLED"
	case BACnetAuthenticationStatus_WAITING_FOR_AUTHENTICATION_FACTOR:
		return "WAITING_FOR_AUTHENTICATION_FACTOR"
	case BACnetAuthenticationStatus_WAITING_FOR_ACCOMPANIMENT:
		return "WAITING_FOR_ACCOMPANIMENT"
	case BACnetAuthenticationStatus_WAITING_FOR_VERIFICATION:
		return "WAITING_FOR_VERIFICATION"
	case BACnetAuthenticationStatus_IN_PROGRESS:
		return "IN_PROGRESS"
	}
	return ""
}

func (e BACnetAuthenticationStatus) String() string {
	return e.name()
}