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

// BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilter is an enum
type BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilter uint8

type IBACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilter interface {
	Serialize(writeBuffer utils.WriteBuffer) error
}

const (
	BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilter_OFFNORMAL BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilter = 0
	BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilter_FAULT     BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilter = 1
	BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilter_NORMAL    BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilter = 2
	BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilter_ALL       BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilter = 3
	BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilter_ACTIVE    BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilter = 4
)

var BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilterValues []BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilter

func init() {
	_ = errors.New
	BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilterValues = []BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilter{
		BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilter_OFFNORMAL,
		BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilter_FAULT,
		BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilter_NORMAL,
		BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilter_ALL,
		BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilter_ACTIVE,
	}
}

func BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilterByValue(value uint8) BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilter {
	switch value {
	case 0:
		return BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilter_OFFNORMAL
	case 1:
		return BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilter_FAULT
	case 2:
		return BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilter_NORMAL
	case 3:
		return BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilter_ALL
	case 4:
		return BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilter_ACTIVE
	}
	return 0
}

func BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilterByName(value string) BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilter {
	switch value {
	case "OFFNORMAL":
		return BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilter_OFFNORMAL
	case "FAULT":
		return BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilter_FAULT
	case "NORMAL":
		return BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilter_NORMAL
	case "ALL":
		return BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilter_ALL
	case "ACTIVE":
		return BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilter_ACTIVE
	}
	return 0
}

func BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilterKnows(value uint8) bool {
	for _, typeValue := range BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilterValues {
		if uint8(typeValue) == value {
			return true
		}
	}
	return false
}

func CastBACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilter(structType interface{}) BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilter {
	castFunc := func(typ interface{}) BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilter {
		if sBACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilter, ok := typ.(BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilter); ok {
			return sBACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilter
		}
		return 0
	}
	return castFunc(structType)
}

func (m BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilter) GetLengthInBits() uint16 {
	return 8
}

func (m BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilter) GetLengthInBytes() uint16 {
	return m.GetLengthInBits() / 8
}

func BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilterParse(readBuffer utils.ReadBuffer) (BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilter, error) {
	val, err := readBuffer.ReadUint8("BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilter", 8)
	if err != nil {
		return 0, nil
	}
	return BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilterByValue(val), nil
}

func (e BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilter) Serialize(writeBuffer utils.WriteBuffer) error {
	return writeBuffer.WriteUint8("BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilter", 8, uint8(e), utils.WithAdditionalStringRepresentation(e.name()))
}

func (e BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilter) name() string {
	switch e {
	case BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilter_OFFNORMAL:
		return "OFFNORMAL"
	case BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilter_FAULT:
		return "FAULT"
	case BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilter_NORMAL:
		return "NORMAL"
	case BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilter_ALL:
		return "ALL"
	case BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilter_ACTIVE:
		return "ACTIVE"
	}
	return ""
}

func (e BACnetConfirmedServiceRequestGetEnrollmentSummaryEventStateFilter) String() string {
	return e.name()
}
