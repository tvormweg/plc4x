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
	"github.com/apache/plc4x/plc4go/internal/spi/utils"
	"github.com/pkg/errors"
)

// Code generated by code-generation. DO NOT EDIT.

// BACnetConstructedDataOccupancyLowerLimitEnforced is the data-structure of this message
type BACnetConstructedDataOccupancyLowerLimitEnforced struct {
	*BACnetConstructedData
	OccupancyLowerLimitEnforced *BACnetApplicationTagBoolean

	// Arguments.
	TagNumber uint8
}

// IBACnetConstructedDataOccupancyLowerLimitEnforced is the corresponding interface of BACnetConstructedDataOccupancyLowerLimitEnforced
type IBACnetConstructedDataOccupancyLowerLimitEnforced interface {
	IBACnetConstructedData
	// GetOccupancyLowerLimitEnforced returns OccupancyLowerLimitEnforced (property field)
	GetOccupancyLowerLimitEnforced() *BACnetApplicationTagBoolean
	// GetLengthInBytes returns the length in bytes
	GetLengthInBytes() uint16
	// GetLengthInBits returns the length in bits
	GetLengthInBits() uint16
	// Serialize serializes this type
	Serialize(writeBuffer utils.WriteBuffer) error
}

///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
/////////////////////// Accessors for discriminator values.
///////////////////////

func (m *BACnetConstructedDataOccupancyLowerLimitEnforced) GetObjectTypeArgument() BACnetObjectType {
	return 0
}

func (m *BACnetConstructedDataOccupancyLowerLimitEnforced) GetPropertyIdentifierArgument() BACnetPropertyIdentifier {
	return BACnetPropertyIdentifier_OCCUPANCY_LOWER_LIMIT_ENFORCED
}

///////////////////////
///////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////

func (m *BACnetConstructedDataOccupancyLowerLimitEnforced) InitializeParent(parent *BACnetConstructedData, openingTag *BACnetOpeningTag, closingTag *BACnetClosingTag) {
	m.BACnetConstructedData.OpeningTag = openingTag
	m.BACnetConstructedData.ClosingTag = closingTag
}

func (m *BACnetConstructedDataOccupancyLowerLimitEnforced) GetParent() *BACnetConstructedData {
	return m.BACnetConstructedData
}

///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
/////////////////////// Accessors for property fields.
///////////////////////

func (m *BACnetConstructedDataOccupancyLowerLimitEnforced) GetOccupancyLowerLimitEnforced() *BACnetApplicationTagBoolean {
	return m.OccupancyLowerLimitEnforced
}

///////////////////////
///////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////

// NewBACnetConstructedDataOccupancyLowerLimitEnforced factory function for BACnetConstructedDataOccupancyLowerLimitEnforced
func NewBACnetConstructedDataOccupancyLowerLimitEnforced(occupancyLowerLimitEnforced *BACnetApplicationTagBoolean, openingTag *BACnetOpeningTag, closingTag *BACnetClosingTag, tagNumber uint8) *BACnetConstructedDataOccupancyLowerLimitEnforced {
	_result := &BACnetConstructedDataOccupancyLowerLimitEnforced{
		OccupancyLowerLimitEnforced: occupancyLowerLimitEnforced,
		BACnetConstructedData:       NewBACnetConstructedData(openingTag, closingTag, tagNumber),
	}
	_result.Child = _result
	return _result
}

func CastBACnetConstructedDataOccupancyLowerLimitEnforced(structType interface{}) *BACnetConstructedDataOccupancyLowerLimitEnforced {
	if casted, ok := structType.(BACnetConstructedDataOccupancyLowerLimitEnforced); ok {
		return &casted
	}
	if casted, ok := structType.(*BACnetConstructedDataOccupancyLowerLimitEnforced); ok {
		return casted
	}
	if casted, ok := structType.(BACnetConstructedData); ok {
		return CastBACnetConstructedDataOccupancyLowerLimitEnforced(casted.Child)
	}
	if casted, ok := structType.(*BACnetConstructedData); ok {
		return CastBACnetConstructedDataOccupancyLowerLimitEnforced(casted.Child)
	}
	return nil
}

func (m *BACnetConstructedDataOccupancyLowerLimitEnforced) GetTypeName() string {
	return "BACnetConstructedDataOccupancyLowerLimitEnforced"
}

func (m *BACnetConstructedDataOccupancyLowerLimitEnforced) GetLengthInBits() uint16 {
	return m.GetLengthInBitsConditional(false)
}

func (m *BACnetConstructedDataOccupancyLowerLimitEnforced) GetLengthInBitsConditional(lastItem bool) uint16 {
	lengthInBits := uint16(m.GetParentLengthInBits())

	// Simple field (occupancyLowerLimitEnforced)
	lengthInBits += m.OccupancyLowerLimitEnforced.GetLengthInBits()

	return lengthInBits
}

func (m *BACnetConstructedDataOccupancyLowerLimitEnforced) GetLengthInBytes() uint16 {
	return m.GetLengthInBits() / 8
}

func BACnetConstructedDataOccupancyLowerLimitEnforcedParse(readBuffer utils.ReadBuffer, tagNumber uint8, objectTypeArgument BACnetObjectType, propertyIdentifierArgument BACnetPropertyIdentifier) (*BACnetConstructedDataOccupancyLowerLimitEnforced, error) {
	positionAware := readBuffer
	_ = positionAware
	if pullErr := readBuffer.PullContext("BACnetConstructedDataOccupancyLowerLimitEnforced"); pullErr != nil {
		return nil, pullErr
	}
	currentPos := positionAware.GetPos()
	_ = currentPos

	// Simple Field (occupancyLowerLimitEnforced)
	if pullErr := readBuffer.PullContext("occupancyLowerLimitEnforced"); pullErr != nil {
		return nil, pullErr
	}
	_occupancyLowerLimitEnforced, _occupancyLowerLimitEnforcedErr := BACnetApplicationTagParse(readBuffer)
	if _occupancyLowerLimitEnforcedErr != nil {
		return nil, errors.Wrap(_occupancyLowerLimitEnforcedErr, "Error parsing 'occupancyLowerLimitEnforced' field")
	}
	occupancyLowerLimitEnforced := CastBACnetApplicationTagBoolean(_occupancyLowerLimitEnforced)
	if closeErr := readBuffer.CloseContext("occupancyLowerLimitEnforced"); closeErr != nil {
		return nil, closeErr
	}

	if closeErr := readBuffer.CloseContext("BACnetConstructedDataOccupancyLowerLimitEnforced"); closeErr != nil {
		return nil, closeErr
	}

	// Create a partially initialized instance
	_child := &BACnetConstructedDataOccupancyLowerLimitEnforced{
		OccupancyLowerLimitEnforced: CastBACnetApplicationTagBoolean(occupancyLowerLimitEnforced),
		BACnetConstructedData:       &BACnetConstructedData{},
	}
	_child.BACnetConstructedData.Child = _child
	return _child, nil
}

func (m *BACnetConstructedDataOccupancyLowerLimitEnforced) Serialize(writeBuffer utils.WriteBuffer) error {
	positionAware := writeBuffer
	_ = positionAware
	ser := func() error {
		if pushErr := writeBuffer.PushContext("BACnetConstructedDataOccupancyLowerLimitEnforced"); pushErr != nil {
			return pushErr
		}

		// Simple Field (occupancyLowerLimitEnforced)
		if pushErr := writeBuffer.PushContext("occupancyLowerLimitEnforced"); pushErr != nil {
			return pushErr
		}
		_occupancyLowerLimitEnforcedErr := m.OccupancyLowerLimitEnforced.Serialize(writeBuffer)
		if popErr := writeBuffer.PopContext("occupancyLowerLimitEnforced"); popErr != nil {
			return popErr
		}
		if _occupancyLowerLimitEnforcedErr != nil {
			return errors.Wrap(_occupancyLowerLimitEnforcedErr, "Error serializing 'occupancyLowerLimitEnforced' field")
		}

		if popErr := writeBuffer.PopContext("BACnetConstructedDataOccupancyLowerLimitEnforced"); popErr != nil {
			return popErr
		}
		return nil
	}
	return m.SerializeParent(writeBuffer, m, ser)
}

func (m *BACnetConstructedDataOccupancyLowerLimitEnforced) String() string {
	if m == nil {
		return "<nil>"
	}
	buffer := utils.NewBoxedWriteBufferWithOptions(true, true)
	if err := m.Serialize(buffer); err != nil {
		return err.Error()
	}
	return buffer.GetBox().String()
}