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

// BACnetConstructedDataCarMode is the data-structure of this message
type BACnetConstructedDataCarMode struct {
	*BACnetConstructedData
	CarMode *BACnetLiftCarModeTagged

	// Arguments.
	TagNumber uint8
}

// IBACnetConstructedDataCarMode is the corresponding interface of BACnetConstructedDataCarMode
type IBACnetConstructedDataCarMode interface {
	IBACnetConstructedData
	// GetCarMode returns CarMode (property field)
	GetCarMode() *BACnetLiftCarModeTagged
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

func (m *BACnetConstructedDataCarMode) GetObjectTypeArgument() BACnetObjectType {
	return 0
}

func (m *BACnetConstructedDataCarMode) GetPropertyIdentifierArgument() BACnetPropertyIdentifier {
	return BACnetPropertyIdentifier_CAR_MODE
}

///////////////////////
///////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////

func (m *BACnetConstructedDataCarMode) InitializeParent(parent *BACnetConstructedData, openingTag *BACnetOpeningTag, closingTag *BACnetClosingTag) {
	m.BACnetConstructedData.OpeningTag = openingTag
	m.BACnetConstructedData.ClosingTag = closingTag
}

func (m *BACnetConstructedDataCarMode) GetParent() *BACnetConstructedData {
	return m.BACnetConstructedData
}

///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
/////////////////////// Accessors for property fields.
///////////////////////

func (m *BACnetConstructedDataCarMode) GetCarMode() *BACnetLiftCarModeTagged {
	return m.CarMode
}

///////////////////////
///////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////

// NewBACnetConstructedDataCarMode factory function for BACnetConstructedDataCarMode
func NewBACnetConstructedDataCarMode(carMode *BACnetLiftCarModeTagged, openingTag *BACnetOpeningTag, closingTag *BACnetClosingTag, tagNumber uint8) *BACnetConstructedDataCarMode {
	_result := &BACnetConstructedDataCarMode{
		CarMode:               carMode,
		BACnetConstructedData: NewBACnetConstructedData(openingTag, closingTag, tagNumber),
	}
	_result.Child = _result
	return _result
}

func CastBACnetConstructedDataCarMode(structType interface{}) *BACnetConstructedDataCarMode {
	if casted, ok := structType.(BACnetConstructedDataCarMode); ok {
		return &casted
	}
	if casted, ok := structType.(*BACnetConstructedDataCarMode); ok {
		return casted
	}
	if casted, ok := structType.(BACnetConstructedData); ok {
		return CastBACnetConstructedDataCarMode(casted.Child)
	}
	if casted, ok := structType.(*BACnetConstructedData); ok {
		return CastBACnetConstructedDataCarMode(casted.Child)
	}
	return nil
}

func (m *BACnetConstructedDataCarMode) GetTypeName() string {
	return "BACnetConstructedDataCarMode"
}

func (m *BACnetConstructedDataCarMode) GetLengthInBits() uint16 {
	return m.GetLengthInBitsConditional(false)
}

func (m *BACnetConstructedDataCarMode) GetLengthInBitsConditional(lastItem bool) uint16 {
	lengthInBits := uint16(m.GetParentLengthInBits())

	// Simple field (carMode)
	lengthInBits += m.CarMode.GetLengthInBits()

	return lengthInBits
}

func (m *BACnetConstructedDataCarMode) GetLengthInBytes() uint16 {
	return m.GetLengthInBits() / 8
}

func BACnetConstructedDataCarModeParse(readBuffer utils.ReadBuffer, tagNumber uint8, objectTypeArgument BACnetObjectType, propertyIdentifierArgument BACnetPropertyIdentifier) (*BACnetConstructedDataCarMode, error) {
	positionAware := readBuffer
	_ = positionAware
	if pullErr := readBuffer.PullContext("BACnetConstructedDataCarMode"); pullErr != nil {
		return nil, pullErr
	}
	currentPos := positionAware.GetPos()
	_ = currentPos

	// Simple Field (carMode)
	if pullErr := readBuffer.PullContext("carMode"); pullErr != nil {
		return nil, pullErr
	}
	_carMode, _carModeErr := BACnetLiftCarModeTaggedParse(readBuffer, uint8(uint8(0)), TagClass(TagClass_APPLICATION_TAGS))
	if _carModeErr != nil {
		return nil, errors.Wrap(_carModeErr, "Error parsing 'carMode' field")
	}
	carMode := CastBACnetLiftCarModeTagged(_carMode)
	if closeErr := readBuffer.CloseContext("carMode"); closeErr != nil {
		return nil, closeErr
	}

	if closeErr := readBuffer.CloseContext("BACnetConstructedDataCarMode"); closeErr != nil {
		return nil, closeErr
	}

	// Create a partially initialized instance
	_child := &BACnetConstructedDataCarMode{
		CarMode:               CastBACnetLiftCarModeTagged(carMode),
		BACnetConstructedData: &BACnetConstructedData{},
	}
	_child.BACnetConstructedData.Child = _child
	return _child, nil
}

func (m *BACnetConstructedDataCarMode) Serialize(writeBuffer utils.WriteBuffer) error {
	positionAware := writeBuffer
	_ = positionAware
	ser := func() error {
		if pushErr := writeBuffer.PushContext("BACnetConstructedDataCarMode"); pushErr != nil {
			return pushErr
		}

		// Simple Field (carMode)
		if pushErr := writeBuffer.PushContext("carMode"); pushErr != nil {
			return pushErr
		}
		_carModeErr := m.CarMode.Serialize(writeBuffer)
		if popErr := writeBuffer.PopContext("carMode"); popErr != nil {
			return popErr
		}
		if _carModeErr != nil {
			return errors.Wrap(_carModeErr, "Error serializing 'carMode' field")
		}

		if popErr := writeBuffer.PopContext("BACnetConstructedDataCarMode"); popErr != nil {
			return popErr
		}
		return nil
	}
	return m.SerializeParent(writeBuffer, m, ser)
}

func (m *BACnetConstructedDataCarMode) String() string {
	if m == nil {
		return "<nil>"
	}
	buffer := utils.NewBoxedWriteBufferWithOptions(true, true)
	if err := m.Serialize(buffer); err != nil {
		return err.Error()
	}
	return buffer.GetBox().String()
}