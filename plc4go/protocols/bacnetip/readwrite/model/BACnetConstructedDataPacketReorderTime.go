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

// BACnetConstructedDataPacketReorderTime is the data-structure of this message
type BACnetConstructedDataPacketReorderTime struct {
	*BACnetConstructedData
	PacketReorderTime *BACnetApplicationTagUnsignedInteger

	// Arguments.
	TagNumber uint8
}

// IBACnetConstructedDataPacketReorderTime is the corresponding interface of BACnetConstructedDataPacketReorderTime
type IBACnetConstructedDataPacketReorderTime interface {
	IBACnetConstructedData
	// GetPacketReorderTime returns PacketReorderTime (property field)
	GetPacketReorderTime() *BACnetApplicationTagUnsignedInteger
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

func (m *BACnetConstructedDataPacketReorderTime) GetObjectTypeArgument() BACnetObjectType {
	return 0
}

func (m *BACnetConstructedDataPacketReorderTime) GetPropertyIdentifierArgument() BACnetPropertyIdentifier {
	return BACnetPropertyIdentifier_PACKET_REORDER_TIME
}

///////////////////////
///////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////

func (m *BACnetConstructedDataPacketReorderTime) InitializeParent(parent *BACnetConstructedData, openingTag *BACnetOpeningTag, closingTag *BACnetClosingTag) {
	m.BACnetConstructedData.OpeningTag = openingTag
	m.BACnetConstructedData.ClosingTag = closingTag
}

func (m *BACnetConstructedDataPacketReorderTime) GetParent() *BACnetConstructedData {
	return m.BACnetConstructedData
}

///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
/////////////////////// Accessors for property fields.
///////////////////////

func (m *BACnetConstructedDataPacketReorderTime) GetPacketReorderTime() *BACnetApplicationTagUnsignedInteger {
	return m.PacketReorderTime
}

///////////////////////
///////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////

// NewBACnetConstructedDataPacketReorderTime factory function for BACnetConstructedDataPacketReorderTime
func NewBACnetConstructedDataPacketReorderTime(packetReorderTime *BACnetApplicationTagUnsignedInteger, openingTag *BACnetOpeningTag, closingTag *BACnetClosingTag, tagNumber uint8) *BACnetConstructedDataPacketReorderTime {
	_result := &BACnetConstructedDataPacketReorderTime{
		PacketReorderTime:     packetReorderTime,
		BACnetConstructedData: NewBACnetConstructedData(openingTag, closingTag, tagNumber),
	}
	_result.Child = _result
	return _result
}

func CastBACnetConstructedDataPacketReorderTime(structType interface{}) *BACnetConstructedDataPacketReorderTime {
	if casted, ok := structType.(BACnetConstructedDataPacketReorderTime); ok {
		return &casted
	}
	if casted, ok := structType.(*BACnetConstructedDataPacketReorderTime); ok {
		return casted
	}
	if casted, ok := structType.(BACnetConstructedData); ok {
		return CastBACnetConstructedDataPacketReorderTime(casted.Child)
	}
	if casted, ok := structType.(*BACnetConstructedData); ok {
		return CastBACnetConstructedDataPacketReorderTime(casted.Child)
	}
	return nil
}

func (m *BACnetConstructedDataPacketReorderTime) GetTypeName() string {
	return "BACnetConstructedDataPacketReorderTime"
}

func (m *BACnetConstructedDataPacketReorderTime) GetLengthInBits() uint16 {
	return m.GetLengthInBitsConditional(false)
}

func (m *BACnetConstructedDataPacketReorderTime) GetLengthInBitsConditional(lastItem bool) uint16 {
	lengthInBits := uint16(m.GetParentLengthInBits())

	// Simple field (packetReorderTime)
	lengthInBits += m.PacketReorderTime.GetLengthInBits()

	return lengthInBits
}

func (m *BACnetConstructedDataPacketReorderTime) GetLengthInBytes() uint16 {
	return m.GetLengthInBits() / 8
}

func BACnetConstructedDataPacketReorderTimeParse(readBuffer utils.ReadBuffer, tagNumber uint8, objectTypeArgument BACnetObjectType, propertyIdentifierArgument BACnetPropertyIdentifier) (*BACnetConstructedDataPacketReorderTime, error) {
	positionAware := readBuffer
	_ = positionAware
	if pullErr := readBuffer.PullContext("BACnetConstructedDataPacketReorderTime"); pullErr != nil {
		return nil, pullErr
	}
	currentPos := positionAware.GetPos()
	_ = currentPos

	// Simple Field (packetReorderTime)
	if pullErr := readBuffer.PullContext("packetReorderTime"); pullErr != nil {
		return nil, pullErr
	}
	_packetReorderTime, _packetReorderTimeErr := BACnetApplicationTagParse(readBuffer)
	if _packetReorderTimeErr != nil {
		return nil, errors.Wrap(_packetReorderTimeErr, "Error parsing 'packetReorderTime' field")
	}
	packetReorderTime := CastBACnetApplicationTagUnsignedInteger(_packetReorderTime)
	if closeErr := readBuffer.CloseContext("packetReorderTime"); closeErr != nil {
		return nil, closeErr
	}

	if closeErr := readBuffer.CloseContext("BACnetConstructedDataPacketReorderTime"); closeErr != nil {
		return nil, closeErr
	}

	// Create a partially initialized instance
	_child := &BACnetConstructedDataPacketReorderTime{
		PacketReorderTime:     CastBACnetApplicationTagUnsignedInteger(packetReorderTime),
		BACnetConstructedData: &BACnetConstructedData{},
	}
	_child.BACnetConstructedData.Child = _child
	return _child, nil
}

func (m *BACnetConstructedDataPacketReorderTime) Serialize(writeBuffer utils.WriteBuffer) error {
	positionAware := writeBuffer
	_ = positionAware
	ser := func() error {
		if pushErr := writeBuffer.PushContext("BACnetConstructedDataPacketReorderTime"); pushErr != nil {
			return pushErr
		}

		// Simple Field (packetReorderTime)
		if pushErr := writeBuffer.PushContext("packetReorderTime"); pushErr != nil {
			return pushErr
		}
		_packetReorderTimeErr := m.PacketReorderTime.Serialize(writeBuffer)
		if popErr := writeBuffer.PopContext("packetReorderTime"); popErr != nil {
			return popErr
		}
		if _packetReorderTimeErr != nil {
			return errors.Wrap(_packetReorderTimeErr, "Error serializing 'packetReorderTime' field")
		}

		if popErr := writeBuffer.PopContext("BACnetConstructedDataPacketReorderTime"); popErr != nil {
			return popErr
		}
		return nil
	}
	return m.SerializeParent(writeBuffer, m, ser)
}

func (m *BACnetConstructedDataPacketReorderTime) String() string {
	if m == nil {
		return "<nil>"
	}
	buffer := utils.NewBoxedWriteBufferWithOptions(true, true)
	if err := m.Serialize(buffer); err != nil {
		return err.Error()
	}
	return buffer.GetBox().String()
}