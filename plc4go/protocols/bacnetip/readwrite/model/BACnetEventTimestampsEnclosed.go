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

// BACnetEventTimestampsEnclosed is the data-structure of this message
type BACnetEventTimestampsEnclosed struct {
	OpeningTag      *BACnetOpeningTag
	EventTimestamps *BACnetEventTimestamps
	ClosingTag      *BACnetClosingTag

	// Arguments.
	TagNumber uint8
}

// IBACnetEventTimestampsEnclosed is the corresponding interface of BACnetEventTimestampsEnclosed
type IBACnetEventTimestampsEnclosed interface {
	// GetOpeningTag returns OpeningTag (property field)
	GetOpeningTag() *BACnetOpeningTag
	// GetEventTimestamps returns EventTimestamps (property field)
	GetEventTimestamps() *BACnetEventTimestamps
	// GetClosingTag returns ClosingTag (property field)
	GetClosingTag() *BACnetClosingTag
	// GetLengthInBytes returns the length in bytes
	GetLengthInBytes() uint16
	// GetLengthInBits returns the length in bits
	GetLengthInBits() uint16
	// Serialize serializes this type
	Serialize(writeBuffer utils.WriteBuffer) error
}

///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
/////////////////////// Accessors for property fields.
///////////////////////

func (m *BACnetEventTimestampsEnclosed) GetOpeningTag() *BACnetOpeningTag {
	return m.OpeningTag
}

func (m *BACnetEventTimestampsEnclosed) GetEventTimestamps() *BACnetEventTimestamps {
	return m.EventTimestamps
}

func (m *BACnetEventTimestampsEnclosed) GetClosingTag() *BACnetClosingTag {
	return m.ClosingTag
}

///////////////////////
///////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////

// NewBACnetEventTimestampsEnclosed factory function for BACnetEventTimestampsEnclosed
func NewBACnetEventTimestampsEnclosed(openingTag *BACnetOpeningTag, eventTimestamps *BACnetEventTimestamps, closingTag *BACnetClosingTag, tagNumber uint8) *BACnetEventTimestampsEnclosed {
	return &BACnetEventTimestampsEnclosed{OpeningTag: openingTag, EventTimestamps: eventTimestamps, ClosingTag: closingTag, TagNumber: tagNumber}
}

func CastBACnetEventTimestampsEnclosed(structType interface{}) *BACnetEventTimestampsEnclosed {
	if casted, ok := structType.(BACnetEventTimestampsEnclosed); ok {
		return &casted
	}
	if casted, ok := structType.(*BACnetEventTimestampsEnclosed); ok {
		return casted
	}
	return nil
}

func (m *BACnetEventTimestampsEnclosed) GetTypeName() string {
	return "BACnetEventTimestampsEnclosed"
}

func (m *BACnetEventTimestampsEnclosed) GetLengthInBits() uint16 {
	return m.GetLengthInBitsConditional(false)
}

func (m *BACnetEventTimestampsEnclosed) GetLengthInBitsConditional(lastItem bool) uint16 {
	lengthInBits := uint16(0)

	// Simple field (openingTag)
	lengthInBits += m.OpeningTag.GetLengthInBits()

	// Simple field (eventTimestamps)
	lengthInBits += m.EventTimestamps.GetLengthInBits()

	// Simple field (closingTag)
	lengthInBits += m.ClosingTag.GetLengthInBits()

	return lengthInBits
}

func (m *BACnetEventTimestampsEnclosed) GetLengthInBytes() uint16 {
	return m.GetLengthInBits() / 8
}

func BACnetEventTimestampsEnclosedParse(readBuffer utils.ReadBuffer, tagNumber uint8) (*BACnetEventTimestampsEnclosed, error) {
	positionAware := readBuffer
	_ = positionAware
	if pullErr := readBuffer.PullContext("BACnetEventTimestampsEnclosed"); pullErr != nil {
		return nil, pullErr
	}
	currentPos := positionAware.GetPos()
	_ = currentPos

	// Simple Field (openingTag)
	if pullErr := readBuffer.PullContext("openingTag"); pullErr != nil {
		return nil, pullErr
	}
	_openingTag, _openingTagErr := BACnetOpeningTagParse(readBuffer, uint8(tagNumber))
	if _openingTagErr != nil {
		return nil, errors.Wrap(_openingTagErr, "Error parsing 'openingTag' field")
	}
	openingTag := CastBACnetOpeningTag(_openingTag)
	if closeErr := readBuffer.CloseContext("openingTag"); closeErr != nil {
		return nil, closeErr
	}

	// Simple Field (eventTimestamps)
	if pullErr := readBuffer.PullContext("eventTimestamps"); pullErr != nil {
		return nil, pullErr
	}
	_eventTimestamps, _eventTimestampsErr := BACnetEventTimestampsParse(readBuffer)
	if _eventTimestampsErr != nil {
		return nil, errors.Wrap(_eventTimestampsErr, "Error parsing 'eventTimestamps' field")
	}
	eventTimestamps := CastBACnetEventTimestamps(_eventTimestamps)
	if closeErr := readBuffer.CloseContext("eventTimestamps"); closeErr != nil {
		return nil, closeErr
	}

	// Simple Field (closingTag)
	if pullErr := readBuffer.PullContext("closingTag"); pullErr != nil {
		return nil, pullErr
	}
	_closingTag, _closingTagErr := BACnetClosingTagParse(readBuffer, uint8(tagNumber))
	if _closingTagErr != nil {
		return nil, errors.Wrap(_closingTagErr, "Error parsing 'closingTag' field")
	}
	closingTag := CastBACnetClosingTag(_closingTag)
	if closeErr := readBuffer.CloseContext("closingTag"); closeErr != nil {
		return nil, closeErr
	}

	if closeErr := readBuffer.CloseContext("BACnetEventTimestampsEnclosed"); closeErr != nil {
		return nil, closeErr
	}

	// Create the instance
	return NewBACnetEventTimestampsEnclosed(openingTag, eventTimestamps, closingTag, tagNumber), nil
}

func (m *BACnetEventTimestampsEnclosed) Serialize(writeBuffer utils.WriteBuffer) error {
	positionAware := writeBuffer
	_ = positionAware
	if pushErr := writeBuffer.PushContext("BACnetEventTimestampsEnclosed"); pushErr != nil {
		return pushErr
	}

	// Simple Field (openingTag)
	if pushErr := writeBuffer.PushContext("openingTag"); pushErr != nil {
		return pushErr
	}
	_openingTagErr := m.OpeningTag.Serialize(writeBuffer)
	if popErr := writeBuffer.PopContext("openingTag"); popErr != nil {
		return popErr
	}
	if _openingTagErr != nil {
		return errors.Wrap(_openingTagErr, "Error serializing 'openingTag' field")
	}

	// Simple Field (eventTimestamps)
	if pushErr := writeBuffer.PushContext("eventTimestamps"); pushErr != nil {
		return pushErr
	}
	_eventTimestampsErr := m.EventTimestamps.Serialize(writeBuffer)
	if popErr := writeBuffer.PopContext("eventTimestamps"); popErr != nil {
		return popErr
	}
	if _eventTimestampsErr != nil {
		return errors.Wrap(_eventTimestampsErr, "Error serializing 'eventTimestamps' field")
	}

	// Simple Field (closingTag)
	if pushErr := writeBuffer.PushContext("closingTag"); pushErr != nil {
		return pushErr
	}
	_closingTagErr := m.ClosingTag.Serialize(writeBuffer)
	if popErr := writeBuffer.PopContext("closingTag"); popErr != nil {
		return popErr
	}
	if _closingTagErr != nil {
		return errors.Wrap(_closingTagErr, "Error serializing 'closingTag' field")
	}

	if popErr := writeBuffer.PopContext("BACnetEventTimestampsEnclosed"); popErr != nil {
		return popErr
	}
	return nil
}

func (m *BACnetEventTimestampsEnclosed) String() string {
	if m == nil {
		return "<nil>"
	}
	buffer := utils.NewBoxedWriteBufferWithOptions(true, true)
	if err := m.Serialize(buffer); err != nil {
		return err.Error()
	}
	return buffer.GetBox().String()
}