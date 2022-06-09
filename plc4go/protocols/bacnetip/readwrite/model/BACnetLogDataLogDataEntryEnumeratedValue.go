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

// BACnetLogDataLogDataEntryEnumeratedValue is the data-structure of this message
type BACnetLogDataLogDataEntryEnumeratedValue struct {
	*BACnetLogDataLogDataEntry
	EnumeratedValue *BACnetContextTagEnumerated
}

// IBACnetLogDataLogDataEntryEnumeratedValue is the corresponding interface of BACnetLogDataLogDataEntryEnumeratedValue
type IBACnetLogDataLogDataEntryEnumeratedValue interface {
	IBACnetLogDataLogDataEntry
	// GetEnumeratedValue returns EnumeratedValue (property field)
	GetEnumeratedValue() *BACnetContextTagEnumerated
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

///////////////////////
///////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////

func (m *BACnetLogDataLogDataEntryEnumeratedValue) InitializeParent(parent *BACnetLogDataLogDataEntry, peekedTagHeader *BACnetTagHeader) {
	m.BACnetLogDataLogDataEntry.PeekedTagHeader = peekedTagHeader
}

func (m *BACnetLogDataLogDataEntryEnumeratedValue) GetParent() *BACnetLogDataLogDataEntry {
	return m.BACnetLogDataLogDataEntry
}

///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
/////////////////////// Accessors for property fields.
///////////////////////

func (m *BACnetLogDataLogDataEntryEnumeratedValue) GetEnumeratedValue() *BACnetContextTagEnumerated {
	return m.EnumeratedValue
}

///////////////////////
///////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////

// NewBACnetLogDataLogDataEntryEnumeratedValue factory function for BACnetLogDataLogDataEntryEnumeratedValue
func NewBACnetLogDataLogDataEntryEnumeratedValue(enumeratedValue *BACnetContextTagEnumerated, peekedTagHeader *BACnetTagHeader) *BACnetLogDataLogDataEntryEnumeratedValue {
	_result := &BACnetLogDataLogDataEntryEnumeratedValue{
		EnumeratedValue:           enumeratedValue,
		BACnetLogDataLogDataEntry: NewBACnetLogDataLogDataEntry(peekedTagHeader),
	}
	_result.Child = _result
	return _result
}

func CastBACnetLogDataLogDataEntryEnumeratedValue(structType interface{}) *BACnetLogDataLogDataEntryEnumeratedValue {
	if casted, ok := structType.(BACnetLogDataLogDataEntryEnumeratedValue); ok {
		return &casted
	}
	if casted, ok := structType.(*BACnetLogDataLogDataEntryEnumeratedValue); ok {
		return casted
	}
	if casted, ok := structType.(BACnetLogDataLogDataEntry); ok {
		return CastBACnetLogDataLogDataEntryEnumeratedValue(casted.Child)
	}
	if casted, ok := structType.(*BACnetLogDataLogDataEntry); ok {
		return CastBACnetLogDataLogDataEntryEnumeratedValue(casted.Child)
	}
	return nil
}

func (m *BACnetLogDataLogDataEntryEnumeratedValue) GetTypeName() string {
	return "BACnetLogDataLogDataEntryEnumeratedValue"
}

func (m *BACnetLogDataLogDataEntryEnumeratedValue) GetLengthInBits() uint16 {
	return m.GetLengthInBitsConditional(false)
}

func (m *BACnetLogDataLogDataEntryEnumeratedValue) GetLengthInBitsConditional(lastItem bool) uint16 {
	lengthInBits := uint16(m.GetParentLengthInBits())

	// Simple field (enumeratedValue)
	lengthInBits += m.EnumeratedValue.GetLengthInBits()

	return lengthInBits
}

func (m *BACnetLogDataLogDataEntryEnumeratedValue) GetLengthInBytes() uint16 {
	return m.GetLengthInBits() / 8
}

func BACnetLogDataLogDataEntryEnumeratedValueParse(readBuffer utils.ReadBuffer) (*BACnetLogDataLogDataEntryEnumeratedValue, error) {
	positionAware := readBuffer
	_ = positionAware
	if pullErr := readBuffer.PullContext("BACnetLogDataLogDataEntryEnumeratedValue"); pullErr != nil {
		return nil, pullErr
	}
	currentPos := positionAware.GetPos()
	_ = currentPos

	// Simple Field (enumeratedValue)
	if pullErr := readBuffer.PullContext("enumeratedValue"); pullErr != nil {
		return nil, pullErr
	}
	_enumeratedValue, _enumeratedValueErr := BACnetContextTagParse(readBuffer, uint8(uint8(2)), BACnetDataType(BACnetDataType_ENUMERATED))
	if _enumeratedValueErr != nil {
		return nil, errors.Wrap(_enumeratedValueErr, "Error parsing 'enumeratedValue' field")
	}
	enumeratedValue := CastBACnetContextTagEnumerated(_enumeratedValue)
	if closeErr := readBuffer.CloseContext("enumeratedValue"); closeErr != nil {
		return nil, closeErr
	}

	if closeErr := readBuffer.CloseContext("BACnetLogDataLogDataEntryEnumeratedValue"); closeErr != nil {
		return nil, closeErr
	}

	// Create a partially initialized instance
	_child := &BACnetLogDataLogDataEntryEnumeratedValue{
		EnumeratedValue:           CastBACnetContextTagEnumerated(enumeratedValue),
		BACnetLogDataLogDataEntry: &BACnetLogDataLogDataEntry{},
	}
	_child.BACnetLogDataLogDataEntry.Child = _child
	return _child, nil
}

func (m *BACnetLogDataLogDataEntryEnumeratedValue) Serialize(writeBuffer utils.WriteBuffer) error {
	positionAware := writeBuffer
	_ = positionAware
	ser := func() error {
		if pushErr := writeBuffer.PushContext("BACnetLogDataLogDataEntryEnumeratedValue"); pushErr != nil {
			return pushErr
		}

		// Simple Field (enumeratedValue)
		if pushErr := writeBuffer.PushContext("enumeratedValue"); pushErr != nil {
			return pushErr
		}
		_enumeratedValueErr := m.EnumeratedValue.Serialize(writeBuffer)
		if popErr := writeBuffer.PopContext("enumeratedValue"); popErr != nil {
			return popErr
		}
		if _enumeratedValueErr != nil {
			return errors.Wrap(_enumeratedValueErr, "Error serializing 'enumeratedValue' field")
		}

		if popErr := writeBuffer.PopContext("BACnetLogDataLogDataEntryEnumeratedValue"); popErr != nil {
			return popErr
		}
		return nil
	}
	return m.SerializeParent(writeBuffer, m, ser)
}

func (m *BACnetLogDataLogDataEntryEnumeratedValue) String() string {
	if m == nil {
		return "<nil>"
	}
	buffer := utils.NewBoxedWriteBufferWithOptions(true, true)
	if err := m.Serialize(buffer); err != nil {
		return err.Error()
	}
	return buffer.GetBox().String()
}