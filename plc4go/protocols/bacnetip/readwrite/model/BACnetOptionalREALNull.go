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

// BACnetOptionalREALNull is the corresponding interface of BACnetOptionalREALNull
type BACnetOptionalREALNull interface {
	utils.LengthAware
	utils.Serializable
	BACnetOptionalREAL
	// GetNullValue returns NullValue (property field)
	GetNullValue() BACnetApplicationTagNull
}

// BACnetOptionalREALNullExactly can be used when we want exactly this type and not a type which fulfills BACnetOptionalREALNull.
// This is useful for switch cases.
type BACnetOptionalREALNullExactly interface {
	BACnetOptionalREALNull
	isBACnetOptionalREALNull() bool
}

// _BACnetOptionalREALNull is the data-structure of this message
type _BACnetOptionalREALNull struct {
	*_BACnetOptionalREAL
	NullValue BACnetApplicationTagNull
}

///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
/////////////////////// Accessors for discriminator values.
///////////////////////

///////////////////////
///////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////

func (m *_BACnetOptionalREALNull) InitializeParent(parent BACnetOptionalREAL, peekedTagHeader BACnetTagHeader) {
	m.PeekedTagHeader = peekedTagHeader
}

func (m *_BACnetOptionalREALNull) GetParent() BACnetOptionalREAL {
	return m._BACnetOptionalREAL
}

///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
/////////////////////// Accessors for property fields.
///////////////////////

func (m *_BACnetOptionalREALNull) GetNullValue() BACnetApplicationTagNull {
	return m.NullValue
}

///////////////////////
///////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////

// NewBACnetOptionalREALNull factory function for _BACnetOptionalREALNull
func NewBACnetOptionalREALNull(nullValue BACnetApplicationTagNull, peekedTagHeader BACnetTagHeader) *_BACnetOptionalREALNull {
	_result := &_BACnetOptionalREALNull{
		NullValue:           nullValue,
		_BACnetOptionalREAL: NewBACnetOptionalREAL(peekedTagHeader),
	}
	_result._BACnetOptionalREAL._BACnetOptionalREALChildRequirements = _result
	return _result
}

// Deprecated: use the interface for direct cast
func CastBACnetOptionalREALNull(structType interface{}) BACnetOptionalREALNull {
	if casted, ok := structType.(BACnetOptionalREALNull); ok {
		return casted
	}
	if casted, ok := structType.(*BACnetOptionalREALNull); ok {
		return *casted
	}
	return nil
}

func (m *_BACnetOptionalREALNull) GetTypeName() string {
	return "BACnetOptionalREALNull"
}

func (m *_BACnetOptionalREALNull) GetLengthInBits() uint16 {
	return m.GetLengthInBitsConditional(false)
}

func (m *_BACnetOptionalREALNull) GetLengthInBitsConditional(lastItem bool) uint16 {
	lengthInBits := uint16(m.GetParentLengthInBits())

	// Simple field (nullValue)
	lengthInBits += m.NullValue.GetLengthInBits()

	return lengthInBits
}

func (m *_BACnetOptionalREALNull) GetLengthInBytes() uint16 {
	return m.GetLengthInBits() / 8
}

func BACnetOptionalREALNullParse(readBuffer utils.ReadBuffer) (BACnetOptionalREALNull, error) {
	positionAware := readBuffer
	_ = positionAware
	if pullErr := readBuffer.PullContext("BACnetOptionalREALNull"); pullErr != nil {
		return nil, errors.Wrap(pullErr, "Error pulling for BACnetOptionalREALNull")
	}
	currentPos := positionAware.GetPos()
	_ = currentPos

	// Simple Field (nullValue)
	if pullErr := readBuffer.PullContext("nullValue"); pullErr != nil {
		return nil, errors.Wrap(pullErr, "Error pulling for nullValue")
	}
	_nullValue, _nullValueErr := BACnetApplicationTagParse(readBuffer)
	if _nullValueErr != nil {
		return nil, errors.Wrap(_nullValueErr, "Error parsing 'nullValue' field")
	}
	nullValue := _nullValue.(BACnetApplicationTagNull)
	if closeErr := readBuffer.CloseContext("nullValue"); closeErr != nil {
		return nil, errors.Wrap(closeErr, "Error closing for nullValue")
	}

	if closeErr := readBuffer.CloseContext("BACnetOptionalREALNull"); closeErr != nil {
		return nil, errors.Wrap(closeErr, "Error closing for BACnetOptionalREALNull")
	}

	// Create a partially initialized instance
	_child := &_BACnetOptionalREALNull{
		NullValue:           nullValue,
		_BACnetOptionalREAL: &_BACnetOptionalREAL{},
	}
	_child._BACnetOptionalREAL._BACnetOptionalREALChildRequirements = _child
	return _child, nil
}

func (m *_BACnetOptionalREALNull) Serialize(writeBuffer utils.WriteBuffer) error {
	positionAware := writeBuffer
	_ = positionAware
	ser := func() error {
		if pushErr := writeBuffer.PushContext("BACnetOptionalREALNull"); pushErr != nil {
			return errors.Wrap(pushErr, "Error pushing for BACnetOptionalREALNull")
		}

		// Simple Field (nullValue)
		if pushErr := writeBuffer.PushContext("nullValue"); pushErr != nil {
			return errors.Wrap(pushErr, "Error pushing for nullValue")
		}
		_nullValueErr := writeBuffer.WriteSerializable(m.GetNullValue())
		if popErr := writeBuffer.PopContext("nullValue"); popErr != nil {
			return errors.Wrap(popErr, "Error popping for nullValue")
		}
		if _nullValueErr != nil {
			return errors.Wrap(_nullValueErr, "Error serializing 'nullValue' field")
		}

		if popErr := writeBuffer.PopContext("BACnetOptionalREALNull"); popErr != nil {
			return errors.Wrap(popErr, "Error popping for BACnetOptionalREALNull")
		}
		return nil
	}
	return m.SerializeParent(writeBuffer, m, ser)
}

func (m *_BACnetOptionalREALNull) isBACnetOptionalREALNull() bool {
	return true
}

func (m *_BACnetOptionalREALNull) String() string {
	if m == nil {
		return "<nil>"
	}
	writeBuffer := utils.NewBoxedWriteBufferWithOptions(true, true)
	if err := writeBuffer.WriteSerializable(m); err != nil {
		return err.Error()
	}
	return writeBuffer.GetBox().String()
}
