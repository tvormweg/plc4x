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

// BACnetPriorityValueOctetString is the corresponding interface of BACnetPriorityValueOctetString
type BACnetPriorityValueOctetString interface {
	utils.LengthAware
	utils.Serializable
	BACnetPriorityValue
	// GetOctetStringValue returns OctetStringValue (property field)
	GetOctetStringValue() BACnetApplicationTagOctetString
}

// BACnetPriorityValueOctetStringExactly can be used when we want exactly this type and not a type which fulfills BACnetPriorityValueOctetString.
// This is useful for switch cases.
type BACnetPriorityValueOctetStringExactly interface {
	BACnetPriorityValueOctetString
	isBACnetPriorityValueOctetString() bool
}

// _BACnetPriorityValueOctetString is the data-structure of this message
type _BACnetPriorityValueOctetString struct {
	*_BACnetPriorityValue
	OctetStringValue BACnetApplicationTagOctetString
}

///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
/////////////////////// Accessors for discriminator values.
///////////////////////

///////////////////////
///////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////

func (m *_BACnetPriorityValueOctetString) InitializeParent(parent BACnetPriorityValue, peekedTagHeader BACnetTagHeader) {
	m.PeekedTagHeader = peekedTagHeader
}

func (m *_BACnetPriorityValueOctetString) GetParent() BACnetPriorityValue {
	return m._BACnetPriorityValue
}

///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
/////////////////////// Accessors for property fields.
///////////////////////

func (m *_BACnetPriorityValueOctetString) GetOctetStringValue() BACnetApplicationTagOctetString {
	return m.OctetStringValue
}

///////////////////////
///////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////

// NewBACnetPriorityValueOctetString factory function for _BACnetPriorityValueOctetString
func NewBACnetPriorityValueOctetString(octetStringValue BACnetApplicationTagOctetString, peekedTagHeader BACnetTagHeader, objectTypeArgument BACnetObjectType) *_BACnetPriorityValueOctetString {
	_result := &_BACnetPriorityValueOctetString{
		OctetStringValue:     octetStringValue,
		_BACnetPriorityValue: NewBACnetPriorityValue(peekedTagHeader, objectTypeArgument),
	}
	_result._BACnetPriorityValue._BACnetPriorityValueChildRequirements = _result
	return _result
}

// Deprecated: use the interface for direct cast
func CastBACnetPriorityValueOctetString(structType interface{}) BACnetPriorityValueOctetString {
	if casted, ok := structType.(BACnetPriorityValueOctetString); ok {
		return casted
	}
	if casted, ok := structType.(*BACnetPriorityValueOctetString); ok {
		return *casted
	}
	return nil
}

func (m *_BACnetPriorityValueOctetString) GetTypeName() string {
	return "BACnetPriorityValueOctetString"
}

func (m *_BACnetPriorityValueOctetString) GetLengthInBits() uint16 {
	return m.GetLengthInBitsConditional(false)
}

func (m *_BACnetPriorityValueOctetString) GetLengthInBitsConditional(lastItem bool) uint16 {
	lengthInBits := uint16(m.GetParentLengthInBits())

	// Simple field (octetStringValue)
	lengthInBits += m.OctetStringValue.GetLengthInBits()

	return lengthInBits
}

func (m *_BACnetPriorityValueOctetString) GetLengthInBytes() uint16 {
	return m.GetLengthInBits() / 8
}

func BACnetPriorityValueOctetStringParse(readBuffer utils.ReadBuffer, objectTypeArgument BACnetObjectType) (BACnetPriorityValueOctetString, error) {
	positionAware := readBuffer
	_ = positionAware
	if pullErr := readBuffer.PullContext("BACnetPriorityValueOctetString"); pullErr != nil {
		return nil, errors.Wrap(pullErr, "Error pulling for BACnetPriorityValueOctetString")
	}
	currentPos := positionAware.GetPos()
	_ = currentPos

	// Simple Field (octetStringValue)
	if pullErr := readBuffer.PullContext("octetStringValue"); pullErr != nil {
		return nil, errors.Wrap(pullErr, "Error pulling for octetStringValue")
	}
	_octetStringValue, _octetStringValueErr := BACnetApplicationTagParse(readBuffer)
	if _octetStringValueErr != nil {
		return nil, errors.Wrap(_octetStringValueErr, "Error parsing 'octetStringValue' field")
	}
	octetStringValue := _octetStringValue.(BACnetApplicationTagOctetString)
	if closeErr := readBuffer.CloseContext("octetStringValue"); closeErr != nil {
		return nil, errors.Wrap(closeErr, "Error closing for octetStringValue")
	}

	if closeErr := readBuffer.CloseContext("BACnetPriorityValueOctetString"); closeErr != nil {
		return nil, errors.Wrap(closeErr, "Error closing for BACnetPriorityValueOctetString")
	}

	// Create a partially initialized instance
	_child := &_BACnetPriorityValueOctetString{
		OctetStringValue: octetStringValue,
		_BACnetPriorityValue: &_BACnetPriorityValue{
			ObjectTypeArgument: objectTypeArgument,
		},
	}
	_child._BACnetPriorityValue._BACnetPriorityValueChildRequirements = _child
	return _child, nil
}

func (m *_BACnetPriorityValueOctetString) Serialize(writeBuffer utils.WriteBuffer) error {
	positionAware := writeBuffer
	_ = positionAware
	ser := func() error {
		if pushErr := writeBuffer.PushContext("BACnetPriorityValueOctetString"); pushErr != nil {
			return errors.Wrap(pushErr, "Error pushing for BACnetPriorityValueOctetString")
		}

		// Simple Field (octetStringValue)
		if pushErr := writeBuffer.PushContext("octetStringValue"); pushErr != nil {
			return errors.Wrap(pushErr, "Error pushing for octetStringValue")
		}
		_octetStringValueErr := writeBuffer.WriteSerializable(m.GetOctetStringValue())
		if popErr := writeBuffer.PopContext("octetStringValue"); popErr != nil {
			return errors.Wrap(popErr, "Error popping for octetStringValue")
		}
		if _octetStringValueErr != nil {
			return errors.Wrap(_octetStringValueErr, "Error serializing 'octetStringValue' field")
		}

		if popErr := writeBuffer.PopContext("BACnetPriorityValueOctetString"); popErr != nil {
			return errors.Wrap(popErr, "Error popping for BACnetPriorityValueOctetString")
		}
		return nil
	}
	return m.SerializeParent(writeBuffer, m, ser)
}

func (m *_BACnetPriorityValueOctetString) isBACnetPriorityValueOctetString() bool {
	return true
}

func (m *_BACnetPriorityValueOctetString) String() string {
	if m == nil {
		return "<nil>"
	}
	writeBuffer := utils.NewBoxedWriteBufferWithOptions(true, true)
	if err := writeBuffer.WriteSerializable(m); err != nil {
		return err.Error()
	}
	return writeBuffer.GetBox().String()
}
