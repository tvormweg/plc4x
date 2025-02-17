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

// BACnetConstructedDataBACnetIPNATTraversal is the corresponding interface of BACnetConstructedDataBACnetIPNATTraversal
type BACnetConstructedDataBACnetIPNATTraversal interface {
	utils.LengthAware
	utils.Serializable
	BACnetConstructedData
	// GetBacnetIPNATTraversal returns BacnetIPNATTraversal (property field)
	GetBacnetIPNATTraversal() BACnetApplicationTagBoolean
	// GetActualValue returns ActualValue (virtual field)
	GetActualValue() BACnetApplicationTagBoolean
}

// BACnetConstructedDataBACnetIPNATTraversalExactly can be used when we want exactly this type and not a type which fulfills BACnetConstructedDataBACnetIPNATTraversal.
// This is useful for switch cases.
type BACnetConstructedDataBACnetIPNATTraversalExactly interface {
	BACnetConstructedDataBACnetIPNATTraversal
	isBACnetConstructedDataBACnetIPNATTraversal() bool
}

// _BACnetConstructedDataBACnetIPNATTraversal is the data-structure of this message
type _BACnetConstructedDataBACnetIPNATTraversal struct {
	*_BACnetConstructedData
	BacnetIPNATTraversal BACnetApplicationTagBoolean
}

///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
/////////////////////// Accessors for discriminator values.
///////////////////////

func (m *_BACnetConstructedDataBACnetIPNATTraversal) GetObjectTypeArgument() BACnetObjectType {
	return 0
}

func (m *_BACnetConstructedDataBACnetIPNATTraversal) GetPropertyIdentifierArgument() BACnetPropertyIdentifier {
	return BACnetPropertyIdentifier_BACNET_IP_NAT_TRAVERSAL
}

///////////////////////
///////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////

func (m *_BACnetConstructedDataBACnetIPNATTraversal) InitializeParent(parent BACnetConstructedData, openingTag BACnetOpeningTag, peekedTagHeader BACnetTagHeader, closingTag BACnetClosingTag) {
	m.OpeningTag = openingTag
	m.PeekedTagHeader = peekedTagHeader
	m.ClosingTag = closingTag
}

func (m *_BACnetConstructedDataBACnetIPNATTraversal) GetParent() BACnetConstructedData {
	return m._BACnetConstructedData
}

///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
/////////////////////// Accessors for property fields.
///////////////////////

func (m *_BACnetConstructedDataBACnetIPNATTraversal) GetBacnetIPNATTraversal() BACnetApplicationTagBoolean {
	return m.BacnetIPNATTraversal
}

///////////////////////
///////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
/////////////////////// Accessors for virtual fields.
///////////////////////

func (m *_BACnetConstructedDataBACnetIPNATTraversal) GetActualValue() BACnetApplicationTagBoolean {
	return CastBACnetApplicationTagBoolean(m.GetBacnetIPNATTraversal())
}

///////////////////////
///////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////

// NewBACnetConstructedDataBACnetIPNATTraversal factory function for _BACnetConstructedDataBACnetIPNATTraversal
func NewBACnetConstructedDataBACnetIPNATTraversal(bacnetIPNATTraversal BACnetApplicationTagBoolean, openingTag BACnetOpeningTag, peekedTagHeader BACnetTagHeader, closingTag BACnetClosingTag, tagNumber uint8, arrayIndexArgument BACnetTagPayloadUnsignedInteger) *_BACnetConstructedDataBACnetIPNATTraversal {
	_result := &_BACnetConstructedDataBACnetIPNATTraversal{
		BacnetIPNATTraversal:   bacnetIPNATTraversal,
		_BACnetConstructedData: NewBACnetConstructedData(openingTag, peekedTagHeader, closingTag, tagNumber, arrayIndexArgument),
	}
	_result._BACnetConstructedData._BACnetConstructedDataChildRequirements = _result
	return _result
}

// Deprecated: use the interface for direct cast
func CastBACnetConstructedDataBACnetIPNATTraversal(structType interface{}) BACnetConstructedDataBACnetIPNATTraversal {
	if casted, ok := structType.(BACnetConstructedDataBACnetIPNATTraversal); ok {
		return casted
	}
	if casted, ok := structType.(*BACnetConstructedDataBACnetIPNATTraversal); ok {
		return *casted
	}
	return nil
}

func (m *_BACnetConstructedDataBACnetIPNATTraversal) GetTypeName() string {
	return "BACnetConstructedDataBACnetIPNATTraversal"
}

func (m *_BACnetConstructedDataBACnetIPNATTraversal) GetLengthInBits() uint16 {
	return m.GetLengthInBitsConditional(false)
}

func (m *_BACnetConstructedDataBACnetIPNATTraversal) GetLengthInBitsConditional(lastItem bool) uint16 {
	lengthInBits := uint16(m.GetParentLengthInBits())

	// Simple field (bacnetIPNATTraversal)
	lengthInBits += m.BacnetIPNATTraversal.GetLengthInBits()

	// A virtual field doesn't have any in- or output.

	return lengthInBits
}

func (m *_BACnetConstructedDataBACnetIPNATTraversal) GetLengthInBytes() uint16 {
	return m.GetLengthInBits() / 8
}

func BACnetConstructedDataBACnetIPNATTraversalParse(readBuffer utils.ReadBuffer, tagNumber uint8, objectTypeArgument BACnetObjectType, propertyIdentifierArgument BACnetPropertyIdentifier, arrayIndexArgument BACnetTagPayloadUnsignedInteger) (BACnetConstructedDataBACnetIPNATTraversal, error) {
	positionAware := readBuffer
	_ = positionAware
	if pullErr := readBuffer.PullContext("BACnetConstructedDataBACnetIPNATTraversal"); pullErr != nil {
		return nil, errors.Wrap(pullErr, "Error pulling for BACnetConstructedDataBACnetIPNATTraversal")
	}
	currentPos := positionAware.GetPos()
	_ = currentPos

	// Simple Field (bacnetIPNATTraversal)
	if pullErr := readBuffer.PullContext("bacnetIPNATTraversal"); pullErr != nil {
		return nil, errors.Wrap(pullErr, "Error pulling for bacnetIPNATTraversal")
	}
	_bacnetIPNATTraversal, _bacnetIPNATTraversalErr := BACnetApplicationTagParse(readBuffer)
	if _bacnetIPNATTraversalErr != nil {
		return nil, errors.Wrap(_bacnetIPNATTraversalErr, "Error parsing 'bacnetIPNATTraversal' field")
	}
	bacnetIPNATTraversal := _bacnetIPNATTraversal.(BACnetApplicationTagBoolean)
	if closeErr := readBuffer.CloseContext("bacnetIPNATTraversal"); closeErr != nil {
		return nil, errors.Wrap(closeErr, "Error closing for bacnetIPNATTraversal")
	}

	// Virtual field
	_actualValue := bacnetIPNATTraversal
	actualValue := _actualValue
	_ = actualValue

	if closeErr := readBuffer.CloseContext("BACnetConstructedDataBACnetIPNATTraversal"); closeErr != nil {
		return nil, errors.Wrap(closeErr, "Error closing for BACnetConstructedDataBACnetIPNATTraversal")
	}

	// Create a partially initialized instance
	_child := &_BACnetConstructedDataBACnetIPNATTraversal{
		BacnetIPNATTraversal: bacnetIPNATTraversal,
		_BACnetConstructedData: &_BACnetConstructedData{
			TagNumber:          tagNumber,
			ArrayIndexArgument: arrayIndexArgument,
		},
	}
	_child._BACnetConstructedData._BACnetConstructedDataChildRequirements = _child
	return _child, nil
}

func (m *_BACnetConstructedDataBACnetIPNATTraversal) Serialize(writeBuffer utils.WriteBuffer) error {
	positionAware := writeBuffer
	_ = positionAware
	ser := func() error {
		if pushErr := writeBuffer.PushContext("BACnetConstructedDataBACnetIPNATTraversal"); pushErr != nil {
			return errors.Wrap(pushErr, "Error pushing for BACnetConstructedDataBACnetIPNATTraversal")
		}

		// Simple Field (bacnetIPNATTraversal)
		if pushErr := writeBuffer.PushContext("bacnetIPNATTraversal"); pushErr != nil {
			return errors.Wrap(pushErr, "Error pushing for bacnetIPNATTraversal")
		}
		_bacnetIPNATTraversalErr := writeBuffer.WriteSerializable(m.GetBacnetIPNATTraversal())
		if popErr := writeBuffer.PopContext("bacnetIPNATTraversal"); popErr != nil {
			return errors.Wrap(popErr, "Error popping for bacnetIPNATTraversal")
		}
		if _bacnetIPNATTraversalErr != nil {
			return errors.Wrap(_bacnetIPNATTraversalErr, "Error serializing 'bacnetIPNATTraversal' field")
		}
		// Virtual field
		if _actualValueErr := writeBuffer.WriteVirtual("actualValue", m.GetActualValue()); _actualValueErr != nil {
			return errors.Wrap(_actualValueErr, "Error serializing 'actualValue' field")
		}

		if popErr := writeBuffer.PopContext("BACnetConstructedDataBACnetIPNATTraversal"); popErr != nil {
			return errors.Wrap(popErr, "Error popping for BACnetConstructedDataBACnetIPNATTraversal")
		}
		return nil
	}
	return m.SerializeParent(writeBuffer, m, ser)
}

func (m *_BACnetConstructedDataBACnetIPNATTraversal) isBACnetConstructedDataBACnetIPNATTraversal() bool {
	return true
}

func (m *_BACnetConstructedDataBACnetIPNATTraversal) String() string {
	if m == nil {
		return "<nil>"
	}
	writeBuffer := utils.NewBoxedWriteBufferWithOptions(true, true)
	if err := writeBuffer.WriteSerializable(m); err != nil {
		return err.Error()
	}
	return writeBuffer.GetBox().String()
}
