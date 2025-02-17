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

// BACnetConstructedDataDefaultSubordinateRelationship is the corresponding interface of BACnetConstructedDataDefaultSubordinateRelationship
type BACnetConstructedDataDefaultSubordinateRelationship interface {
	utils.LengthAware
	utils.Serializable
	BACnetConstructedData
	// GetDefaultSubordinateRelationship returns DefaultSubordinateRelationship (property field)
	GetDefaultSubordinateRelationship() BACnetRelationshipTagged
	// GetActualValue returns ActualValue (virtual field)
	GetActualValue() BACnetRelationshipTagged
}

// BACnetConstructedDataDefaultSubordinateRelationshipExactly can be used when we want exactly this type and not a type which fulfills BACnetConstructedDataDefaultSubordinateRelationship.
// This is useful for switch cases.
type BACnetConstructedDataDefaultSubordinateRelationshipExactly interface {
	BACnetConstructedDataDefaultSubordinateRelationship
	isBACnetConstructedDataDefaultSubordinateRelationship() bool
}

// _BACnetConstructedDataDefaultSubordinateRelationship is the data-structure of this message
type _BACnetConstructedDataDefaultSubordinateRelationship struct {
	*_BACnetConstructedData
	DefaultSubordinateRelationship BACnetRelationshipTagged
}

///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
/////////////////////// Accessors for discriminator values.
///////////////////////

func (m *_BACnetConstructedDataDefaultSubordinateRelationship) GetObjectTypeArgument() BACnetObjectType {
	return 0
}

func (m *_BACnetConstructedDataDefaultSubordinateRelationship) GetPropertyIdentifierArgument() BACnetPropertyIdentifier {
	return BACnetPropertyIdentifier_DEFAULT_SUBORDINATE_RELATIONSHIP
}

///////////////////////
///////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////

func (m *_BACnetConstructedDataDefaultSubordinateRelationship) InitializeParent(parent BACnetConstructedData, openingTag BACnetOpeningTag, peekedTagHeader BACnetTagHeader, closingTag BACnetClosingTag) {
	m.OpeningTag = openingTag
	m.PeekedTagHeader = peekedTagHeader
	m.ClosingTag = closingTag
}

func (m *_BACnetConstructedDataDefaultSubordinateRelationship) GetParent() BACnetConstructedData {
	return m._BACnetConstructedData
}

///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
/////////////////////// Accessors for property fields.
///////////////////////

func (m *_BACnetConstructedDataDefaultSubordinateRelationship) GetDefaultSubordinateRelationship() BACnetRelationshipTagged {
	return m.DefaultSubordinateRelationship
}

///////////////////////
///////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
/////////////////////// Accessors for virtual fields.
///////////////////////

func (m *_BACnetConstructedDataDefaultSubordinateRelationship) GetActualValue() BACnetRelationshipTagged {
	return CastBACnetRelationshipTagged(m.GetDefaultSubordinateRelationship())
}

///////////////////////
///////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////

// NewBACnetConstructedDataDefaultSubordinateRelationship factory function for _BACnetConstructedDataDefaultSubordinateRelationship
func NewBACnetConstructedDataDefaultSubordinateRelationship(defaultSubordinateRelationship BACnetRelationshipTagged, openingTag BACnetOpeningTag, peekedTagHeader BACnetTagHeader, closingTag BACnetClosingTag, tagNumber uint8, arrayIndexArgument BACnetTagPayloadUnsignedInteger) *_BACnetConstructedDataDefaultSubordinateRelationship {
	_result := &_BACnetConstructedDataDefaultSubordinateRelationship{
		DefaultSubordinateRelationship: defaultSubordinateRelationship,
		_BACnetConstructedData:         NewBACnetConstructedData(openingTag, peekedTagHeader, closingTag, tagNumber, arrayIndexArgument),
	}
	_result._BACnetConstructedData._BACnetConstructedDataChildRequirements = _result
	return _result
}

// Deprecated: use the interface for direct cast
func CastBACnetConstructedDataDefaultSubordinateRelationship(structType interface{}) BACnetConstructedDataDefaultSubordinateRelationship {
	if casted, ok := structType.(BACnetConstructedDataDefaultSubordinateRelationship); ok {
		return casted
	}
	if casted, ok := structType.(*BACnetConstructedDataDefaultSubordinateRelationship); ok {
		return *casted
	}
	return nil
}

func (m *_BACnetConstructedDataDefaultSubordinateRelationship) GetTypeName() string {
	return "BACnetConstructedDataDefaultSubordinateRelationship"
}

func (m *_BACnetConstructedDataDefaultSubordinateRelationship) GetLengthInBits() uint16 {
	return m.GetLengthInBitsConditional(false)
}

func (m *_BACnetConstructedDataDefaultSubordinateRelationship) GetLengthInBitsConditional(lastItem bool) uint16 {
	lengthInBits := uint16(m.GetParentLengthInBits())

	// Simple field (defaultSubordinateRelationship)
	lengthInBits += m.DefaultSubordinateRelationship.GetLengthInBits()

	// A virtual field doesn't have any in- or output.

	return lengthInBits
}

func (m *_BACnetConstructedDataDefaultSubordinateRelationship) GetLengthInBytes() uint16 {
	return m.GetLengthInBits() / 8
}

func BACnetConstructedDataDefaultSubordinateRelationshipParse(readBuffer utils.ReadBuffer, tagNumber uint8, objectTypeArgument BACnetObjectType, propertyIdentifierArgument BACnetPropertyIdentifier, arrayIndexArgument BACnetTagPayloadUnsignedInteger) (BACnetConstructedDataDefaultSubordinateRelationship, error) {
	positionAware := readBuffer
	_ = positionAware
	if pullErr := readBuffer.PullContext("BACnetConstructedDataDefaultSubordinateRelationship"); pullErr != nil {
		return nil, errors.Wrap(pullErr, "Error pulling for BACnetConstructedDataDefaultSubordinateRelationship")
	}
	currentPos := positionAware.GetPos()
	_ = currentPos

	// Simple Field (defaultSubordinateRelationship)
	if pullErr := readBuffer.PullContext("defaultSubordinateRelationship"); pullErr != nil {
		return nil, errors.Wrap(pullErr, "Error pulling for defaultSubordinateRelationship")
	}
	_defaultSubordinateRelationship, _defaultSubordinateRelationshipErr := BACnetRelationshipTaggedParse(readBuffer, uint8(uint8(0)), TagClass(TagClass_APPLICATION_TAGS))
	if _defaultSubordinateRelationshipErr != nil {
		return nil, errors.Wrap(_defaultSubordinateRelationshipErr, "Error parsing 'defaultSubordinateRelationship' field")
	}
	defaultSubordinateRelationship := _defaultSubordinateRelationship.(BACnetRelationshipTagged)
	if closeErr := readBuffer.CloseContext("defaultSubordinateRelationship"); closeErr != nil {
		return nil, errors.Wrap(closeErr, "Error closing for defaultSubordinateRelationship")
	}

	// Virtual field
	_actualValue := defaultSubordinateRelationship
	actualValue := _actualValue
	_ = actualValue

	if closeErr := readBuffer.CloseContext("BACnetConstructedDataDefaultSubordinateRelationship"); closeErr != nil {
		return nil, errors.Wrap(closeErr, "Error closing for BACnetConstructedDataDefaultSubordinateRelationship")
	}

	// Create a partially initialized instance
	_child := &_BACnetConstructedDataDefaultSubordinateRelationship{
		DefaultSubordinateRelationship: defaultSubordinateRelationship,
		_BACnetConstructedData: &_BACnetConstructedData{
			TagNumber:          tagNumber,
			ArrayIndexArgument: arrayIndexArgument,
		},
	}
	_child._BACnetConstructedData._BACnetConstructedDataChildRequirements = _child
	return _child, nil
}

func (m *_BACnetConstructedDataDefaultSubordinateRelationship) Serialize(writeBuffer utils.WriteBuffer) error {
	positionAware := writeBuffer
	_ = positionAware
	ser := func() error {
		if pushErr := writeBuffer.PushContext("BACnetConstructedDataDefaultSubordinateRelationship"); pushErr != nil {
			return errors.Wrap(pushErr, "Error pushing for BACnetConstructedDataDefaultSubordinateRelationship")
		}

		// Simple Field (defaultSubordinateRelationship)
		if pushErr := writeBuffer.PushContext("defaultSubordinateRelationship"); pushErr != nil {
			return errors.Wrap(pushErr, "Error pushing for defaultSubordinateRelationship")
		}
		_defaultSubordinateRelationshipErr := writeBuffer.WriteSerializable(m.GetDefaultSubordinateRelationship())
		if popErr := writeBuffer.PopContext("defaultSubordinateRelationship"); popErr != nil {
			return errors.Wrap(popErr, "Error popping for defaultSubordinateRelationship")
		}
		if _defaultSubordinateRelationshipErr != nil {
			return errors.Wrap(_defaultSubordinateRelationshipErr, "Error serializing 'defaultSubordinateRelationship' field")
		}
		// Virtual field
		if _actualValueErr := writeBuffer.WriteVirtual("actualValue", m.GetActualValue()); _actualValueErr != nil {
			return errors.Wrap(_actualValueErr, "Error serializing 'actualValue' field")
		}

		if popErr := writeBuffer.PopContext("BACnetConstructedDataDefaultSubordinateRelationship"); popErr != nil {
			return errors.Wrap(popErr, "Error popping for BACnetConstructedDataDefaultSubordinateRelationship")
		}
		return nil
	}
	return m.SerializeParent(writeBuffer, m, ser)
}

func (m *_BACnetConstructedDataDefaultSubordinateRelationship) isBACnetConstructedDataDefaultSubordinateRelationship() bool {
	return true
}

func (m *_BACnetConstructedDataDefaultSubordinateRelationship) String() string {
	if m == nil {
		return "<nil>"
	}
	writeBuffer := utils.NewBoxedWriteBufferWithOptions(true, true)
	if err := writeBuffer.WriteSerializable(m); err != nil {
		return err.Error()
	}
	return writeBuffer.GetBox().String()
}
