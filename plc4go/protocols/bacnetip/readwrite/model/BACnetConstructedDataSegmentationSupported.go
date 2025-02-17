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

// BACnetConstructedDataSegmentationSupported is the corresponding interface of BACnetConstructedDataSegmentationSupported
type BACnetConstructedDataSegmentationSupported interface {
	utils.LengthAware
	utils.Serializable
	BACnetConstructedData
	// GetSegmentationSupported returns SegmentationSupported (property field)
	GetSegmentationSupported() BACnetSegmentationTagged
	// GetActualValue returns ActualValue (virtual field)
	GetActualValue() BACnetSegmentationTagged
}

// BACnetConstructedDataSegmentationSupportedExactly can be used when we want exactly this type and not a type which fulfills BACnetConstructedDataSegmentationSupported.
// This is useful for switch cases.
type BACnetConstructedDataSegmentationSupportedExactly interface {
	BACnetConstructedDataSegmentationSupported
	isBACnetConstructedDataSegmentationSupported() bool
}

// _BACnetConstructedDataSegmentationSupported is the data-structure of this message
type _BACnetConstructedDataSegmentationSupported struct {
	*_BACnetConstructedData
	SegmentationSupported BACnetSegmentationTagged
}

///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
/////////////////////// Accessors for discriminator values.
///////////////////////

func (m *_BACnetConstructedDataSegmentationSupported) GetObjectTypeArgument() BACnetObjectType {
	return 0
}

func (m *_BACnetConstructedDataSegmentationSupported) GetPropertyIdentifierArgument() BACnetPropertyIdentifier {
	return BACnetPropertyIdentifier_SEGMENTATION_SUPPORTED
}

///////////////////////
///////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////

func (m *_BACnetConstructedDataSegmentationSupported) InitializeParent(parent BACnetConstructedData, openingTag BACnetOpeningTag, peekedTagHeader BACnetTagHeader, closingTag BACnetClosingTag) {
	m.OpeningTag = openingTag
	m.PeekedTagHeader = peekedTagHeader
	m.ClosingTag = closingTag
}

func (m *_BACnetConstructedDataSegmentationSupported) GetParent() BACnetConstructedData {
	return m._BACnetConstructedData
}

///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
/////////////////////// Accessors for property fields.
///////////////////////

func (m *_BACnetConstructedDataSegmentationSupported) GetSegmentationSupported() BACnetSegmentationTagged {
	return m.SegmentationSupported
}

///////////////////////
///////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
/////////////////////// Accessors for virtual fields.
///////////////////////

func (m *_BACnetConstructedDataSegmentationSupported) GetActualValue() BACnetSegmentationTagged {
	return CastBACnetSegmentationTagged(m.GetSegmentationSupported())
}

///////////////////////
///////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////

// NewBACnetConstructedDataSegmentationSupported factory function for _BACnetConstructedDataSegmentationSupported
func NewBACnetConstructedDataSegmentationSupported(segmentationSupported BACnetSegmentationTagged, openingTag BACnetOpeningTag, peekedTagHeader BACnetTagHeader, closingTag BACnetClosingTag, tagNumber uint8, arrayIndexArgument BACnetTagPayloadUnsignedInteger) *_BACnetConstructedDataSegmentationSupported {
	_result := &_BACnetConstructedDataSegmentationSupported{
		SegmentationSupported:  segmentationSupported,
		_BACnetConstructedData: NewBACnetConstructedData(openingTag, peekedTagHeader, closingTag, tagNumber, arrayIndexArgument),
	}
	_result._BACnetConstructedData._BACnetConstructedDataChildRequirements = _result
	return _result
}

// Deprecated: use the interface for direct cast
func CastBACnetConstructedDataSegmentationSupported(structType interface{}) BACnetConstructedDataSegmentationSupported {
	if casted, ok := structType.(BACnetConstructedDataSegmentationSupported); ok {
		return casted
	}
	if casted, ok := structType.(*BACnetConstructedDataSegmentationSupported); ok {
		return *casted
	}
	return nil
}

func (m *_BACnetConstructedDataSegmentationSupported) GetTypeName() string {
	return "BACnetConstructedDataSegmentationSupported"
}

func (m *_BACnetConstructedDataSegmentationSupported) GetLengthInBits() uint16 {
	return m.GetLengthInBitsConditional(false)
}

func (m *_BACnetConstructedDataSegmentationSupported) GetLengthInBitsConditional(lastItem bool) uint16 {
	lengthInBits := uint16(m.GetParentLengthInBits())

	// Simple field (segmentationSupported)
	lengthInBits += m.SegmentationSupported.GetLengthInBits()

	// A virtual field doesn't have any in- or output.

	return lengthInBits
}

func (m *_BACnetConstructedDataSegmentationSupported) GetLengthInBytes() uint16 {
	return m.GetLengthInBits() / 8
}

func BACnetConstructedDataSegmentationSupportedParse(readBuffer utils.ReadBuffer, tagNumber uint8, objectTypeArgument BACnetObjectType, propertyIdentifierArgument BACnetPropertyIdentifier, arrayIndexArgument BACnetTagPayloadUnsignedInteger) (BACnetConstructedDataSegmentationSupported, error) {
	positionAware := readBuffer
	_ = positionAware
	if pullErr := readBuffer.PullContext("BACnetConstructedDataSegmentationSupported"); pullErr != nil {
		return nil, errors.Wrap(pullErr, "Error pulling for BACnetConstructedDataSegmentationSupported")
	}
	currentPos := positionAware.GetPos()
	_ = currentPos

	// Simple Field (segmentationSupported)
	if pullErr := readBuffer.PullContext("segmentationSupported"); pullErr != nil {
		return nil, errors.Wrap(pullErr, "Error pulling for segmentationSupported")
	}
	_segmentationSupported, _segmentationSupportedErr := BACnetSegmentationTaggedParse(readBuffer, uint8(uint8(0)), TagClass(TagClass_APPLICATION_TAGS))
	if _segmentationSupportedErr != nil {
		return nil, errors.Wrap(_segmentationSupportedErr, "Error parsing 'segmentationSupported' field")
	}
	segmentationSupported := _segmentationSupported.(BACnetSegmentationTagged)
	if closeErr := readBuffer.CloseContext("segmentationSupported"); closeErr != nil {
		return nil, errors.Wrap(closeErr, "Error closing for segmentationSupported")
	}

	// Virtual field
	_actualValue := segmentationSupported
	actualValue := _actualValue
	_ = actualValue

	if closeErr := readBuffer.CloseContext("BACnetConstructedDataSegmentationSupported"); closeErr != nil {
		return nil, errors.Wrap(closeErr, "Error closing for BACnetConstructedDataSegmentationSupported")
	}

	// Create a partially initialized instance
	_child := &_BACnetConstructedDataSegmentationSupported{
		SegmentationSupported: segmentationSupported,
		_BACnetConstructedData: &_BACnetConstructedData{
			TagNumber:          tagNumber,
			ArrayIndexArgument: arrayIndexArgument,
		},
	}
	_child._BACnetConstructedData._BACnetConstructedDataChildRequirements = _child
	return _child, nil
}

func (m *_BACnetConstructedDataSegmentationSupported) Serialize(writeBuffer utils.WriteBuffer) error {
	positionAware := writeBuffer
	_ = positionAware
	ser := func() error {
		if pushErr := writeBuffer.PushContext("BACnetConstructedDataSegmentationSupported"); pushErr != nil {
			return errors.Wrap(pushErr, "Error pushing for BACnetConstructedDataSegmentationSupported")
		}

		// Simple Field (segmentationSupported)
		if pushErr := writeBuffer.PushContext("segmentationSupported"); pushErr != nil {
			return errors.Wrap(pushErr, "Error pushing for segmentationSupported")
		}
		_segmentationSupportedErr := writeBuffer.WriteSerializable(m.GetSegmentationSupported())
		if popErr := writeBuffer.PopContext("segmentationSupported"); popErr != nil {
			return errors.Wrap(popErr, "Error popping for segmentationSupported")
		}
		if _segmentationSupportedErr != nil {
			return errors.Wrap(_segmentationSupportedErr, "Error serializing 'segmentationSupported' field")
		}
		// Virtual field
		if _actualValueErr := writeBuffer.WriteVirtual("actualValue", m.GetActualValue()); _actualValueErr != nil {
			return errors.Wrap(_actualValueErr, "Error serializing 'actualValue' field")
		}

		if popErr := writeBuffer.PopContext("BACnetConstructedDataSegmentationSupported"); popErr != nil {
			return errors.Wrap(popErr, "Error popping for BACnetConstructedDataSegmentationSupported")
		}
		return nil
	}
	return m.SerializeParent(writeBuffer, m, ser)
}

func (m *_BACnetConstructedDataSegmentationSupported) isBACnetConstructedDataSegmentationSupported() bool {
	return true
}

func (m *_BACnetConstructedDataSegmentationSupported) String() string {
	if m == nil {
		return "<nil>"
	}
	writeBuffer := utils.NewBoxedWriteBufferWithOptions(true, true)
	if err := writeBuffer.WriteSerializable(m); err != nil {
		return err.Error()
	}
	return writeBuffer.GetBox().String()
}
