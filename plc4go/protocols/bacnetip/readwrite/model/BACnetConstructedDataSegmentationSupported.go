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

// BACnetConstructedDataSegmentationSupported is the data-structure of this message
type BACnetConstructedDataSegmentationSupported struct {
	*BACnetConstructedData
	SegmentationSupported *BACnetSegmentationTagged

	// Arguments.
	TagNumber          uint8
	ArrayIndexArgument *BACnetTagPayloadUnsignedInteger
}

// IBACnetConstructedDataSegmentationSupported is the corresponding interface of BACnetConstructedDataSegmentationSupported
type IBACnetConstructedDataSegmentationSupported interface {
	IBACnetConstructedData
	// GetSegmentationSupported returns SegmentationSupported (property field)
	GetSegmentationSupported() *BACnetSegmentationTagged
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

func (m *BACnetConstructedDataSegmentationSupported) GetObjectTypeArgument() BACnetObjectType {
	return 0
}

func (m *BACnetConstructedDataSegmentationSupported) GetPropertyIdentifierArgument() BACnetPropertyIdentifier {
	return BACnetPropertyIdentifier_SEGMENTATION_SUPPORTED
}

///////////////////////
///////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////

func (m *BACnetConstructedDataSegmentationSupported) InitializeParent(parent *BACnetConstructedData, openingTag *BACnetOpeningTag, peekedTagHeader *BACnetTagHeader, closingTag *BACnetClosingTag) {
	m.BACnetConstructedData.OpeningTag = openingTag
	m.BACnetConstructedData.PeekedTagHeader = peekedTagHeader
	m.BACnetConstructedData.ClosingTag = closingTag
}

func (m *BACnetConstructedDataSegmentationSupported) GetParent() *BACnetConstructedData {
	return m.BACnetConstructedData
}

///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
/////////////////////// Accessors for property fields.
///////////////////////

func (m *BACnetConstructedDataSegmentationSupported) GetSegmentationSupported() *BACnetSegmentationTagged {
	return m.SegmentationSupported
}

///////////////////////
///////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////

// NewBACnetConstructedDataSegmentationSupported factory function for BACnetConstructedDataSegmentationSupported
func NewBACnetConstructedDataSegmentationSupported(segmentationSupported *BACnetSegmentationTagged, openingTag *BACnetOpeningTag, peekedTagHeader *BACnetTagHeader, closingTag *BACnetClosingTag, tagNumber uint8, arrayIndexArgument *BACnetTagPayloadUnsignedInteger) *BACnetConstructedDataSegmentationSupported {
	_result := &BACnetConstructedDataSegmentationSupported{
		SegmentationSupported: segmentationSupported,
		BACnetConstructedData: NewBACnetConstructedData(openingTag, peekedTagHeader, closingTag, tagNumber, arrayIndexArgument),
	}
	_result.Child = _result
	return _result
}

func CastBACnetConstructedDataSegmentationSupported(structType interface{}) *BACnetConstructedDataSegmentationSupported {
	if casted, ok := structType.(BACnetConstructedDataSegmentationSupported); ok {
		return &casted
	}
	if casted, ok := structType.(*BACnetConstructedDataSegmentationSupported); ok {
		return casted
	}
	if casted, ok := structType.(BACnetConstructedData); ok {
		return CastBACnetConstructedDataSegmentationSupported(casted.Child)
	}
	if casted, ok := structType.(*BACnetConstructedData); ok {
		return CastBACnetConstructedDataSegmentationSupported(casted.Child)
	}
	return nil
}

func (m *BACnetConstructedDataSegmentationSupported) GetTypeName() string {
	return "BACnetConstructedDataSegmentationSupported"
}

func (m *BACnetConstructedDataSegmentationSupported) GetLengthInBits() uint16 {
	return m.GetLengthInBitsConditional(false)
}

func (m *BACnetConstructedDataSegmentationSupported) GetLengthInBitsConditional(lastItem bool) uint16 {
	lengthInBits := uint16(m.GetParentLengthInBits())

	// Simple field (segmentationSupported)
	lengthInBits += m.SegmentationSupported.GetLengthInBits()

	return lengthInBits
}

func (m *BACnetConstructedDataSegmentationSupported) GetLengthInBytes() uint16 {
	return m.GetLengthInBits() / 8
}

func BACnetConstructedDataSegmentationSupportedParse(readBuffer utils.ReadBuffer, tagNumber uint8, objectTypeArgument BACnetObjectType, propertyIdentifierArgument BACnetPropertyIdentifier, arrayIndexArgument *BACnetTagPayloadUnsignedInteger) (*BACnetConstructedDataSegmentationSupported, error) {
	positionAware := readBuffer
	_ = positionAware
	if pullErr := readBuffer.PullContext("BACnetConstructedDataSegmentationSupported"); pullErr != nil {
		return nil, pullErr
	}
	currentPos := positionAware.GetPos()
	_ = currentPos

	// Simple Field (segmentationSupported)
	if pullErr := readBuffer.PullContext("segmentationSupported"); pullErr != nil {
		return nil, pullErr
	}
	_segmentationSupported, _segmentationSupportedErr := BACnetSegmentationTaggedParse(readBuffer, uint8(uint8(0)), TagClass(TagClass_APPLICATION_TAGS))
	if _segmentationSupportedErr != nil {
		return nil, errors.Wrap(_segmentationSupportedErr, "Error parsing 'segmentationSupported' field")
	}
	segmentationSupported := CastBACnetSegmentationTagged(_segmentationSupported)
	if closeErr := readBuffer.CloseContext("segmentationSupported"); closeErr != nil {
		return nil, closeErr
	}

	if closeErr := readBuffer.CloseContext("BACnetConstructedDataSegmentationSupported"); closeErr != nil {
		return nil, closeErr
	}

	// Create a partially initialized instance
	_child := &BACnetConstructedDataSegmentationSupported{
		SegmentationSupported: CastBACnetSegmentationTagged(segmentationSupported),
		BACnetConstructedData: &BACnetConstructedData{},
	}
	_child.BACnetConstructedData.Child = _child
	return _child, nil
}

func (m *BACnetConstructedDataSegmentationSupported) Serialize(writeBuffer utils.WriteBuffer) error {
	positionAware := writeBuffer
	_ = positionAware
	ser := func() error {
		if pushErr := writeBuffer.PushContext("BACnetConstructedDataSegmentationSupported"); pushErr != nil {
			return pushErr
		}

		// Simple Field (segmentationSupported)
		if pushErr := writeBuffer.PushContext("segmentationSupported"); pushErr != nil {
			return pushErr
		}
		_segmentationSupportedErr := m.SegmentationSupported.Serialize(writeBuffer)
		if popErr := writeBuffer.PopContext("segmentationSupported"); popErr != nil {
			return popErr
		}
		if _segmentationSupportedErr != nil {
			return errors.Wrap(_segmentationSupportedErr, "Error serializing 'segmentationSupported' field")
		}

		if popErr := writeBuffer.PopContext("BACnetConstructedDataSegmentationSupported"); popErr != nil {
			return popErr
		}
		return nil
	}
	return m.SerializeParent(writeBuffer, m, ser)
}

func (m *BACnetConstructedDataSegmentationSupported) String() string {
	if m == nil {
		return "<nil>"
	}
	buffer := utils.NewBoxedWriteBufferWithOptions(true, true)
	if err := m.Serialize(buffer); err != nil {
		return err.Error()
	}
	return buffer.GetBox().String()
}