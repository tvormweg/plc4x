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

// BACnetConstructedDataProtocolVersion is the data-structure of this message
type BACnetConstructedDataProtocolVersion struct {
	*BACnetConstructedData
	ProtocolVersion *BACnetApplicationTagUnsignedInteger

	// Arguments.
	TagNumber          uint8
	ArrayIndexArgument *BACnetTagPayloadUnsignedInteger
}

// IBACnetConstructedDataProtocolVersion is the corresponding interface of BACnetConstructedDataProtocolVersion
type IBACnetConstructedDataProtocolVersion interface {
	IBACnetConstructedData
	// GetProtocolVersion returns ProtocolVersion (property field)
	GetProtocolVersion() *BACnetApplicationTagUnsignedInteger
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

func (m *BACnetConstructedDataProtocolVersion) GetObjectTypeArgument() BACnetObjectType {
	return 0
}

func (m *BACnetConstructedDataProtocolVersion) GetPropertyIdentifierArgument() BACnetPropertyIdentifier {
	return BACnetPropertyIdentifier_PROTOCOL_VERSION
}

///////////////////////
///////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////

func (m *BACnetConstructedDataProtocolVersion) InitializeParent(parent *BACnetConstructedData, openingTag *BACnetOpeningTag, peekedTagHeader *BACnetTagHeader, closingTag *BACnetClosingTag) {
	m.BACnetConstructedData.OpeningTag = openingTag
	m.BACnetConstructedData.PeekedTagHeader = peekedTagHeader
	m.BACnetConstructedData.ClosingTag = closingTag
}

func (m *BACnetConstructedDataProtocolVersion) GetParent() *BACnetConstructedData {
	return m.BACnetConstructedData
}

///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
/////////////////////// Accessors for property fields.
///////////////////////

func (m *BACnetConstructedDataProtocolVersion) GetProtocolVersion() *BACnetApplicationTagUnsignedInteger {
	return m.ProtocolVersion
}

///////////////////////
///////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////

// NewBACnetConstructedDataProtocolVersion factory function for BACnetConstructedDataProtocolVersion
func NewBACnetConstructedDataProtocolVersion(protocolVersion *BACnetApplicationTagUnsignedInteger, openingTag *BACnetOpeningTag, peekedTagHeader *BACnetTagHeader, closingTag *BACnetClosingTag, tagNumber uint8, arrayIndexArgument *BACnetTagPayloadUnsignedInteger) *BACnetConstructedDataProtocolVersion {
	_result := &BACnetConstructedDataProtocolVersion{
		ProtocolVersion:       protocolVersion,
		BACnetConstructedData: NewBACnetConstructedData(openingTag, peekedTagHeader, closingTag, tagNumber, arrayIndexArgument),
	}
	_result.Child = _result
	return _result
}

func CastBACnetConstructedDataProtocolVersion(structType interface{}) *BACnetConstructedDataProtocolVersion {
	if casted, ok := structType.(BACnetConstructedDataProtocolVersion); ok {
		return &casted
	}
	if casted, ok := structType.(*BACnetConstructedDataProtocolVersion); ok {
		return casted
	}
	if casted, ok := structType.(BACnetConstructedData); ok {
		return CastBACnetConstructedDataProtocolVersion(casted.Child)
	}
	if casted, ok := structType.(*BACnetConstructedData); ok {
		return CastBACnetConstructedDataProtocolVersion(casted.Child)
	}
	return nil
}

func (m *BACnetConstructedDataProtocolVersion) GetTypeName() string {
	return "BACnetConstructedDataProtocolVersion"
}

func (m *BACnetConstructedDataProtocolVersion) GetLengthInBits() uint16 {
	return m.GetLengthInBitsConditional(false)
}

func (m *BACnetConstructedDataProtocolVersion) GetLengthInBitsConditional(lastItem bool) uint16 {
	lengthInBits := uint16(m.GetParentLengthInBits())

	// Simple field (protocolVersion)
	lengthInBits += m.ProtocolVersion.GetLengthInBits()

	return lengthInBits
}

func (m *BACnetConstructedDataProtocolVersion) GetLengthInBytes() uint16 {
	return m.GetLengthInBits() / 8
}

func BACnetConstructedDataProtocolVersionParse(readBuffer utils.ReadBuffer, tagNumber uint8, objectTypeArgument BACnetObjectType, propertyIdentifierArgument BACnetPropertyIdentifier, arrayIndexArgument *BACnetTagPayloadUnsignedInteger) (*BACnetConstructedDataProtocolVersion, error) {
	positionAware := readBuffer
	_ = positionAware
	if pullErr := readBuffer.PullContext("BACnetConstructedDataProtocolVersion"); pullErr != nil {
		return nil, pullErr
	}
	currentPos := positionAware.GetPos()
	_ = currentPos

	// Simple Field (protocolVersion)
	if pullErr := readBuffer.PullContext("protocolVersion"); pullErr != nil {
		return nil, pullErr
	}
	_protocolVersion, _protocolVersionErr := BACnetApplicationTagParse(readBuffer)
	if _protocolVersionErr != nil {
		return nil, errors.Wrap(_protocolVersionErr, "Error parsing 'protocolVersion' field")
	}
	protocolVersion := CastBACnetApplicationTagUnsignedInteger(_protocolVersion)
	if closeErr := readBuffer.CloseContext("protocolVersion"); closeErr != nil {
		return nil, closeErr
	}

	if closeErr := readBuffer.CloseContext("BACnetConstructedDataProtocolVersion"); closeErr != nil {
		return nil, closeErr
	}

	// Create a partially initialized instance
	_child := &BACnetConstructedDataProtocolVersion{
		ProtocolVersion:       CastBACnetApplicationTagUnsignedInteger(protocolVersion),
		BACnetConstructedData: &BACnetConstructedData{},
	}
	_child.BACnetConstructedData.Child = _child
	return _child, nil
}

func (m *BACnetConstructedDataProtocolVersion) Serialize(writeBuffer utils.WriteBuffer) error {
	positionAware := writeBuffer
	_ = positionAware
	ser := func() error {
		if pushErr := writeBuffer.PushContext("BACnetConstructedDataProtocolVersion"); pushErr != nil {
			return pushErr
		}

		// Simple Field (protocolVersion)
		if pushErr := writeBuffer.PushContext("protocolVersion"); pushErr != nil {
			return pushErr
		}
		_protocolVersionErr := m.ProtocolVersion.Serialize(writeBuffer)
		if popErr := writeBuffer.PopContext("protocolVersion"); popErr != nil {
			return popErr
		}
		if _protocolVersionErr != nil {
			return errors.Wrap(_protocolVersionErr, "Error serializing 'protocolVersion' field")
		}

		if popErr := writeBuffer.PopContext("BACnetConstructedDataProtocolVersion"); popErr != nil {
			return popErr
		}
		return nil
	}
	return m.SerializeParent(writeBuffer, m, ser)
}

func (m *BACnetConstructedDataProtocolVersion) String() string {
	if m == nil {
		return "<nil>"
	}
	buffer := utils.NewBoxedWriteBufferWithOptions(true, true)
	if err := m.Serialize(buffer); err != nil {
		return err.Error()
	}
	return buffer.GetBox().String()
}