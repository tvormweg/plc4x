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

// BACnetConstructedDataArchive is the corresponding interface of BACnetConstructedDataArchive
type BACnetConstructedDataArchive interface {
	utils.LengthAware
	utils.Serializable
	BACnetConstructedData
	// GetArchive returns Archive (property field)
	GetArchive() BACnetApplicationTagBoolean
	// GetActualValue returns ActualValue (virtual field)
	GetActualValue() BACnetApplicationTagBoolean
}

// BACnetConstructedDataArchiveExactly can be used when we want exactly this type and not a type which fulfills BACnetConstructedDataArchive.
// This is useful for switch cases.
type BACnetConstructedDataArchiveExactly interface {
	BACnetConstructedDataArchive
	isBACnetConstructedDataArchive() bool
}

// _BACnetConstructedDataArchive is the data-structure of this message
type _BACnetConstructedDataArchive struct {
	*_BACnetConstructedData
	Archive BACnetApplicationTagBoolean
}

///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
/////////////////////// Accessors for discriminator values.
///////////////////////

func (m *_BACnetConstructedDataArchive) GetObjectTypeArgument() BACnetObjectType {
	return 0
}

func (m *_BACnetConstructedDataArchive) GetPropertyIdentifierArgument() BACnetPropertyIdentifier {
	return BACnetPropertyIdentifier_ARCHIVE
}

///////////////////////
///////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////

func (m *_BACnetConstructedDataArchive) InitializeParent(parent BACnetConstructedData, openingTag BACnetOpeningTag, peekedTagHeader BACnetTagHeader, closingTag BACnetClosingTag) {
	m.OpeningTag = openingTag
	m.PeekedTagHeader = peekedTagHeader
	m.ClosingTag = closingTag
}

func (m *_BACnetConstructedDataArchive) GetParent() BACnetConstructedData {
	return m._BACnetConstructedData
}

///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
/////////////////////// Accessors for property fields.
///////////////////////

func (m *_BACnetConstructedDataArchive) GetArchive() BACnetApplicationTagBoolean {
	return m.Archive
}

///////////////////////
///////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
/////////////////////// Accessors for virtual fields.
///////////////////////

func (m *_BACnetConstructedDataArchive) GetActualValue() BACnetApplicationTagBoolean {
	return CastBACnetApplicationTagBoolean(m.GetArchive())
}

///////////////////////
///////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////

// NewBACnetConstructedDataArchive factory function for _BACnetConstructedDataArchive
func NewBACnetConstructedDataArchive(archive BACnetApplicationTagBoolean, openingTag BACnetOpeningTag, peekedTagHeader BACnetTagHeader, closingTag BACnetClosingTag, tagNumber uint8, arrayIndexArgument BACnetTagPayloadUnsignedInteger) *_BACnetConstructedDataArchive {
	_result := &_BACnetConstructedDataArchive{
		Archive:                archive,
		_BACnetConstructedData: NewBACnetConstructedData(openingTag, peekedTagHeader, closingTag, tagNumber, arrayIndexArgument),
	}
	_result._BACnetConstructedData._BACnetConstructedDataChildRequirements = _result
	return _result
}

// Deprecated: use the interface for direct cast
func CastBACnetConstructedDataArchive(structType interface{}) BACnetConstructedDataArchive {
	if casted, ok := structType.(BACnetConstructedDataArchive); ok {
		return casted
	}
	if casted, ok := structType.(*BACnetConstructedDataArchive); ok {
		return *casted
	}
	return nil
}

func (m *_BACnetConstructedDataArchive) GetTypeName() string {
	return "BACnetConstructedDataArchive"
}

func (m *_BACnetConstructedDataArchive) GetLengthInBits() uint16 {
	return m.GetLengthInBitsConditional(false)
}

func (m *_BACnetConstructedDataArchive) GetLengthInBitsConditional(lastItem bool) uint16 {
	lengthInBits := uint16(m.GetParentLengthInBits())

	// Simple field (archive)
	lengthInBits += m.Archive.GetLengthInBits()

	// A virtual field doesn't have any in- or output.

	return lengthInBits
}

func (m *_BACnetConstructedDataArchive) GetLengthInBytes() uint16 {
	return m.GetLengthInBits() / 8
}

func BACnetConstructedDataArchiveParse(readBuffer utils.ReadBuffer, tagNumber uint8, objectTypeArgument BACnetObjectType, propertyIdentifierArgument BACnetPropertyIdentifier, arrayIndexArgument BACnetTagPayloadUnsignedInteger) (BACnetConstructedDataArchive, error) {
	positionAware := readBuffer
	_ = positionAware
	if pullErr := readBuffer.PullContext("BACnetConstructedDataArchive"); pullErr != nil {
		return nil, errors.Wrap(pullErr, "Error pulling for BACnetConstructedDataArchive")
	}
	currentPos := positionAware.GetPos()
	_ = currentPos

	// Simple Field (archive)
	if pullErr := readBuffer.PullContext("archive"); pullErr != nil {
		return nil, errors.Wrap(pullErr, "Error pulling for archive")
	}
	_archive, _archiveErr := BACnetApplicationTagParse(readBuffer)
	if _archiveErr != nil {
		return nil, errors.Wrap(_archiveErr, "Error parsing 'archive' field")
	}
	archive := _archive.(BACnetApplicationTagBoolean)
	if closeErr := readBuffer.CloseContext("archive"); closeErr != nil {
		return nil, errors.Wrap(closeErr, "Error closing for archive")
	}

	// Virtual field
	_actualValue := archive
	actualValue := _actualValue
	_ = actualValue

	if closeErr := readBuffer.CloseContext("BACnetConstructedDataArchive"); closeErr != nil {
		return nil, errors.Wrap(closeErr, "Error closing for BACnetConstructedDataArchive")
	}

	// Create a partially initialized instance
	_child := &_BACnetConstructedDataArchive{
		Archive: archive,
		_BACnetConstructedData: &_BACnetConstructedData{
			TagNumber:          tagNumber,
			ArrayIndexArgument: arrayIndexArgument,
		},
	}
	_child._BACnetConstructedData._BACnetConstructedDataChildRequirements = _child
	return _child, nil
}

func (m *_BACnetConstructedDataArchive) Serialize(writeBuffer utils.WriteBuffer) error {
	positionAware := writeBuffer
	_ = positionAware
	ser := func() error {
		if pushErr := writeBuffer.PushContext("BACnetConstructedDataArchive"); pushErr != nil {
			return errors.Wrap(pushErr, "Error pushing for BACnetConstructedDataArchive")
		}

		// Simple Field (archive)
		if pushErr := writeBuffer.PushContext("archive"); pushErr != nil {
			return errors.Wrap(pushErr, "Error pushing for archive")
		}
		_archiveErr := writeBuffer.WriteSerializable(m.GetArchive())
		if popErr := writeBuffer.PopContext("archive"); popErr != nil {
			return errors.Wrap(popErr, "Error popping for archive")
		}
		if _archiveErr != nil {
			return errors.Wrap(_archiveErr, "Error serializing 'archive' field")
		}
		// Virtual field
		if _actualValueErr := writeBuffer.WriteVirtual("actualValue", m.GetActualValue()); _actualValueErr != nil {
			return errors.Wrap(_actualValueErr, "Error serializing 'actualValue' field")
		}

		if popErr := writeBuffer.PopContext("BACnetConstructedDataArchive"); popErr != nil {
			return errors.Wrap(popErr, "Error popping for BACnetConstructedDataArchive")
		}
		return nil
	}
	return m.SerializeParent(writeBuffer, m, ser)
}

func (m *_BACnetConstructedDataArchive) isBACnetConstructedDataArchive() bool {
	return true
}

func (m *_BACnetConstructedDataArchive) String() string {
	if m == nil {
		return "<nil>"
	}
	writeBuffer := utils.NewBoxedWriteBufferWithOptions(true, true)
	if err := writeBuffer.WriteSerializable(m); err != nil {
		return err.Error()
	}
	return writeBuffer.GetBox().String()
}
