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

// BACnetAssignedLandingCallsLandingCallsList is the corresponding interface of BACnetAssignedLandingCallsLandingCallsList
type BACnetAssignedLandingCallsLandingCallsList interface {
	utils.LengthAware
	utils.Serializable
	// GetOpeningTag returns OpeningTag (property field)
	GetOpeningTag() BACnetOpeningTag
	// GetLandingCalls returns LandingCalls (property field)
	GetLandingCalls() []BACnetAssignedLandingCallsLandingCallsListEntry
	// GetClosingTag returns ClosingTag (property field)
	GetClosingTag() BACnetClosingTag
}

// BACnetAssignedLandingCallsLandingCallsListExactly can be used when we want exactly this type and not a type which fulfills BACnetAssignedLandingCallsLandingCallsList.
// This is useful for switch cases.
type BACnetAssignedLandingCallsLandingCallsListExactly interface {
	BACnetAssignedLandingCallsLandingCallsList
	isBACnetAssignedLandingCallsLandingCallsList() bool
}

// _BACnetAssignedLandingCallsLandingCallsList is the data-structure of this message
type _BACnetAssignedLandingCallsLandingCallsList struct {
	OpeningTag   BACnetOpeningTag
	LandingCalls []BACnetAssignedLandingCallsLandingCallsListEntry
	ClosingTag   BACnetClosingTag

	// Arguments.
	TagNumber uint8
}

///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
/////////////////////// Accessors for property fields.
///////////////////////

func (m *_BACnetAssignedLandingCallsLandingCallsList) GetOpeningTag() BACnetOpeningTag {
	return m.OpeningTag
}

func (m *_BACnetAssignedLandingCallsLandingCallsList) GetLandingCalls() []BACnetAssignedLandingCallsLandingCallsListEntry {
	return m.LandingCalls
}

func (m *_BACnetAssignedLandingCallsLandingCallsList) GetClosingTag() BACnetClosingTag {
	return m.ClosingTag
}

///////////////////////
///////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////

// NewBACnetAssignedLandingCallsLandingCallsList factory function for _BACnetAssignedLandingCallsLandingCallsList
func NewBACnetAssignedLandingCallsLandingCallsList(openingTag BACnetOpeningTag, landingCalls []BACnetAssignedLandingCallsLandingCallsListEntry, closingTag BACnetClosingTag, tagNumber uint8) *_BACnetAssignedLandingCallsLandingCallsList {
	return &_BACnetAssignedLandingCallsLandingCallsList{OpeningTag: openingTag, LandingCalls: landingCalls, ClosingTag: closingTag, TagNumber: tagNumber}
}

// Deprecated: use the interface for direct cast
func CastBACnetAssignedLandingCallsLandingCallsList(structType interface{}) BACnetAssignedLandingCallsLandingCallsList {
	if casted, ok := structType.(BACnetAssignedLandingCallsLandingCallsList); ok {
		return casted
	}
	if casted, ok := structType.(*BACnetAssignedLandingCallsLandingCallsList); ok {
		return *casted
	}
	return nil
}

func (m *_BACnetAssignedLandingCallsLandingCallsList) GetTypeName() string {
	return "BACnetAssignedLandingCallsLandingCallsList"
}

func (m *_BACnetAssignedLandingCallsLandingCallsList) GetLengthInBits() uint16 {
	return m.GetLengthInBitsConditional(false)
}

func (m *_BACnetAssignedLandingCallsLandingCallsList) GetLengthInBitsConditional(lastItem bool) uint16 {
	lengthInBits := uint16(0)

	// Simple field (openingTag)
	lengthInBits += m.OpeningTag.GetLengthInBits()

	// Array field
	if len(m.LandingCalls) > 0 {
		for _, element := range m.LandingCalls {
			lengthInBits += element.GetLengthInBits()
		}
	}

	// Simple field (closingTag)
	lengthInBits += m.ClosingTag.GetLengthInBits()

	return lengthInBits
}

func (m *_BACnetAssignedLandingCallsLandingCallsList) GetLengthInBytes() uint16 {
	return m.GetLengthInBits() / 8
}

func BACnetAssignedLandingCallsLandingCallsListParse(readBuffer utils.ReadBuffer, tagNumber uint8) (BACnetAssignedLandingCallsLandingCallsList, error) {
	positionAware := readBuffer
	_ = positionAware
	if pullErr := readBuffer.PullContext("BACnetAssignedLandingCallsLandingCallsList"); pullErr != nil {
		return nil, errors.Wrap(pullErr, "Error pulling for BACnetAssignedLandingCallsLandingCallsList")
	}
	currentPos := positionAware.GetPos()
	_ = currentPos

	// Simple Field (openingTag)
	if pullErr := readBuffer.PullContext("openingTag"); pullErr != nil {
		return nil, errors.Wrap(pullErr, "Error pulling for openingTag")
	}
	_openingTag, _openingTagErr := BACnetOpeningTagParse(readBuffer, uint8(tagNumber))
	if _openingTagErr != nil {
		return nil, errors.Wrap(_openingTagErr, "Error parsing 'openingTag' field")
	}
	openingTag := _openingTag.(BACnetOpeningTag)
	if closeErr := readBuffer.CloseContext("openingTag"); closeErr != nil {
		return nil, errors.Wrap(closeErr, "Error closing for openingTag")
	}

	// Array field (landingCalls)
	if pullErr := readBuffer.PullContext("landingCalls", utils.WithRenderAsList(true)); pullErr != nil {
		return nil, errors.Wrap(pullErr, "Error pulling for landingCalls")
	}
	// Terminated array
	var landingCalls []BACnetAssignedLandingCallsLandingCallsListEntry
	{
		for !bool(IsBACnetConstructedDataClosingTag(readBuffer, false, tagNumber)) {
			_item, _err := BACnetAssignedLandingCallsLandingCallsListEntryParse(readBuffer)
			if _err != nil {
				return nil, errors.Wrap(_err, "Error parsing 'landingCalls' field")
			}
			landingCalls = append(landingCalls, _item.(BACnetAssignedLandingCallsLandingCallsListEntry))

		}
	}
	if closeErr := readBuffer.CloseContext("landingCalls", utils.WithRenderAsList(true)); closeErr != nil {
		return nil, errors.Wrap(closeErr, "Error closing for landingCalls")
	}

	// Simple Field (closingTag)
	if pullErr := readBuffer.PullContext("closingTag"); pullErr != nil {
		return nil, errors.Wrap(pullErr, "Error pulling for closingTag")
	}
	_closingTag, _closingTagErr := BACnetClosingTagParse(readBuffer, uint8(tagNumber))
	if _closingTagErr != nil {
		return nil, errors.Wrap(_closingTagErr, "Error parsing 'closingTag' field")
	}
	closingTag := _closingTag.(BACnetClosingTag)
	if closeErr := readBuffer.CloseContext("closingTag"); closeErr != nil {
		return nil, errors.Wrap(closeErr, "Error closing for closingTag")
	}

	if closeErr := readBuffer.CloseContext("BACnetAssignedLandingCallsLandingCallsList"); closeErr != nil {
		return nil, errors.Wrap(closeErr, "Error closing for BACnetAssignedLandingCallsLandingCallsList")
	}

	// Create the instance
	return NewBACnetAssignedLandingCallsLandingCallsList(openingTag, landingCalls, closingTag, tagNumber), nil
}

func (m *_BACnetAssignedLandingCallsLandingCallsList) Serialize(writeBuffer utils.WriteBuffer) error {
	positionAware := writeBuffer
	_ = positionAware
	if pushErr := writeBuffer.PushContext("BACnetAssignedLandingCallsLandingCallsList"); pushErr != nil {
		return errors.Wrap(pushErr, "Error pushing for BACnetAssignedLandingCallsLandingCallsList")
	}

	// Simple Field (openingTag)
	if pushErr := writeBuffer.PushContext("openingTag"); pushErr != nil {
		return errors.Wrap(pushErr, "Error pushing for openingTag")
	}
	_openingTagErr := writeBuffer.WriteSerializable(m.GetOpeningTag())
	if popErr := writeBuffer.PopContext("openingTag"); popErr != nil {
		return errors.Wrap(popErr, "Error popping for openingTag")
	}
	if _openingTagErr != nil {
		return errors.Wrap(_openingTagErr, "Error serializing 'openingTag' field")
	}

	// Array Field (landingCalls)
	if pushErr := writeBuffer.PushContext("landingCalls", utils.WithRenderAsList(true)); pushErr != nil {
		return errors.Wrap(pushErr, "Error pushing for landingCalls")
	}
	for _, _element := range m.GetLandingCalls() {
		_elementErr := writeBuffer.WriteSerializable(_element)
		if _elementErr != nil {
			return errors.Wrap(_elementErr, "Error serializing 'landingCalls' field")
		}
	}
	if popErr := writeBuffer.PopContext("landingCalls", utils.WithRenderAsList(true)); popErr != nil {
		return errors.Wrap(popErr, "Error popping for landingCalls")
	}

	// Simple Field (closingTag)
	if pushErr := writeBuffer.PushContext("closingTag"); pushErr != nil {
		return errors.Wrap(pushErr, "Error pushing for closingTag")
	}
	_closingTagErr := writeBuffer.WriteSerializable(m.GetClosingTag())
	if popErr := writeBuffer.PopContext("closingTag"); popErr != nil {
		return errors.Wrap(popErr, "Error popping for closingTag")
	}
	if _closingTagErr != nil {
		return errors.Wrap(_closingTagErr, "Error serializing 'closingTag' field")
	}

	if popErr := writeBuffer.PopContext("BACnetAssignedLandingCallsLandingCallsList"); popErr != nil {
		return errors.Wrap(popErr, "Error popping for BACnetAssignedLandingCallsLandingCallsList")
	}
	return nil
}

func (m *_BACnetAssignedLandingCallsLandingCallsList) isBACnetAssignedLandingCallsLandingCallsList() bool {
	return true
}

func (m *_BACnetAssignedLandingCallsLandingCallsList) String() string {
	if m == nil {
		return "<nil>"
	}
	writeBuffer := utils.NewBoxedWriteBufferWithOptions(true, true)
	if err := writeBuffer.WriteSerializable(m); err != nil {
		return err.Error()
	}
	return writeBuffer.GetBox().String()
}
