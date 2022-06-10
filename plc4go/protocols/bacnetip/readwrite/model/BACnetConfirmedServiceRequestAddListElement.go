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
	"github.com/rs/zerolog/log"
	"io"
)

// Code generated by code-generation. DO NOT EDIT.

// BACnetConfirmedServiceRequestAddListElement is the data-structure of this message
type BACnetConfirmedServiceRequestAddListElement struct {
	*BACnetConfirmedServiceRequest
	ObjectIdentifier   *BACnetContextTagObjectIdentifier
	PropertyIdentifier *BACnetPropertyIdentifierTagged
	ArrayIndex         *BACnetContextTagUnsignedInteger
	ListOfElements     *BACnetConstructedData

	// Arguments.
	ServiceRequestLength uint16
}

// IBACnetConfirmedServiceRequestAddListElement is the corresponding interface of BACnetConfirmedServiceRequestAddListElement
type IBACnetConfirmedServiceRequestAddListElement interface {
	IBACnetConfirmedServiceRequest
	// GetObjectIdentifier returns ObjectIdentifier (property field)
	GetObjectIdentifier() *BACnetContextTagObjectIdentifier
	// GetPropertyIdentifier returns PropertyIdentifier (property field)
	GetPropertyIdentifier() *BACnetPropertyIdentifierTagged
	// GetArrayIndex returns ArrayIndex (property field)
	GetArrayIndex() *BACnetContextTagUnsignedInteger
	// GetListOfElements returns ListOfElements (property field)
	GetListOfElements() *BACnetConstructedData
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

func (m *BACnetConfirmedServiceRequestAddListElement) GetServiceChoice() BACnetConfirmedServiceChoice {
	return BACnetConfirmedServiceChoice_ADD_LIST_ELEMENT
}

///////////////////////
///////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////

func (m *BACnetConfirmedServiceRequestAddListElement) InitializeParent(parent *BACnetConfirmedServiceRequest) {
}

func (m *BACnetConfirmedServiceRequestAddListElement) GetParent() *BACnetConfirmedServiceRequest {
	return m.BACnetConfirmedServiceRequest
}

///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
/////////////////////// Accessors for property fields.
///////////////////////

func (m *BACnetConfirmedServiceRequestAddListElement) GetObjectIdentifier() *BACnetContextTagObjectIdentifier {
	return m.ObjectIdentifier
}

func (m *BACnetConfirmedServiceRequestAddListElement) GetPropertyIdentifier() *BACnetPropertyIdentifierTagged {
	return m.PropertyIdentifier
}

func (m *BACnetConfirmedServiceRequestAddListElement) GetArrayIndex() *BACnetContextTagUnsignedInteger {
	return m.ArrayIndex
}

func (m *BACnetConfirmedServiceRequestAddListElement) GetListOfElements() *BACnetConstructedData {
	return m.ListOfElements
}

///////////////////////
///////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////

// NewBACnetConfirmedServiceRequestAddListElement factory function for BACnetConfirmedServiceRequestAddListElement
func NewBACnetConfirmedServiceRequestAddListElement(objectIdentifier *BACnetContextTagObjectIdentifier, propertyIdentifier *BACnetPropertyIdentifierTagged, arrayIndex *BACnetContextTagUnsignedInteger, listOfElements *BACnetConstructedData, serviceRequestLength uint16) *BACnetConfirmedServiceRequestAddListElement {
	_result := &BACnetConfirmedServiceRequestAddListElement{
		ObjectIdentifier:              objectIdentifier,
		PropertyIdentifier:            propertyIdentifier,
		ArrayIndex:                    arrayIndex,
		ListOfElements:                listOfElements,
		BACnetConfirmedServiceRequest: NewBACnetConfirmedServiceRequest(serviceRequestLength),
	}
	_result.Child = _result
	return _result
}

func CastBACnetConfirmedServiceRequestAddListElement(structType interface{}) *BACnetConfirmedServiceRequestAddListElement {
	if casted, ok := structType.(BACnetConfirmedServiceRequestAddListElement); ok {
		return &casted
	}
	if casted, ok := structType.(*BACnetConfirmedServiceRequestAddListElement); ok {
		return casted
	}
	if casted, ok := structType.(BACnetConfirmedServiceRequest); ok {
		return CastBACnetConfirmedServiceRequestAddListElement(casted.Child)
	}
	if casted, ok := structType.(*BACnetConfirmedServiceRequest); ok {
		return CastBACnetConfirmedServiceRequestAddListElement(casted.Child)
	}
	return nil
}

func (m *BACnetConfirmedServiceRequestAddListElement) GetTypeName() string {
	return "BACnetConfirmedServiceRequestAddListElement"
}

func (m *BACnetConfirmedServiceRequestAddListElement) GetLengthInBits() uint16 {
	return m.GetLengthInBitsConditional(false)
}

func (m *BACnetConfirmedServiceRequestAddListElement) GetLengthInBitsConditional(lastItem bool) uint16 {
	lengthInBits := uint16(m.GetParentLengthInBits())

	// Simple field (objectIdentifier)
	lengthInBits += m.ObjectIdentifier.GetLengthInBits()

	// Simple field (propertyIdentifier)
	lengthInBits += m.PropertyIdentifier.GetLengthInBits()

	// Optional Field (arrayIndex)
	if m.ArrayIndex != nil {
		lengthInBits += (*m.ArrayIndex).GetLengthInBits()
	}

	// Optional Field (listOfElements)
	if m.ListOfElements != nil {
		lengthInBits += (*m.ListOfElements).GetLengthInBits()
	}

	return lengthInBits
}

func (m *BACnetConfirmedServiceRequestAddListElement) GetLengthInBytes() uint16 {
	return m.GetLengthInBits() / 8
}

func BACnetConfirmedServiceRequestAddListElementParse(readBuffer utils.ReadBuffer, serviceRequestLength uint16) (*BACnetConfirmedServiceRequestAddListElement, error) {
	positionAware := readBuffer
	_ = positionAware
	if pullErr := readBuffer.PullContext("BACnetConfirmedServiceRequestAddListElement"); pullErr != nil {
		return nil, pullErr
	}
	currentPos := positionAware.GetPos()
	_ = currentPos

	// Simple Field (objectIdentifier)
	if pullErr := readBuffer.PullContext("objectIdentifier"); pullErr != nil {
		return nil, pullErr
	}
	_objectIdentifier, _objectIdentifierErr := BACnetContextTagParse(readBuffer, uint8(uint8(0)), BACnetDataType(BACnetDataType_BACNET_OBJECT_IDENTIFIER))
	if _objectIdentifierErr != nil {
		return nil, errors.Wrap(_objectIdentifierErr, "Error parsing 'objectIdentifier' field")
	}
	objectIdentifier := CastBACnetContextTagObjectIdentifier(_objectIdentifier)
	if closeErr := readBuffer.CloseContext("objectIdentifier"); closeErr != nil {
		return nil, closeErr
	}

	// Simple Field (propertyIdentifier)
	if pullErr := readBuffer.PullContext("propertyIdentifier"); pullErr != nil {
		return nil, pullErr
	}
	_propertyIdentifier, _propertyIdentifierErr := BACnetPropertyIdentifierTaggedParse(readBuffer, uint8(uint8(1)), TagClass(TagClass_CONTEXT_SPECIFIC_TAGS))
	if _propertyIdentifierErr != nil {
		return nil, errors.Wrap(_propertyIdentifierErr, "Error parsing 'propertyIdentifier' field")
	}
	propertyIdentifier := CastBACnetPropertyIdentifierTagged(_propertyIdentifier)
	if closeErr := readBuffer.CloseContext("propertyIdentifier"); closeErr != nil {
		return nil, closeErr
	}

	// Optional Field (arrayIndex) (Can be skipped, if a given expression evaluates to false)
	var arrayIndex *BACnetContextTagUnsignedInteger = nil
	{
		currentPos = positionAware.GetPos()
		if pullErr := readBuffer.PullContext("arrayIndex"); pullErr != nil {
			return nil, pullErr
		}
		_val, _err := BACnetContextTagParse(readBuffer, uint8(2), BACnetDataType_UNSIGNED_INTEGER)
		switch {
		case errors.Is(_err, utils.ParseAssertError{}) || errors.Is(_err, io.EOF):
			log.Debug().Err(_err).Msg("Resetting position because optional threw an error")
			readBuffer.Reset(currentPos)
		case _err != nil:
			return nil, errors.Wrap(_err, "Error parsing 'arrayIndex' field")
		default:
			arrayIndex = CastBACnetContextTagUnsignedInteger(_val)
			if closeErr := readBuffer.CloseContext("arrayIndex"); closeErr != nil {
				return nil, closeErr
			}
		}
	}

	// Optional Field (listOfElements) (Can be skipped, if a given expression evaluates to false)
	var listOfElements *BACnetConstructedData = nil
	{
		currentPos = positionAware.GetPos()
		if pullErr := readBuffer.PullContext("listOfElements"); pullErr != nil {
			return nil, pullErr
		}
		_val, _err := BACnetConstructedDataParse(readBuffer, uint8(3), objectIdentifier.GetObjectType(), propertyIdentifier.GetValue(), CastBACnetTagPayloadUnsignedInteger(CastBACnetTagPayloadUnsignedInteger(utils.InlineIf(bool((arrayIndex) != (nil)), func() interface{} { return CastBACnetTagPayloadUnsignedInteger((*arrayIndex).GetPayload()) }, func() interface{} { return CastBACnetTagPayloadUnsignedInteger(nil) }))))
		switch {
		case errors.Is(_err, utils.ParseAssertError{}) || errors.Is(_err, io.EOF):
			log.Debug().Err(_err).Msg("Resetting position because optional threw an error")
			readBuffer.Reset(currentPos)
		case _err != nil:
			return nil, errors.Wrap(_err, "Error parsing 'listOfElements' field")
		default:
			listOfElements = CastBACnetConstructedData(_val)
			if closeErr := readBuffer.CloseContext("listOfElements"); closeErr != nil {
				return nil, closeErr
			}
		}
	}

	if closeErr := readBuffer.CloseContext("BACnetConfirmedServiceRequestAddListElement"); closeErr != nil {
		return nil, closeErr
	}

	// Create a partially initialized instance
	_child := &BACnetConfirmedServiceRequestAddListElement{
		ObjectIdentifier:              CastBACnetContextTagObjectIdentifier(objectIdentifier),
		PropertyIdentifier:            CastBACnetPropertyIdentifierTagged(propertyIdentifier),
		ArrayIndex:                    CastBACnetContextTagUnsignedInteger(arrayIndex),
		ListOfElements:                CastBACnetConstructedData(listOfElements),
		BACnetConfirmedServiceRequest: &BACnetConfirmedServiceRequest{},
	}
	_child.BACnetConfirmedServiceRequest.Child = _child
	return _child, nil
}

func (m *BACnetConfirmedServiceRequestAddListElement) Serialize(writeBuffer utils.WriteBuffer) error {
	positionAware := writeBuffer
	_ = positionAware
	ser := func() error {
		if pushErr := writeBuffer.PushContext("BACnetConfirmedServiceRequestAddListElement"); pushErr != nil {
			return pushErr
		}

		// Simple Field (objectIdentifier)
		if pushErr := writeBuffer.PushContext("objectIdentifier"); pushErr != nil {
			return pushErr
		}
		_objectIdentifierErr := m.ObjectIdentifier.Serialize(writeBuffer)
		if popErr := writeBuffer.PopContext("objectIdentifier"); popErr != nil {
			return popErr
		}
		if _objectIdentifierErr != nil {
			return errors.Wrap(_objectIdentifierErr, "Error serializing 'objectIdentifier' field")
		}

		// Simple Field (propertyIdentifier)
		if pushErr := writeBuffer.PushContext("propertyIdentifier"); pushErr != nil {
			return pushErr
		}
		_propertyIdentifierErr := m.PropertyIdentifier.Serialize(writeBuffer)
		if popErr := writeBuffer.PopContext("propertyIdentifier"); popErr != nil {
			return popErr
		}
		if _propertyIdentifierErr != nil {
			return errors.Wrap(_propertyIdentifierErr, "Error serializing 'propertyIdentifier' field")
		}

		// Optional Field (arrayIndex) (Can be skipped, if the value is null)
		var arrayIndex *BACnetContextTagUnsignedInteger = nil
		if m.ArrayIndex != nil {
			if pushErr := writeBuffer.PushContext("arrayIndex"); pushErr != nil {
				return pushErr
			}
			arrayIndex = m.ArrayIndex
			_arrayIndexErr := arrayIndex.Serialize(writeBuffer)
			if popErr := writeBuffer.PopContext("arrayIndex"); popErr != nil {
				return popErr
			}
			if _arrayIndexErr != nil {
				return errors.Wrap(_arrayIndexErr, "Error serializing 'arrayIndex' field")
			}
		}

		// Optional Field (listOfElements) (Can be skipped, if the value is null)
		var listOfElements *BACnetConstructedData = nil
		if m.ListOfElements != nil {
			if pushErr := writeBuffer.PushContext("listOfElements"); pushErr != nil {
				return pushErr
			}
			listOfElements = m.ListOfElements
			_listOfElementsErr := listOfElements.Serialize(writeBuffer)
			if popErr := writeBuffer.PopContext("listOfElements"); popErr != nil {
				return popErr
			}
			if _listOfElementsErr != nil {
				return errors.Wrap(_listOfElementsErr, "Error serializing 'listOfElements' field")
			}
		}

		if popErr := writeBuffer.PopContext("BACnetConfirmedServiceRequestAddListElement"); popErr != nil {
			return popErr
		}
		return nil
	}
	return m.SerializeParent(writeBuffer, m, ser)
}

func (m *BACnetConfirmedServiceRequestAddListElement) String() string {
	if m == nil {
		return "<nil>"
	}
	buffer := utils.NewBoxedWriteBufferWithOptions(true, true)
	if err := m.Serialize(buffer); err != nil {
		return err.Error()
	}
	return buffer.GetBox().String()
}
