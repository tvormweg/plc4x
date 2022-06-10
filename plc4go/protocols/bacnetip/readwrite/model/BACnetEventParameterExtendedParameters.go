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

// BACnetEventParameterExtendedParameters is the data-structure of this message
type BACnetEventParameterExtendedParameters struct {
	OpeningTag           *BACnetOpeningTag
	PeekedTagHeader      *BACnetTagHeader
	NullValue            *BACnetApplicationTagNull
	RealValue            *BACnetApplicationTagReal
	UnsignedValue        *BACnetApplicationTagUnsignedInteger
	BooleanValue         *BACnetApplicationTagBoolean
	IntegerValue         *BACnetApplicationTagSignedInteger
	DoubleValue          *BACnetApplicationTagDouble
	OctetStringValue     *BACnetApplicationTagOctetString
	CharacterStringValue *BACnetApplicationTagCharacterString
	BitStringValue       *BACnetApplicationTagBitString
	EnumeratedValue      *BACnetApplicationTagEnumerated
	DateValue            *BACnetApplicationTagDate
	TimeValue            *BACnetApplicationTagTime
	ObjectIdentifier     *BACnetApplicationTagObjectIdentifier
	Reference            *BACnetDeviceObjectPropertyReferenceEnclosed
	ClosingTag           *BACnetClosingTag

	// Arguments.
	TagNumber uint8
}

// IBACnetEventParameterExtendedParameters is the corresponding interface of BACnetEventParameterExtendedParameters
type IBACnetEventParameterExtendedParameters interface {
	// GetOpeningTag returns OpeningTag (property field)
	GetOpeningTag() *BACnetOpeningTag
	// GetPeekedTagHeader returns PeekedTagHeader (property field)
	GetPeekedTagHeader() *BACnetTagHeader
	// GetNullValue returns NullValue (property field)
	GetNullValue() *BACnetApplicationTagNull
	// GetRealValue returns RealValue (property field)
	GetRealValue() *BACnetApplicationTagReal
	// GetUnsignedValue returns UnsignedValue (property field)
	GetUnsignedValue() *BACnetApplicationTagUnsignedInteger
	// GetBooleanValue returns BooleanValue (property field)
	GetBooleanValue() *BACnetApplicationTagBoolean
	// GetIntegerValue returns IntegerValue (property field)
	GetIntegerValue() *BACnetApplicationTagSignedInteger
	// GetDoubleValue returns DoubleValue (property field)
	GetDoubleValue() *BACnetApplicationTagDouble
	// GetOctetStringValue returns OctetStringValue (property field)
	GetOctetStringValue() *BACnetApplicationTagOctetString
	// GetCharacterStringValue returns CharacterStringValue (property field)
	GetCharacterStringValue() *BACnetApplicationTagCharacterString
	// GetBitStringValue returns BitStringValue (property field)
	GetBitStringValue() *BACnetApplicationTagBitString
	// GetEnumeratedValue returns EnumeratedValue (property field)
	GetEnumeratedValue() *BACnetApplicationTagEnumerated
	// GetDateValue returns DateValue (property field)
	GetDateValue() *BACnetApplicationTagDate
	// GetTimeValue returns TimeValue (property field)
	GetTimeValue() *BACnetApplicationTagTime
	// GetObjectIdentifier returns ObjectIdentifier (property field)
	GetObjectIdentifier() *BACnetApplicationTagObjectIdentifier
	// GetReference returns Reference (property field)
	GetReference() *BACnetDeviceObjectPropertyReferenceEnclosed
	// GetClosingTag returns ClosingTag (property field)
	GetClosingTag() *BACnetClosingTag
	// GetPeekedTagNumber returns PeekedTagNumber (virtual field)
	GetPeekedTagNumber() uint8
	// GetIsOpeningTag returns IsOpeningTag (virtual field)
	GetIsOpeningTag() bool
	// GetIsClosingTag returns IsClosingTag (virtual field)
	GetIsClosingTag() bool
	// GetLengthInBytes returns the length in bytes
	GetLengthInBytes() uint16
	// GetLengthInBits returns the length in bits
	GetLengthInBits() uint16
	// Serialize serializes this type
	Serialize(writeBuffer utils.WriteBuffer) error
}

///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
/////////////////////// Accessors for property fields.
///////////////////////

func (m *BACnetEventParameterExtendedParameters) GetOpeningTag() *BACnetOpeningTag {
	return m.OpeningTag
}

func (m *BACnetEventParameterExtendedParameters) GetPeekedTagHeader() *BACnetTagHeader {
	return m.PeekedTagHeader
}

func (m *BACnetEventParameterExtendedParameters) GetNullValue() *BACnetApplicationTagNull {
	return m.NullValue
}

func (m *BACnetEventParameterExtendedParameters) GetRealValue() *BACnetApplicationTagReal {
	return m.RealValue
}

func (m *BACnetEventParameterExtendedParameters) GetUnsignedValue() *BACnetApplicationTagUnsignedInteger {
	return m.UnsignedValue
}

func (m *BACnetEventParameterExtendedParameters) GetBooleanValue() *BACnetApplicationTagBoolean {
	return m.BooleanValue
}

func (m *BACnetEventParameterExtendedParameters) GetIntegerValue() *BACnetApplicationTagSignedInteger {
	return m.IntegerValue
}

func (m *BACnetEventParameterExtendedParameters) GetDoubleValue() *BACnetApplicationTagDouble {
	return m.DoubleValue
}

func (m *BACnetEventParameterExtendedParameters) GetOctetStringValue() *BACnetApplicationTagOctetString {
	return m.OctetStringValue
}

func (m *BACnetEventParameterExtendedParameters) GetCharacterStringValue() *BACnetApplicationTagCharacterString {
	return m.CharacterStringValue
}

func (m *BACnetEventParameterExtendedParameters) GetBitStringValue() *BACnetApplicationTagBitString {
	return m.BitStringValue
}

func (m *BACnetEventParameterExtendedParameters) GetEnumeratedValue() *BACnetApplicationTagEnumerated {
	return m.EnumeratedValue
}

func (m *BACnetEventParameterExtendedParameters) GetDateValue() *BACnetApplicationTagDate {
	return m.DateValue
}

func (m *BACnetEventParameterExtendedParameters) GetTimeValue() *BACnetApplicationTagTime {
	return m.TimeValue
}

func (m *BACnetEventParameterExtendedParameters) GetObjectIdentifier() *BACnetApplicationTagObjectIdentifier {
	return m.ObjectIdentifier
}

func (m *BACnetEventParameterExtendedParameters) GetReference() *BACnetDeviceObjectPropertyReferenceEnclosed {
	return m.Reference
}

func (m *BACnetEventParameterExtendedParameters) GetClosingTag() *BACnetClosingTag {
	return m.ClosingTag
}

///////////////////////
///////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
/////////////////////// Accessors for virtual fields.
///////////////////////

func (m *BACnetEventParameterExtendedParameters) GetPeekedTagNumber() uint8 {
	nullValue := m.NullValue
	_ = nullValue
	realValue := m.RealValue
	_ = realValue
	unsignedValue := m.UnsignedValue
	_ = unsignedValue
	booleanValue := m.BooleanValue
	_ = booleanValue
	integerValue := m.IntegerValue
	_ = integerValue
	doubleValue := m.DoubleValue
	_ = doubleValue
	octetStringValue := m.OctetStringValue
	_ = octetStringValue
	characterStringValue := m.CharacterStringValue
	_ = characterStringValue
	bitStringValue := m.BitStringValue
	_ = bitStringValue
	enumeratedValue := m.EnumeratedValue
	_ = enumeratedValue
	dateValue := m.DateValue
	_ = dateValue
	timeValue := m.TimeValue
	_ = timeValue
	objectIdentifier := m.ObjectIdentifier
	_ = objectIdentifier
	reference := m.Reference
	_ = reference
	return uint8(m.GetPeekedTagHeader().GetActualTagNumber())
}

func (m *BACnetEventParameterExtendedParameters) GetIsOpeningTag() bool {
	nullValue := m.NullValue
	_ = nullValue
	realValue := m.RealValue
	_ = realValue
	unsignedValue := m.UnsignedValue
	_ = unsignedValue
	booleanValue := m.BooleanValue
	_ = booleanValue
	integerValue := m.IntegerValue
	_ = integerValue
	doubleValue := m.DoubleValue
	_ = doubleValue
	octetStringValue := m.OctetStringValue
	_ = octetStringValue
	characterStringValue := m.CharacterStringValue
	_ = characterStringValue
	bitStringValue := m.BitStringValue
	_ = bitStringValue
	enumeratedValue := m.EnumeratedValue
	_ = enumeratedValue
	dateValue := m.DateValue
	_ = dateValue
	timeValue := m.TimeValue
	_ = timeValue
	objectIdentifier := m.ObjectIdentifier
	_ = objectIdentifier
	reference := m.Reference
	_ = reference
	return bool(bool((m.GetPeekedTagHeader().GetLengthValueType()) == (0x6)))
}

func (m *BACnetEventParameterExtendedParameters) GetIsClosingTag() bool {
	nullValue := m.NullValue
	_ = nullValue
	realValue := m.RealValue
	_ = realValue
	unsignedValue := m.UnsignedValue
	_ = unsignedValue
	booleanValue := m.BooleanValue
	_ = booleanValue
	integerValue := m.IntegerValue
	_ = integerValue
	doubleValue := m.DoubleValue
	_ = doubleValue
	octetStringValue := m.OctetStringValue
	_ = octetStringValue
	characterStringValue := m.CharacterStringValue
	_ = characterStringValue
	bitStringValue := m.BitStringValue
	_ = bitStringValue
	enumeratedValue := m.EnumeratedValue
	_ = enumeratedValue
	dateValue := m.DateValue
	_ = dateValue
	timeValue := m.TimeValue
	_ = timeValue
	objectIdentifier := m.ObjectIdentifier
	_ = objectIdentifier
	reference := m.Reference
	_ = reference
	return bool(bool((m.GetPeekedTagHeader().GetLengthValueType()) == (0x7)))
}

///////////////////////
///////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////

// NewBACnetEventParameterExtendedParameters factory function for BACnetEventParameterExtendedParameters
func NewBACnetEventParameterExtendedParameters(openingTag *BACnetOpeningTag, peekedTagHeader *BACnetTagHeader, nullValue *BACnetApplicationTagNull, realValue *BACnetApplicationTagReal, unsignedValue *BACnetApplicationTagUnsignedInteger, booleanValue *BACnetApplicationTagBoolean, integerValue *BACnetApplicationTagSignedInteger, doubleValue *BACnetApplicationTagDouble, octetStringValue *BACnetApplicationTagOctetString, characterStringValue *BACnetApplicationTagCharacterString, bitStringValue *BACnetApplicationTagBitString, enumeratedValue *BACnetApplicationTagEnumerated, dateValue *BACnetApplicationTagDate, timeValue *BACnetApplicationTagTime, objectIdentifier *BACnetApplicationTagObjectIdentifier, reference *BACnetDeviceObjectPropertyReferenceEnclosed, closingTag *BACnetClosingTag, tagNumber uint8) *BACnetEventParameterExtendedParameters {
	return &BACnetEventParameterExtendedParameters{OpeningTag: openingTag, PeekedTagHeader: peekedTagHeader, NullValue: nullValue, RealValue: realValue, UnsignedValue: unsignedValue, BooleanValue: booleanValue, IntegerValue: integerValue, DoubleValue: doubleValue, OctetStringValue: octetStringValue, CharacterStringValue: characterStringValue, BitStringValue: bitStringValue, EnumeratedValue: enumeratedValue, DateValue: dateValue, TimeValue: timeValue, ObjectIdentifier: objectIdentifier, Reference: reference, ClosingTag: closingTag, TagNumber: tagNumber}
}

func CastBACnetEventParameterExtendedParameters(structType interface{}) *BACnetEventParameterExtendedParameters {
	if casted, ok := structType.(BACnetEventParameterExtendedParameters); ok {
		return &casted
	}
	if casted, ok := structType.(*BACnetEventParameterExtendedParameters); ok {
		return casted
	}
	return nil
}

func (m *BACnetEventParameterExtendedParameters) GetTypeName() string {
	return "BACnetEventParameterExtendedParameters"
}

func (m *BACnetEventParameterExtendedParameters) GetLengthInBits() uint16 {
	return m.GetLengthInBitsConditional(false)
}

func (m *BACnetEventParameterExtendedParameters) GetLengthInBitsConditional(lastItem bool) uint16 {
	lengthInBits := uint16(0)

	// Simple field (openingTag)
	lengthInBits += m.OpeningTag.GetLengthInBits()

	// A virtual field doesn't have any in- or output.

	// A virtual field doesn't have any in- or output.

	// A virtual field doesn't have any in- or output.

	// Optional Field (nullValue)
	if m.NullValue != nil {
		lengthInBits += (*m.NullValue).GetLengthInBits()
	}

	// Optional Field (realValue)
	if m.RealValue != nil {
		lengthInBits += (*m.RealValue).GetLengthInBits()
	}

	// Optional Field (unsignedValue)
	if m.UnsignedValue != nil {
		lengthInBits += (*m.UnsignedValue).GetLengthInBits()
	}

	// Optional Field (booleanValue)
	if m.BooleanValue != nil {
		lengthInBits += (*m.BooleanValue).GetLengthInBits()
	}

	// Optional Field (integerValue)
	if m.IntegerValue != nil {
		lengthInBits += (*m.IntegerValue).GetLengthInBits()
	}

	// Optional Field (doubleValue)
	if m.DoubleValue != nil {
		lengthInBits += (*m.DoubleValue).GetLengthInBits()
	}

	// Optional Field (octetStringValue)
	if m.OctetStringValue != nil {
		lengthInBits += (*m.OctetStringValue).GetLengthInBits()
	}

	// Optional Field (characterStringValue)
	if m.CharacterStringValue != nil {
		lengthInBits += (*m.CharacterStringValue).GetLengthInBits()
	}

	// Optional Field (bitStringValue)
	if m.BitStringValue != nil {
		lengthInBits += (*m.BitStringValue).GetLengthInBits()
	}

	// Optional Field (enumeratedValue)
	if m.EnumeratedValue != nil {
		lengthInBits += (*m.EnumeratedValue).GetLengthInBits()
	}

	// Optional Field (dateValue)
	if m.DateValue != nil {
		lengthInBits += (*m.DateValue).GetLengthInBits()
	}

	// Optional Field (timeValue)
	if m.TimeValue != nil {
		lengthInBits += (*m.TimeValue).GetLengthInBits()
	}

	// Optional Field (objectIdentifier)
	if m.ObjectIdentifier != nil {
		lengthInBits += (*m.ObjectIdentifier).GetLengthInBits()
	}

	// Optional Field (reference)
	if m.Reference != nil {
		lengthInBits += (*m.Reference).GetLengthInBits()
	}

	// Simple field (closingTag)
	lengthInBits += m.ClosingTag.GetLengthInBits()

	return lengthInBits
}

func (m *BACnetEventParameterExtendedParameters) GetLengthInBytes() uint16 {
	return m.GetLengthInBits() / 8
}

func BACnetEventParameterExtendedParametersParse(readBuffer utils.ReadBuffer, tagNumber uint8) (*BACnetEventParameterExtendedParameters, error) {
	positionAware := readBuffer
	_ = positionAware
	if pullErr := readBuffer.PullContext("BACnetEventParameterExtendedParameters"); pullErr != nil {
		return nil, pullErr
	}
	currentPos := positionAware.GetPos()
	_ = currentPos

	// Simple Field (openingTag)
	if pullErr := readBuffer.PullContext("openingTag"); pullErr != nil {
		return nil, pullErr
	}
	_openingTag, _openingTagErr := BACnetOpeningTagParse(readBuffer, uint8(tagNumber))
	if _openingTagErr != nil {
		return nil, errors.Wrap(_openingTagErr, "Error parsing 'openingTag' field")
	}
	openingTag := CastBACnetOpeningTag(_openingTag)
	if closeErr := readBuffer.CloseContext("openingTag"); closeErr != nil {
		return nil, closeErr
	}

	// Peek Field (peekedTagHeader)
	currentPos = positionAware.GetPos()
	if pullErr := readBuffer.PullContext("peekedTagHeader"); pullErr != nil {
		return nil, pullErr
	}
	peekedTagHeader, _ := BACnetTagHeaderParse(readBuffer)
	readBuffer.Reset(currentPos)

	// Virtual field
	_peekedTagNumber := peekedTagHeader.GetActualTagNumber()
	peekedTagNumber := uint8(_peekedTagNumber)
	_ = peekedTagNumber

	// Virtual field
	_isOpeningTag := bool((peekedTagHeader.GetLengthValueType()) == (0x6))
	isOpeningTag := bool(_isOpeningTag)
	_ = isOpeningTag

	// Virtual field
	_isClosingTag := bool((peekedTagHeader.GetLengthValueType()) == (0x7))
	isClosingTag := bool(_isClosingTag)
	_ = isClosingTag

	// Optional Field (nullValue) (Can be skipped, if a given expression evaluates to false)
	var nullValue *BACnetApplicationTagNull = nil
	if bool(bool(bool((peekedTagNumber) == (0x0))) && bool(!(isOpeningTag))) && bool(!(isClosingTag)) {
		currentPos = positionAware.GetPos()
		if pullErr := readBuffer.PullContext("nullValue"); pullErr != nil {
			return nil, pullErr
		}
		_val, _err := BACnetApplicationTagParse(readBuffer)
		switch {
		case errors.Is(_err, utils.ParseAssertError{}) || errors.Is(_err, io.EOF):
			log.Debug().Err(_err).Msg("Resetting position because optional threw an error")
			readBuffer.Reset(currentPos)
		case _err != nil:
			return nil, errors.Wrap(_err, "Error parsing 'nullValue' field")
		default:
			nullValue = CastBACnetApplicationTagNull(_val)
			if closeErr := readBuffer.CloseContext("nullValue"); closeErr != nil {
				return nil, closeErr
			}
		}
	}

	// Optional Field (realValue) (Can be skipped, if a given expression evaluates to false)
	var realValue *BACnetApplicationTagReal = nil
	if bool(bool(bool((peekedTagNumber) == (0x4))) && bool(!(isOpeningTag))) && bool(!(isClosingTag)) {
		currentPos = positionAware.GetPos()
		if pullErr := readBuffer.PullContext("realValue"); pullErr != nil {
			return nil, pullErr
		}
		_val, _err := BACnetApplicationTagParse(readBuffer)
		switch {
		case errors.Is(_err, utils.ParseAssertError{}) || errors.Is(_err, io.EOF):
			log.Debug().Err(_err).Msg("Resetting position because optional threw an error")
			readBuffer.Reset(currentPos)
		case _err != nil:
			return nil, errors.Wrap(_err, "Error parsing 'realValue' field")
		default:
			realValue = CastBACnetApplicationTagReal(_val)
			if closeErr := readBuffer.CloseContext("realValue"); closeErr != nil {
				return nil, closeErr
			}
		}
	}

	// Optional Field (unsignedValue) (Can be skipped, if a given expression evaluates to false)
	var unsignedValue *BACnetApplicationTagUnsignedInteger = nil
	if bool(bool(bool((peekedTagNumber) == (0x2))) && bool(!(isOpeningTag))) && bool(!(isClosingTag)) {
		currentPos = positionAware.GetPos()
		if pullErr := readBuffer.PullContext("unsignedValue"); pullErr != nil {
			return nil, pullErr
		}
		_val, _err := BACnetApplicationTagParse(readBuffer)
		switch {
		case errors.Is(_err, utils.ParseAssertError{}) || errors.Is(_err, io.EOF):
			log.Debug().Err(_err).Msg("Resetting position because optional threw an error")
			readBuffer.Reset(currentPos)
		case _err != nil:
			return nil, errors.Wrap(_err, "Error parsing 'unsignedValue' field")
		default:
			unsignedValue = CastBACnetApplicationTagUnsignedInteger(_val)
			if closeErr := readBuffer.CloseContext("unsignedValue"); closeErr != nil {
				return nil, closeErr
			}
		}
	}

	// Optional Field (booleanValue) (Can be skipped, if a given expression evaluates to false)
	var booleanValue *BACnetApplicationTagBoolean = nil
	if bool(bool(bool((peekedTagNumber) == (0x1))) && bool(!(isOpeningTag))) && bool(!(isClosingTag)) {
		currentPos = positionAware.GetPos()
		if pullErr := readBuffer.PullContext("booleanValue"); pullErr != nil {
			return nil, pullErr
		}
		_val, _err := BACnetApplicationTagParse(readBuffer)
		switch {
		case errors.Is(_err, utils.ParseAssertError{}) || errors.Is(_err, io.EOF):
			log.Debug().Err(_err).Msg("Resetting position because optional threw an error")
			readBuffer.Reset(currentPos)
		case _err != nil:
			return nil, errors.Wrap(_err, "Error parsing 'booleanValue' field")
		default:
			booleanValue = CastBACnetApplicationTagBoolean(_val)
			if closeErr := readBuffer.CloseContext("booleanValue"); closeErr != nil {
				return nil, closeErr
			}
		}
	}

	// Optional Field (integerValue) (Can be skipped, if a given expression evaluates to false)
	var integerValue *BACnetApplicationTagSignedInteger = nil
	if bool(bool(bool((peekedTagNumber) == (0x3))) && bool(!(isOpeningTag))) && bool(!(isClosingTag)) {
		currentPos = positionAware.GetPos()
		if pullErr := readBuffer.PullContext("integerValue"); pullErr != nil {
			return nil, pullErr
		}
		_val, _err := BACnetApplicationTagParse(readBuffer)
		switch {
		case errors.Is(_err, utils.ParseAssertError{}) || errors.Is(_err, io.EOF):
			log.Debug().Err(_err).Msg("Resetting position because optional threw an error")
			readBuffer.Reset(currentPos)
		case _err != nil:
			return nil, errors.Wrap(_err, "Error parsing 'integerValue' field")
		default:
			integerValue = CastBACnetApplicationTagSignedInteger(_val)
			if closeErr := readBuffer.CloseContext("integerValue"); closeErr != nil {
				return nil, closeErr
			}
		}
	}

	// Optional Field (doubleValue) (Can be skipped, if a given expression evaluates to false)
	var doubleValue *BACnetApplicationTagDouble = nil
	if bool(bool(bool((peekedTagNumber) == (0x5))) && bool(!(isOpeningTag))) && bool(!(isClosingTag)) {
		currentPos = positionAware.GetPos()
		if pullErr := readBuffer.PullContext("doubleValue"); pullErr != nil {
			return nil, pullErr
		}
		_val, _err := BACnetApplicationTagParse(readBuffer)
		switch {
		case errors.Is(_err, utils.ParseAssertError{}) || errors.Is(_err, io.EOF):
			log.Debug().Err(_err).Msg("Resetting position because optional threw an error")
			readBuffer.Reset(currentPos)
		case _err != nil:
			return nil, errors.Wrap(_err, "Error parsing 'doubleValue' field")
		default:
			doubleValue = CastBACnetApplicationTagDouble(_val)
			if closeErr := readBuffer.CloseContext("doubleValue"); closeErr != nil {
				return nil, closeErr
			}
		}
	}

	// Optional Field (octetStringValue) (Can be skipped, if a given expression evaluates to false)
	var octetStringValue *BACnetApplicationTagOctetString = nil
	if bool(bool(bool((peekedTagNumber) == (0x6))) && bool(!(isOpeningTag))) && bool(!(isClosingTag)) {
		currentPos = positionAware.GetPos()
		if pullErr := readBuffer.PullContext("octetStringValue"); pullErr != nil {
			return nil, pullErr
		}
		_val, _err := BACnetApplicationTagParse(readBuffer)
		switch {
		case errors.Is(_err, utils.ParseAssertError{}) || errors.Is(_err, io.EOF):
			log.Debug().Err(_err).Msg("Resetting position because optional threw an error")
			readBuffer.Reset(currentPos)
		case _err != nil:
			return nil, errors.Wrap(_err, "Error parsing 'octetStringValue' field")
		default:
			octetStringValue = CastBACnetApplicationTagOctetString(_val)
			if closeErr := readBuffer.CloseContext("octetStringValue"); closeErr != nil {
				return nil, closeErr
			}
		}
	}

	// Optional Field (characterStringValue) (Can be skipped, if a given expression evaluates to false)
	var characterStringValue *BACnetApplicationTagCharacterString = nil
	if bool(bool(bool((peekedTagNumber) == (0x7))) && bool(!(isOpeningTag))) && bool(!(isClosingTag)) {
		currentPos = positionAware.GetPos()
		if pullErr := readBuffer.PullContext("characterStringValue"); pullErr != nil {
			return nil, pullErr
		}
		_val, _err := BACnetApplicationTagParse(readBuffer)
		switch {
		case errors.Is(_err, utils.ParseAssertError{}) || errors.Is(_err, io.EOF):
			log.Debug().Err(_err).Msg("Resetting position because optional threw an error")
			readBuffer.Reset(currentPos)
		case _err != nil:
			return nil, errors.Wrap(_err, "Error parsing 'characterStringValue' field")
		default:
			characterStringValue = CastBACnetApplicationTagCharacterString(_val)
			if closeErr := readBuffer.CloseContext("characterStringValue"); closeErr != nil {
				return nil, closeErr
			}
		}
	}

	// Optional Field (bitStringValue) (Can be skipped, if a given expression evaluates to false)
	var bitStringValue *BACnetApplicationTagBitString = nil
	if bool(bool(bool((peekedTagNumber) == (0x8))) && bool(!(isOpeningTag))) && bool(!(isClosingTag)) {
		currentPos = positionAware.GetPos()
		if pullErr := readBuffer.PullContext("bitStringValue"); pullErr != nil {
			return nil, pullErr
		}
		_val, _err := BACnetApplicationTagParse(readBuffer)
		switch {
		case errors.Is(_err, utils.ParseAssertError{}) || errors.Is(_err, io.EOF):
			log.Debug().Err(_err).Msg("Resetting position because optional threw an error")
			readBuffer.Reset(currentPos)
		case _err != nil:
			return nil, errors.Wrap(_err, "Error parsing 'bitStringValue' field")
		default:
			bitStringValue = CastBACnetApplicationTagBitString(_val)
			if closeErr := readBuffer.CloseContext("bitStringValue"); closeErr != nil {
				return nil, closeErr
			}
		}
	}

	// Optional Field (enumeratedValue) (Can be skipped, if a given expression evaluates to false)
	var enumeratedValue *BACnetApplicationTagEnumerated = nil
	if bool(bool(bool((peekedTagNumber) == (0x9))) && bool(!(isOpeningTag))) && bool(!(isClosingTag)) {
		currentPos = positionAware.GetPos()
		if pullErr := readBuffer.PullContext("enumeratedValue"); pullErr != nil {
			return nil, pullErr
		}
		_val, _err := BACnetApplicationTagParse(readBuffer)
		switch {
		case errors.Is(_err, utils.ParseAssertError{}) || errors.Is(_err, io.EOF):
			log.Debug().Err(_err).Msg("Resetting position because optional threw an error")
			readBuffer.Reset(currentPos)
		case _err != nil:
			return nil, errors.Wrap(_err, "Error parsing 'enumeratedValue' field")
		default:
			enumeratedValue = CastBACnetApplicationTagEnumerated(_val)
			if closeErr := readBuffer.CloseContext("enumeratedValue"); closeErr != nil {
				return nil, closeErr
			}
		}
	}

	// Optional Field (dateValue) (Can be skipped, if a given expression evaluates to false)
	var dateValue *BACnetApplicationTagDate = nil
	if bool(bool(bool((peekedTagNumber) == (0xA))) && bool(!(isOpeningTag))) && bool(!(isClosingTag)) {
		currentPos = positionAware.GetPos()
		if pullErr := readBuffer.PullContext("dateValue"); pullErr != nil {
			return nil, pullErr
		}
		_val, _err := BACnetApplicationTagParse(readBuffer)
		switch {
		case errors.Is(_err, utils.ParseAssertError{}) || errors.Is(_err, io.EOF):
			log.Debug().Err(_err).Msg("Resetting position because optional threw an error")
			readBuffer.Reset(currentPos)
		case _err != nil:
			return nil, errors.Wrap(_err, "Error parsing 'dateValue' field")
		default:
			dateValue = CastBACnetApplicationTagDate(_val)
			if closeErr := readBuffer.CloseContext("dateValue"); closeErr != nil {
				return nil, closeErr
			}
		}
	}

	// Optional Field (timeValue) (Can be skipped, if a given expression evaluates to false)
	var timeValue *BACnetApplicationTagTime = nil
	if bool(bool(bool((peekedTagNumber) == (0xB))) && bool(!(isOpeningTag))) && bool(!(isClosingTag)) {
		currentPos = positionAware.GetPos()
		if pullErr := readBuffer.PullContext("timeValue"); pullErr != nil {
			return nil, pullErr
		}
		_val, _err := BACnetApplicationTagParse(readBuffer)
		switch {
		case errors.Is(_err, utils.ParseAssertError{}) || errors.Is(_err, io.EOF):
			log.Debug().Err(_err).Msg("Resetting position because optional threw an error")
			readBuffer.Reset(currentPos)
		case _err != nil:
			return nil, errors.Wrap(_err, "Error parsing 'timeValue' field")
		default:
			timeValue = CastBACnetApplicationTagTime(_val)
			if closeErr := readBuffer.CloseContext("timeValue"); closeErr != nil {
				return nil, closeErr
			}
		}
	}

	// Optional Field (objectIdentifier) (Can be skipped, if a given expression evaluates to false)
	var objectIdentifier *BACnetApplicationTagObjectIdentifier = nil
	if bool(bool((peekedTagNumber) == (0xC))) && bool(!(isOpeningTag)) {
		currentPos = positionAware.GetPos()
		if pullErr := readBuffer.PullContext("objectIdentifier"); pullErr != nil {
			return nil, pullErr
		}
		_val, _err := BACnetApplicationTagParse(readBuffer)
		switch {
		case errors.Is(_err, utils.ParseAssertError{}) || errors.Is(_err, io.EOF):
			log.Debug().Err(_err).Msg("Resetting position because optional threw an error")
			readBuffer.Reset(currentPos)
		case _err != nil:
			return nil, errors.Wrap(_err, "Error parsing 'objectIdentifier' field")
		default:
			objectIdentifier = CastBACnetApplicationTagObjectIdentifier(_val)
			if closeErr := readBuffer.CloseContext("objectIdentifier"); closeErr != nil {
				return nil, closeErr
			}
		}
	}

	// Optional Field (reference) (Can be skipped, if a given expression evaluates to false)
	var reference *BACnetDeviceObjectPropertyReferenceEnclosed = nil
	if bool(isOpeningTag) && bool(!(isClosingTag)) {
		currentPos = positionAware.GetPos()
		if pullErr := readBuffer.PullContext("reference"); pullErr != nil {
			return nil, pullErr
		}
		_val, _err := BACnetDeviceObjectPropertyReferenceEnclosedParse(readBuffer, uint8(0))
		switch {
		case errors.Is(_err, utils.ParseAssertError{}) || errors.Is(_err, io.EOF):
			log.Debug().Err(_err).Msg("Resetting position because optional threw an error")
			readBuffer.Reset(currentPos)
		case _err != nil:
			return nil, errors.Wrap(_err, "Error parsing 'reference' field")
		default:
			reference = CastBACnetDeviceObjectPropertyReferenceEnclosed(_val)
			if closeErr := readBuffer.CloseContext("reference"); closeErr != nil {
				return nil, closeErr
			}
		}
	}

	// Simple Field (closingTag)
	if pullErr := readBuffer.PullContext("closingTag"); pullErr != nil {
		return nil, pullErr
	}
	_closingTag, _closingTagErr := BACnetClosingTagParse(readBuffer, uint8(tagNumber))
	if _closingTagErr != nil {
		return nil, errors.Wrap(_closingTagErr, "Error parsing 'closingTag' field")
	}
	closingTag := CastBACnetClosingTag(_closingTag)
	if closeErr := readBuffer.CloseContext("closingTag"); closeErr != nil {
		return nil, closeErr
	}

	if closeErr := readBuffer.CloseContext("BACnetEventParameterExtendedParameters"); closeErr != nil {
		return nil, closeErr
	}

	// Create the instance
	return NewBACnetEventParameterExtendedParameters(openingTag, peekedTagHeader, nullValue, realValue, unsignedValue, booleanValue, integerValue, doubleValue, octetStringValue, characterStringValue, bitStringValue, enumeratedValue, dateValue, timeValue, objectIdentifier, reference, closingTag, tagNumber), nil
}

func (m *BACnetEventParameterExtendedParameters) Serialize(writeBuffer utils.WriteBuffer) error {
	positionAware := writeBuffer
	_ = positionAware
	if pushErr := writeBuffer.PushContext("BACnetEventParameterExtendedParameters"); pushErr != nil {
		return pushErr
	}

	// Simple Field (openingTag)
	if pushErr := writeBuffer.PushContext("openingTag"); pushErr != nil {
		return pushErr
	}
	_openingTagErr := m.OpeningTag.Serialize(writeBuffer)
	if popErr := writeBuffer.PopContext("openingTag"); popErr != nil {
		return popErr
	}
	if _openingTagErr != nil {
		return errors.Wrap(_openingTagErr, "Error serializing 'openingTag' field")
	}
	// Virtual field
	if _peekedTagNumberErr := writeBuffer.WriteVirtual("peekedTagNumber", m.GetPeekedTagNumber()); _peekedTagNumberErr != nil {
		return errors.Wrap(_peekedTagNumberErr, "Error serializing 'peekedTagNumber' field")
	}
	// Virtual field
	if _isOpeningTagErr := writeBuffer.WriteVirtual("isOpeningTag", m.GetIsOpeningTag()); _isOpeningTagErr != nil {
		return errors.Wrap(_isOpeningTagErr, "Error serializing 'isOpeningTag' field")
	}
	// Virtual field
	if _isClosingTagErr := writeBuffer.WriteVirtual("isClosingTag", m.GetIsClosingTag()); _isClosingTagErr != nil {
		return errors.Wrap(_isClosingTagErr, "Error serializing 'isClosingTag' field")
	}

	// Optional Field (nullValue) (Can be skipped, if the value is null)
	var nullValue *BACnetApplicationTagNull = nil
	if m.NullValue != nil {
		if pushErr := writeBuffer.PushContext("nullValue"); pushErr != nil {
			return pushErr
		}
		nullValue = m.NullValue
		_nullValueErr := nullValue.Serialize(writeBuffer)
		if popErr := writeBuffer.PopContext("nullValue"); popErr != nil {
			return popErr
		}
		if _nullValueErr != nil {
			return errors.Wrap(_nullValueErr, "Error serializing 'nullValue' field")
		}
	}

	// Optional Field (realValue) (Can be skipped, if the value is null)
	var realValue *BACnetApplicationTagReal = nil
	if m.RealValue != nil {
		if pushErr := writeBuffer.PushContext("realValue"); pushErr != nil {
			return pushErr
		}
		realValue = m.RealValue
		_realValueErr := realValue.Serialize(writeBuffer)
		if popErr := writeBuffer.PopContext("realValue"); popErr != nil {
			return popErr
		}
		if _realValueErr != nil {
			return errors.Wrap(_realValueErr, "Error serializing 'realValue' field")
		}
	}

	// Optional Field (unsignedValue) (Can be skipped, if the value is null)
	var unsignedValue *BACnetApplicationTagUnsignedInteger = nil
	if m.UnsignedValue != nil {
		if pushErr := writeBuffer.PushContext("unsignedValue"); pushErr != nil {
			return pushErr
		}
		unsignedValue = m.UnsignedValue
		_unsignedValueErr := unsignedValue.Serialize(writeBuffer)
		if popErr := writeBuffer.PopContext("unsignedValue"); popErr != nil {
			return popErr
		}
		if _unsignedValueErr != nil {
			return errors.Wrap(_unsignedValueErr, "Error serializing 'unsignedValue' field")
		}
	}

	// Optional Field (booleanValue) (Can be skipped, if the value is null)
	var booleanValue *BACnetApplicationTagBoolean = nil
	if m.BooleanValue != nil {
		if pushErr := writeBuffer.PushContext("booleanValue"); pushErr != nil {
			return pushErr
		}
		booleanValue = m.BooleanValue
		_booleanValueErr := booleanValue.Serialize(writeBuffer)
		if popErr := writeBuffer.PopContext("booleanValue"); popErr != nil {
			return popErr
		}
		if _booleanValueErr != nil {
			return errors.Wrap(_booleanValueErr, "Error serializing 'booleanValue' field")
		}
	}

	// Optional Field (integerValue) (Can be skipped, if the value is null)
	var integerValue *BACnetApplicationTagSignedInteger = nil
	if m.IntegerValue != nil {
		if pushErr := writeBuffer.PushContext("integerValue"); pushErr != nil {
			return pushErr
		}
		integerValue = m.IntegerValue
		_integerValueErr := integerValue.Serialize(writeBuffer)
		if popErr := writeBuffer.PopContext("integerValue"); popErr != nil {
			return popErr
		}
		if _integerValueErr != nil {
			return errors.Wrap(_integerValueErr, "Error serializing 'integerValue' field")
		}
	}

	// Optional Field (doubleValue) (Can be skipped, if the value is null)
	var doubleValue *BACnetApplicationTagDouble = nil
	if m.DoubleValue != nil {
		if pushErr := writeBuffer.PushContext("doubleValue"); pushErr != nil {
			return pushErr
		}
		doubleValue = m.DoubleValue
		_doubleValueErr := doubleValue.Serialize(writeBuffer)
		if popErr := writeBuffer.PopContext("doubleValue"); popErr != nil {
			return popErr
		}
		if _doubleValueErr != nil {
			return errors.Wrap(_doubleValueErr, "Error serializing 'doubleValue' field")
		}
	}

	// Optional Field (octetStringValue) (Can be skipped, if the value is null)
	var octetStringValue *BACnetApplicationTagOctetString = nil
	if m.OctetStringValue != nil {
		if pushErr := writeBuffer.PushContext("octetStringValue"); pushErr != nil {
			return pushErr
		}
		octetStringValue = m.OctetStringValue
		_octetStringValueErr := octetStringValue.Serialize(writeBuffer)
		if popErr := writeBuffer.PopContext("octetStringValue"); popErr != nil {
			return popErr
		}
		if _octetStringValueErr != nil {
			return errors.Wrap(_octetStringValueErr, "Error serializing 'octetStringValue' field")
		}
	}

	// Optional Field (characterStringValue) (Can be skipped, if the value is null)
	var characterStringValue *BACnetApplicationTagCharacterString = nil
	if m.CharacterStringValue != nil {
		if pushErr := writeBuffer.PushContext("characterStringValue"); pushErr != nil {
			return pushErr
		}
		characterStringValue = m.CharacterStringValue
		_characterStringValueErr := characterStringValue.Serialize(writeBuffer)
		if popErr := writeBuffer.PopContext("characterStringValue"); popErr != nil {
			return popErr
		}
		if _characterStringValueErr != nil {
			return errors.Wrap(_characterStringValueErr, "Error serializing 'characterStringValue' field")
		}
	}

	// Optional Field (bitStringValue) (Can be skipped, if the value is null)
	var bitStringValue *BACnetApplicationTagBitString = nil
	if m.BitStringValue != nil {
		if pushErr := writeBuffer.PushContext("bitStringValue"); pushErr != nil {
			return pushErr
		}
		bitStringValue = m.BitStringValue
		_bitStringValueErr := bitStringValue.Serialize(writeBuffer)
		if popErr := writeBuffer.PopContext("bitStringValue"); popErr != nil {
			return popErr
		}
		if _bitStringValueErr != nil {
			return errors.Wrap(_bitStringValueErr, "Error serializing 'bitStringValue' field")
		}
	}

	// Optional Field (enumeratedValue) (Can be skipped, if the value is null)
	var enumeratedValue *BACnetApplicationTagEnumerated = nil
	if m.EnumeratedValue != nil {
		if pushErr := writeBuffer.PushContext("enumeratedValue"); pushErr != nil {
			return pushErr
		}
		enumeratedValue = m.EnumeratedValue
		_enumeratedValueErr := enumeratedValue.Serialize(writeBuffer)
		if popErr := writeBuffer.PopContext("enumeratedValue"); popErr != nil {
			return popErr
		}
		if _enumeratedValueErr != nil {
			return errors.Wrap(_enumeratedValueErr, "Error serializing 'enumeratedValue' field")
		}
	}

	// Optional Field (dateValue) (Can be skipped, if the value is null)
	var dateValue *BACnetApplicationTagDate = nil
	if m.DateValue != nil {
		if pushErr := writeBuffer.PushContext("dateValue"); pushErr != nil {
			return pushErr
		}
		dateValue = m.DateValue
		_dateValueErr := dateValue.Serialize(writeBuffer)
		if popErr := writeBuffer.PopContext("dateValue"); popErr != nil {
			return popErr
		}
		if _dateValueErr != nil {
			return errors.Wrap(_dateValueErr, "Error serializing 'dateValue' field")
		}
	}

	// Optional Field (timeValue) (Can be skipped, if the value is null)
	var timeValue *BACnetApplicationTagTime = nil
	if m.TimeValue != nil {
		if pushErr := writeBuffer.PushContext("timeValue"); pushErr != nil {
			return pushErr
		}
		timeValue = m.TimeValue
		_timeValueErr := timeValue.Serialize(writeBuffer)
		if popErr := writeBuffer.PopContext("timeValue"); popErr != nil {
			return popErr
		}
		if _timeValueErr != nil {
			return errors.Wrap(_timeValueErr, "Error serializing 'timeValue' field")
		}
	}

	// Optional Field (objectIdentifier) (Can be skipped, if the value is null)
	var objectIdentifier *BACnetApplicationTagObjectIdentifier = nil
	if m.ObjectIdentifier != nil {
		if pushErr := writeBuffer.PushContext("objectIdentifier"); pushErr != nil {
			return pushErr
		}
		objectIdentifier = m.ObjectIdentifier
		_objectIdentifierErr := objectIdentifier.Serialize(writeBuffer)
		if popErr := writeBuffer.PopContext("objectIdentifier"); popErr != nil {
			return popErr
		}
		if _objectIdentifierErr != nil {
			return errors.Wrap(_objectIdentifierErr, "Error serializing 'objectIdentifier' field")
		}
	}

	// Optional Field (reference) (Can be skipped, if the value is null)
	var reference *BACnetDeviceObjectPropertyReferenceEnclosed = nil
	if m.Reference != nil {
		if pushErr := writeBuffer.PushContext("reference"); pushErr != nil {
			return pushErr
		}
		reference = m.Reference
		_referenceErr := reference.Serialize(writeBuffer)
		if popErr := writeBuffer.PopContext("reference"); popErr != nil {
			return popErr
		}
		if _referenceErr != nil {
			return errors.Wrap(_referenceErr, "Error serializing 'reference' field")
		}
	}

	// Simple Field (closingTag)
	if pushErr := writeBuffer.PushContext("closingTag"); pushErr != nil {
		return pushErr
	}
	_closingTagErr := m.ClosingTag.Serialize(writeBuffer)
	if popErr := writeBuffer.PopContext("closingTag"); popErr != nil {
		return popErr
	}
	if _closingTagErr != nil {
		return errors.Wrap(_closingTagErr, "Error serializing 'closingTag' field")
	}

	if popErr := writeBuffer.PopContext("BACnetEventParameterExtendedParameters"); popErr != nil {
		return popErr
	}
	return nil
}

func (m *BACnetEventParameterExtendedParameters) String() string {
	if m == nil {
		return "<nil>"
	}
	buffer := utils.NewBoxedWriteBufferWithOptions(true, true)
	if err := m.Serialize(buffer); err != nil {
		return err.Error()
	}
	return buffer.GetBox().String()
}
