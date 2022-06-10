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

// BACnetBDTEntry is the data-structure of this message
type BACnetBDTEntry struct {
	BbmdAddress   *BACnetHostNPortEnclosed
	BroadcastMask *BACnetContextTagOctetString
}

// IBACnetBDTEntry is the corresponding interface of BACnetBDTEntry
type IBACnetBDTEntry interface {
	// GetBbmdAddress returns BbmdAddress (property field)
	GetBbmdAddress() *BACnetHostNPortEnclosed
	// GetBroadcastMask returns BroadcastMask (property field)
	GetBroadcastMask() *BACnetContextTagOctetString
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

func (m *BACnetBDTEntry) GetBbmdAddress() *BACnetHostNPortEnclosed {
	return m.BbmdAddress
}

func (m *BACnetBDTEntry) GetBroadcastMask() *BACnetContextTagOctetString {
	return m.BroadcastMask
}

///////////////////////
///////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////

// NewBACnetBDTEntry factory function for BACnetBDTEntry
func NewBACnetBDTEntry(bbmdAddress *BACnetHostNPortEnclosed, broadcastMask *BACnetContextTagOctetString) *BACnetBDTEntry {
	return &BACnetBDTEntry{BbmdAddress: bbmdAddress, BroadcastMask: broadcastMask}
}

func CastBACnetBDTEntry(structType interface{}) *BACnetBDTEntry {
	if casted, ok := structType.(BACnetBDTEntry); ok {
		return &casted
	}
	if casted, ok := structType.(*BACnetBDTEntry); ok {
		return casted
	}
	return nil
}

func (m *BACnetBDTEntry) GetTypeName() string {
	return "BACnetBDTEntry"
}

func (m *BACnetBDTEntry) GetLengthInBits() uint16 {
	return m.GetLengthInBitsConditional(false)
}

func (m *BACnetBDTEntry) GetLengthInBitsConditional(lastItem bool) uint16 {
	lengthInBits := uint16(0)

	// Simple field (bbmdAddress)
	lengthInBits += m.BbmdAddress.GetLengthInBits()

	// Optional Field (broadcastMask)
	if m.BroadcastMask != nil {
		lengthInBits += (*m.BroadcastMask).GetLengthInBits()
	}

	return lengthInBits
}

func (m *BACnetBDTEntry) GetLengthInBytes() uint16 {
	return m.GetLengthInBits() / 8
}

func BACnetBDTEntryParse(readBuffer utils.ReadBuffer) (*BACnetBDTEntry, error) {
	positionAware := readBuffer
	_ = positionAware
	if pullErr := readBuffer.PullContext("BACnetBDTEntry"); pullErr != nil {
		return nil, pullErr
	}
	currentPos := positionAware.GetPos()
	_ = currentPos

	// Simple Field (bbmdAddress)
	if pullErr := readBuffer.PullContext("bbmdAddress"); pullErr != nil {
		return nil, pullErr
	}
	_bbmdAddress, _bbmdAddressErr := BACnetHostNPortEnclosedParse(readBuffer, uint8(uint8(0)))
	if _bbmdAddressErr != nil {
		return nil, errors.Wrap(_bbmdAddressErr, "Error parsing 'bbmdAddress' field")
	}
	bbmdAddress := CastBACnetHostNPortEnclosed(_bbmdAddress)
	if closeErr := readBuffer.CloseContext("bbmdAddress"); closeErr != nil {
		return nil, closeErr
	}

	// Optional Field (broadcastMask) (Can be skipped, if a given expression evaluates to false)
	var broadcastMask *BACnetContextTagOctetString = nil
	{
		currentPos = positionAware.GetPos()
		if pullErr := readBuffer.PullContext("broadcastMask"); pullErr != nil {
			return nil, pullErr
		}
		_val, _err := BACnetContextTagParse(readBuffer, uint8(1), BACnetDataType_OCTET_STRING)
		switch {
		case errors.Is(_err, utils.ParseAssertError{}) || errors.Is(_err, io.EOF):
			log.Debug().Err(_err).Msg("Resetting position because optional threw an error")
			readBuffer.Reset(currentPos)
		case _err != nil:
			return nil, errors.Wrap(_err, "Error parsing 'broadcastMask' field")
		default:
			broadcastMask = CastBACnetContextTagOctetString(_val)
			if closeErr := readBuffer.CloseContext("broadcastMask"); closeErr != nil {
				return nil, closeErr
			}
		}
	}

	if closeErr := readBuffer.CloseContext("BACnetBDTEntry"); closeErr != nil {
		return nil, closeErr
	}

	// Create the instance
	return NewBACnetBDTEntry(bbmdAddress, broadcastMask), nil
}

func (m *BACnetBDTEntry) Serialize(writeBuffer utils.WriteBuffer) error {
	positionAware := writeBuffer
	_ = positionAware
	if pushErr := writeBuffer.PushContext("BACnetBDTEntry"); pushErr != nil {
		return pushErr
	}

	// Simple Field (bbmdAddress)
	if pushErr := writeBuffer.PushContext("bbmdAddress"); pushErr != nil {
		return pushErr
	}
	_bbmdAddressErr := m.BbmdAddress.Serialize(writeBuffer)
	if popErr := writeBuffer.PopContext("bbmdAddress"); popErr != nil {
		return popErr
	}
	if _bbmdAddressErr != nil {
		return errors.Wrap(_bbmdAddressErr, "Error serializing 'bbmdAddress' field")
	}

	// Optional Field (broadcastMask) (Can be skipped, if the value is null)
	var broadcastMask *BACnetContextTagOctetString = nil
	if m.BroadcastMask != nil {
		if pushErr := writeBuffer.PushContext("broadcastMask"); pushErr != nil {
			return pushErr
		}
		broadcastMask = m.BroadcastMask
		_broadcastMaskErr := broadcastMask.Serialize(writeBuffer)
		if popErr := writeBuffer.PopContext("broadcastMask"); popErr != nil {
			return popErr
		}
		if _broadcastMaskErr != nil {
			return errors.Wrap(_broadcastMaskErr, "Error serializing 'broadcastMask' field")
		}
	}

	if popErr := writeBuffer.PopContext("BACnetBDTEntry"); popErr != nil {
		return popErr
	}
	return nil
}

func (m *BACnetBDTEntry) String() string {
	if m == nil {
		return "<nil>"
	}
	buffer := utils.NewBoxedWriteBufferWithOptions(true, true)
	if err := m.Serialize(buffer); err != nil {
		return err.Error()
	}
	return buffer.GetBox().String()
}
