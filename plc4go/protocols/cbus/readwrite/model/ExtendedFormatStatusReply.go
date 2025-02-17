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
	"fmt"
	"github.com/apache/plc4x/plc4go/internal/spi/utils"
	"github.com/pkg/errors"
)

// Code generated by code-generation. DO NOT EDIT.

// Constant values.
const ExtendedFormatStatusReply_CR byte = 0x0D
const ExtendedFormatStatusReply_LF byte = 0x0A

// ExtendedFormatStatusReply is the corresponding interface of ExtendedFormatStatusReply
type ExtendedFormatStatusReply interface {
	utils.LengthAware
	utils.Serializable
	// GetStatusHeader returns StatusHeader (property field)
	GetStatusHeader() ExtendedStatusHeader
	// GetCoding returns Coding (property field)
	GetCoding() StatusCoding
	// GetApplication returns Application (property field)
	GetApplication() ApplicationIdContainer
	// GetBlockStart returns BlockStart (property field)
	GetBlockStart() uint8
	// GetStatusBytes returns StatusBytes (property field)
	GetStatusBytes() []StatusByte
	// GetCrc returns Crc (property field)
	GetCrc() Checksum
}

// ExtendedFormatStatusReplyExactly can be used when we want exactly this type and not a type which fulfills ExtendedFormatStatusReply.
// This is useful for switch cases.
type ExtendedFormatStatusReplyExactly interface {
	ExtendedFormatStatusReply
	isExtendedFormatStatusReply() bool
}

// _ExtendedFormatStatusReply is the data-structure of this message
type _ExtendedFormatStatusReply struct {
	StatusHeader ExtendedStatusHeader
	Coding       StatusCoding
	Application  ApplicationIdContainer
	BlockStart   uint8
	StatusBytes  []StatusByte
	Crc          Checksum
}

///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
/////////////////////// Accessors for property fields.
///////////////////////

func (m *_ExtendedFormatStatusReply) GetStatusHeader() ExtendedStatusHeader {
	return m.StatusHeader
}

func (m *_ExtendedFormatStatusReply) GetCoding() StatusCoding {
	return m.Coding
}

func (m *_ExtendedFormatStatusReply) GetApplication() ApplicationIdContainer {
	return m.Application
}

func (m *_ExtendedFormatStatusReply) GetBlockStart() uint8 {
	return m.BlockStart
}

func (m *_ExtendedFormatStatusReply) GetStatusBytes() []StatusByte {
	return m.StatusBytes
}

func (m *_ExtendedFormatStatusReply) GetCrc() Checksum {
	return m.Crc
}

///////////////////////
///////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
/////////////////////// Accessors for const fields.
///////////////////////

func (m *_ExtendedFormatStatusReply) GetCr() byte {
	return ExtendedFormatStatusReply_CR
}

func (m *_ExtendedFormatStatusReply) GetLf() byte {
	return ExtendedFormatStatusReply_LF
}

///////////////////////
///////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////

// NewExtendedFormatStatusReply factory function for _ExtendedFormatStatusReply
func NewExtendedFormatStatusReply(statusHeader ExtendedStatusHeader, coding StatusCoding, application ApplicationIdContainer, blockStart uint8, statusBytes []StatusByte, crc Checksum) *_ExtendedFormatStatusReply {
	return &_ExtendedFormatStatusReply{StatusHeader: statusHeader, Coding: coding, Application: application, BlockStart: blockStart, StatusBytes: statusBytes, Crc: crc}
}

// Deprecated: use the interface for direct cast
func CastExtendedFormatStatusReply(structType interface{}) ExtendedFormatStatusReply {
	if casted, ok := structType.(ExtendedFormatStatusReply); ok {
		return casted
	}
	if casted, ok := structType.(*ExtendedFormatStatusReply); ok {
		return *casted
	}
	return nil
}

func (m *_ExtendedFormatStatusReply) GetTypeName() string {
	return "ExtendedFormatStatusReply"
}

func (m *_ExtendedFormatStatusReply) GetLengthInBits() uint16 {
	return m.GetLengthInBitsConditional(false)
}

func (m *_ExtendedFormatStatusReply) GetLengthInBitsConditional(lastItem bool) uint16 {
	lengthInBits := uint16(0)

	// Simple field (statusHeader)
	lengthInBits += m.StatusHeader.GetLengthInBits()

	// Simple field (coding)
	lengthInBits += 8

	// Simple field (application)
	lengthInBits += 8

	// Simple field (blockStart)
	lengthInBits += 8

	// Array field
	if len(m.StatusBytes) > 0 {
		for i, element := range m.StatusBytes {
			last := i == len(m.StatusBytes)-1
			lengthInBits += element.(interface{ GetLengthInBitsConditional(bool) uint16 }).GetLengthInBitsConditional(last)
		}
	}

	// Simple field (crc)
	lengthInBits += m.Crc.GetLengthInBits()

	// Const Field (cr)
	lengthInBits += 8

	// Const Field (lf)
	lengthInBits += 8

	return lengthInBits
}

func (m *_ExtendedFormatStatusReply) GetLengthInBytes() uint16 {
	return m.GetLengthInBits() / 8
}

func ExtendedFormatStatusReplyParse(readBuffer utils.ReadBuffer) (ExtendedFormatStatusReply, error) {
	positionAware := readBuffer
	_ = positionAware
	if pullErr := readBuffer.PullContext("ExtendedFormatStatusReply"); pullErr != nil {
		return nil, errors.Wrap(pullErr, "Error pulling for ExtendedFormatStatusReply")
	}
	currentPos := positionAware.GetPos()
	_ = currentPos

	// Simple Field (statusHeader)
	if pullErr := readBuffer.PullContext("statusHeader"); pullErr != nil {
		return nil, errors.Wrap(pullErr, "Error pulling for statusHeader")
	}
	_statusHeader, _statusHeaderErr := ExtendedStatusHeaderParse(readBuffer)
	if _statusHeaderErr != nil {
		return nil, errors.Wrap(_statusHeaderErr, "Error parsing 'statusHeader' field")
	}
	statusHeader := _statusHeader.(ExtendedStatusHeader)
	if closeErr := readBuffer.CloseContext("statusHeader"); closeErr != nil {
		return nil, errors.Wrap(closeErr, "Error closing for statusHeader")
	}

	// Simple Field (coding)
	if pullErr := readBuffer.PullContext("coding"); pullErr != nil {
		return nil, errors.Wrap(pullErr, "Error pulling for coding")
	}
	_coding, _codingErr := StatusCodingParse(readBuffer)
	if _codingErr != nil {
		return nil, errors.Wrap(_codingErr, "Error parsing 'coding' field")
	}
	coding := _coding
	if closeErr := readBuffer.CloseContext("coding"); closeErr != nil {
		return nil, errors.Wrap(closeErr, "Error closing for coding")
	}

	// Simple Field (application)
	if pullErr := readBuffer.PullContext("application"); pullErr != nil {
		return nil, errors.Wrap(pullErr, "Error pulling for application")
	}
	_application, _applicationErr := ApplicationIdContainerParse(readBuffer)
	if _applicationErr != nil {
		return nil, errors.Wrap(_applicationErr, "Error parsing 'application' field")
	}
	application := _application
	if closeErr := readBuffer.CloseContext("application"); closeErr != nil {
		return nil, errors.Wrap(closeErr, "Error closing for application")
	}

	// Simple Field (blockStart)
	_blockStart, _blockStartErr := readBuffer.ReadUint8("blockStart", 8)
	if _blockStartErr != nil {
		return nil, errors.Wrap(_blockStartErr, "Error parsing 'blockStart' field")
	}
	blockStart := _blockStart

	// Array field (statusBytes)
	if pullErr := readBuffer.PullContext("statusBytes", utils.WithRenderAsList(true)); pullErr != nil {
		return nil, errors.Wrap(pullErr, "Error pulling for statusBytes")
	}
	// Count array
	statusBytes := make([]StatusByte, uint16(statusHeader.GetNumberOfCharacterPairs())-uint16(uint16(3)))
	// This happens when the size is set conditional to 0
	if len(statusBytes) == 0 {
		statusBytes = nil
	}
	{
		for curItem := uint16(0); curItem < uint16(uint16(statusHeader.GetNumberOfCharacterPairs())-uint16(uint16(3))); curItem++ {
			_item, _err := StatusByteParse(readBuffer)
			if _err != nil {
				return nil, errors.Wrap(_err, "Error parsing 'statusBytes' field")
			}
			statusBytes[curItem] = _item.(StatusByte)
		}
	}
	if closeErr := readBuffer.CloseContext("statusBytes", utils.WithRenderAsList(true)); closeErr != nil {
		return nil, errors.Wrap(closeErr, "Error closing for statusBytes")
	}

	// Simple Field (crc)
	if pullErr := readBuffer.PullContext("crc"); pullErr != nil {
		return nil, errors.Wrap(pullErr, "Error pulling for crc")
	}
	_crc, _crcErr := ChecksumParse(readBuffer)
	if _crcErr != nil {
		return nil, errors.Wrap(_crcErr, "Error parsing 'crc' field")
	}
	crc := _crc.(Checksum)
	if closeErr := readBuffer.CloseContext("crc"); closeErr != nil {
		return nil, errors.Wrap(closeErr, "Error closing for crc")
	}

	// Const Field (cr)
	cr, _crErr := readBuffer.ReadByte("cr")
	if _crErr != nil {
		return nil, errors.Wrap(_crErr, "Error parsing 'cr' field")
	}
	if cr != ExtendedFormatStatusReply_CR {
		return nil, errors.New("Expected constant value " + fmt.Sprintf("%d", ExtendedFormatStatusReply_CR) + " but got " + fmt.Sprintf("%d", cr))
	}

	// Const Field (lf)
	lf, _lfErr := readBuffer.ReadByte("lf")
	if _lfErr != nil {
		return nil, errors.Wrap(_lfErr, "Error parsing 'lf' field")
	}
	if lf != ExtendedFormatStatusReply_LF {
		return nil, errors.New("Expected constant value " + fmt.Sprintf("%d", ExtendedFormatStatusReply_LF) + " but got " + fmt.Sprintf("%d", lf))
	}

	if closeErr := readBuffer.CloseContext("ExtendedFormatStatusReply"); closeErr != nil {
		return nil, errors.Wrap(closeErr, "Error closing for ExtendedFormatStatusReply")
	}

	// Create the instance
	return NewExtendedFormatStatusReply(statusHeader, coding, application, blockStart, statusBytes, crc), nil
}

func (m *_ExtendedFormatStatusReply) Serialize(writeBuffer utils.WriteBuffer) error {
	positionAware := writeBuffer
	_ = positionAware
	if pushErr := writeBuffer.PushContext("ExtendedFormatStatusReply"); pushErr != nil {
		return errors.Wrap(pushErr, "Error pushing for ExtendedFormatStatusReply")
	}

	// Simple Field (statusHeader)
	if pushErr := writeBuffer.PushContext("statusHeader"); pushErr != nil {
		return errors.Wrap(pushErr, "Error pushing for statusHeader")
	}
	_statusHeaderErr := writeBuffer.WriteSerializable(m.GetStatusHeader())
	if popErr := writeBuffer.PopContext("statusHeader"); popErr != nil {
		return errors.Wrap(popErr, "Error popping for statusHeader")
	}
	if _statusHeaderErr != nil {
		return errors.Wrap(_statusHeaderErr, "Error serializing 'statusHeader' field")
	}

	// Simple Field (coding)
	if pushErr := writeBuffer.PushContext("coding"); pushErr != nil {
		return errors.Wrap(pushErr, "Error pushing for coding")
	}
	_codingErr := writeBuffer.WriteSerializable(m.GetCoding())
	if popErr := writeBuffer.PopContext("coding"); popErr != nil {
		return errors.Wrap(popErr, "Error popping for coding")
	}
	if _codingErr != nil {
		return errors.Wrap(_codingErr, "Error serializing 'coding' field")
	}

	// Simple Field (application)
	if pushErr := writeBuffer.PushContext("application"); pushErr != nil {
		return errors.Wrap(pushErr, "Error pushing for application")
	}
	_applicationErr := writeBuffer.WriteSerializable(m.GetApplication())
	if popErr := writeBuffer.PopContext("application"); popErr != nil {
		return errors.Wrap(popErr, "Error popping for application")
	}
	if _applicationErr != nil {
		return errors.Wrap(_applicationErr, "Error serializing 'application' field")
	}

	// Simple Field (blockStart)
	blockStart := uint8(m.GetBlockStart())
	_blockStartErr := writeBuffer.WriteUint8("blockStart", 8, (blockStart))
	if _blockStartErr != nil {
		return errors.Wrap(_blockStartErr, "Error serializing 'blockStart' field")
	}

	// Array Field (statusBytes)
	if pushErr := writeBuffer.PushContext("statusBytes", utils.WithRenderAsList(true)); pushErr != nil {
		return errors.Wrap(pushErr, "Error pushing for statusBytes")
	}
	for _, _element := range m.GetStatusBytes() {
		_elementErr := writeBuffer.WriteSerializable(_element)
		if _elementErr != nil {
			return errors.Wrap(_elementErr, "Error serializing 'statusBytes' field")
		}
	}
	if popErr := writeBuffer.PopContext("statusBytes", utils.WithRenderAsList(true)); popErr != nil {
		return errors.Wrap(popErr, "Error popping for statusBytes")
	}

	// Simple Field (crc)
	if pushErr := writeBuffer.PushContext("crc"); pushErr != nil {
		return errors.Wrap(pushErr, "Error pushing for crc")
	}
	_crcErr := writeBuffer.WriteSerializable(m.GetCrc())
	if popErr := writeBuffer.PopContext("crc"); popErr != nil {
		return errors.Wrap(popErr, "Error popping for crc")
	}
	if _crcErr != nil {
		return errors.Wrap(_crcErr, "Error serializing 'crc' field")
	}

	// Const Field (cr)
	_crErr := writeBuffer.WriteByte("cr", 0x0D)
	if _crErr != nil {
		return errors.Wrap(_crErr, "Error serializing 'cr' field")
	}

	// Const Field (lf)
	_lfErr := writeBuffer.WriteByte("lf", 0x0A)
	if _lfErr != nil {
		return errors.Wrap(_lfErr, "Error serializing 'lf' field")
	}

	if popErr := writeBuffer.PopContext("ExtendedFormatStatusReply"); popErr != nil {
		return errors.Wrap(popErr, "Error popping for ExtendedFormatStatusReply")
	}
	return nil
}

func (m *_ExtendedFormatStatusReply) isExtendedFormatStatusReply() bool {
	return true
}

func (m *_ExtendedFormatStatusReply) String() string {
	if m == nil {
		return "<nil>"
	}
	writeBuffer := utils.NewBoxedWriteBufferWithOptions(true, true)
	if err := writeBuffer.WriteSerializable(m); err != nil {
		return err.Error()
	}
	return writeBuffer.GetBox().String()
}
