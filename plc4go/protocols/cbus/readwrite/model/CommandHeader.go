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

// CommandHeader is the corresponding interface of CommandHeader
type CommandHeader interface {
	utils.LengthAware
	utils.Serializable
	// GetValue returns Value (property field)
	GetValue() byte
}

// CommandHeaderExactly can be used when we want exactly this type and not a type which fulfills CommandHeader.
// This is useful for switch cases.
type CommandHeaderExactly interface {
	CommandHeader
	isCommandHeader() bool
}

// _CommandHeader is the data-structure of this message
type _CommandHeader struct {
	Value byte
}

///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
/////////////////////// Accessors for property fields.
///////////////////////

func (m *_CommandHeader) GetValue() byte {
	return m.Value
}

///////////////////////
///////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////

// NewCommandHeader factory function for _CommandHeader
func NewCommandHeader(value byte) *_CommandHeader {
	return &_CommandHeader{Value: value}
}

// Deprecated: use the interface for direct cast
func CastCommandHeader(structType interface{}) CommandHeader {
	if casted, ok := structType.(CommandHeader); ok {
		return casted
	}
	if casted, ok := structType.(*CommandHeader); ok {
		return *casted
	}
	return nil
}

func (m *_CommandHeader) GetTypeName() string {
	return "CommandHeader"
}

func (m *_CommandHeader) GetLengthInBits() uint16 {
	return m.GetLengthInBitsConditional(false)
}

func (m *_CommandHeader) GetLengthInBitsConditional(lastItem bool) uint16 {
	lengthInBits := uint16(0)

	// Simple field (value)
	lengthInBits += 8

	return lengthInBits
}

func (m *_CommandHeader) GetLengthInBytes() uint16 {
	return m.GetLengthInBits() / 8
}

func CommandHeaderParse(readBuffer utils.ReadBuffer) (CommandHeader, error) {
	positionAware := readBuffer
	_ = positionAware
	if pullErr := readBuffer.PullContext("CommandHeader"); pullErr != nil {
		return nil, errors.Wrap(pullErr, "Error pulling for CommandHeader")
	}
	currentPos := positionAware.GetPos()
	_ = currentPos

	// Simple Field (value)
	_value, _valueErr := readBuffer.ReadByte("value")
	if _valueErr != nil {
		return nil, errors.Wrap(_valueErr, "Error parsing 'value' field")
	}
	value := _value

	if closeErr := readBuffer.CloseContext("CommandHeader"); closeErr != nil {
		return nil, errors.Wrap(closeErr, "Error closing for CommandHeader")
	}

	// Create the instance
	return NewCommandHeader(value), nil
}

func (m *_CommandHeader) Serialize(writeBuffer utils.WriteBuffer) error {
	positionAware := writeBuffer
	_ = positionAware
	if pushErr := writeBuffer.PushContext("CommandHeader"); pushErr != nil {
		return errors.Wrap(pushErr, "Error pushing for CommandHeader")
	}

	// Simple Field (value)
	value := byte(m.GetValue())
	_valueErr := writeBuffer.WriteByte("value", (value))
	if _valueErr != nil {
		return errors.Wrap(_valueErr, "Error serializing 'value' field")
	}

	if popErr := writeBuffer.PopContext("CommandHeader"); popErr != nil {
		return errors.Wrap(popErr, "Error popping for CommandHeader")
	}
	return nil
}

func (m *_CommandHeader) isCommandHeader() bool {
	return true
}

func (m *_CommandHeader) String() string {
	if m == nil {
		return "<nil>"
	}
	writeBuffer := utils.NewBoxedWriteBufferWithOptions(true, true)
	if err := writeBuffer.WriteSerializable(m); err != nil {
		return err.Error()
	}
	return writeBuffer.GetBox().String()
}
