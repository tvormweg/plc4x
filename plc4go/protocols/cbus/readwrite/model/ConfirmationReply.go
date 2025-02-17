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

// ConfirmationReply is the corresponding interface of ConfirmationReply
type ConfirmationReply interface {
	utils.LengthAware
	utils.Serializable
	Reply
	// GetIsA returns IsA (property field)
	GetIsA() Confirmation
}

// ConfirmationReplyExactly can be used when we want exactly this type and not a type which fulfills ConfirmationReply.
// This is useful for switch cases.
type ConfirmationReplyExactly interface {
	ConfirmationReply
	isConfirmationReply() bool
}

// _ConfirmationReply is the data-structure of this message
type _ConfirmationReply struct {
	*_Reply
	IsA Confirmation
}

///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
/////////////////////// Accessors for discriminator values.
///////////////////////

///////////////////////
///////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////

func (m *_ConfirmationReply) InitializeParent(parent Reply, magicByte byte) {
	m.MagicByte = magicByte
}

func (m *_ConfirmationReply) GetParent() Reply {
	return m._Reply
}

///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
/////////////////////// Accessors for property fields.
///////////////////////

func (m *_ConfirmationReply) GetIsA() Confirmation {
	return m.IsA
}

///////////////////////
///////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////

// NewConfirmationReply factory function for _ConfirmationReply
func NewConfirmationReply(isA Confirmation, magicByte byte) *_ConfirmationReply {
	_result := &_ConfirmationReply{
		IsA:    isA,
		_Reply: NewReply(magicByte),
	}
	_result._Reply._ReplyChildRequirements = _result
	return _result
}

// Deprecated: use the interface for direct cast
func CastConfirmationReply(structType interface{}) ConfirmationReply {
	if casted, ok := structType.(ConfirmationReply); ok {
		return casted
	}
	if casted, ok := structType.(*ConfirmationReply); ok {
		return *casted
	}
	return nil
}

func (m *_ConfirmationReply) GetTypeName() string {
	return "ConfirmationReply"
}

func (m *_ConfirmationReply) GetLengthInBits() uint16 {
	return m.GetLengthInBitsConditional(false)
}

func (m *_ConfirmationReply) GetLengthInBitsConditional(lastItem bool) uint16 {
	lengthInBits := uint16(m.GetParentLengthInBits())

	// Simple field (isA)
	lengthInBits += m.IsA.GetLengthInBits()

	return lengthInBits
}

func (m *_ConfirmationReply) GetLengthInBytes() uint16 {
	return m.GetLengthInBits() / 8
}

func ConfirmationReplyParse(readBuffer utils.ReadBuffer) (ConfirmationReply, error) {
	positionAware := readBuffer
	_ = positionAware
	if pullErr := readBuffer.PullContext("ConfirmationReply"); pullErr != nil {
		return nil, errors.Wrap(pullErr, "Error pulling for ConfirmationReply")
	}
	currentPos := positionAware.GetPos()
	_ = currentPos

	// Simple Field (isA)
	if pullErr := readBuffer.PullContext("isA"); pullErr != nil {
		return nil, errors.Wrap(pullErr, "Error pulling for isA")
	}
	_isA, _isAErr := ConfirmationParse(readBuffer)
	if _isAErr != nil {
		return nil, errors.Wrap(_isAErr, "Error parsing 'isA' field")
	}
	isA := _isA.(Confirmation)
	if closeErr := readBuffer.CloseContext("isA"); closeErr != nil {
		return nil, errors.Wrap(closeErr, "Error closing for isA")
	}

	if closeErr := readBuffer.CloseContext("ConfirmationReply"); closeErr != nil {
		return nil, errors.Wrap(closeErr, "Error closing for ConfirmationReply")
	}

	// Create a partially initialized instance
	_child := &_ConfirmationReply{
		IsA:    isA,
		_Reply: &_Reply{},
	}
	_child._Reply._ReplyChildRequirements = _child
	return _child, nil
}

func (m *_ConfirmationReply) Serialize(writeBuffer utils.WriteBuffer) error {
	positionAware := writeBuffer
	_ = positionAware
	ser := func() error {
		if pushErr := writeBuffer.PushContext("ConfirmationReply"); pushErr != nil {
			return errors.Wrap(pushErr, "Error pushing for ConfirmationReply")
		}

		// Simple Field (isA)
		if pushErr := writeBuffer.PushContext("isA"); pushErr != nil {
			return errors.Wrap(pushErr, "Error pushing for isA")
		}
		_isAErr := writeBuffer.WriteSerializable(m.GetIsA())
		if popErr := writeBuffer.PopContext("isA"); popErr != nil {
			return errors.Wrap(popErr, "Error popping for isA")
		}
		if _isAErr != nil {
			return errors.Wrap(_isAErr, "Error serializing 'isA' field")
		}

		if popErr := writeBuffer.PopContext("ConfirmationReply"); popErr != nil {
			return errors.Wrap(popErr, "Error popping for ConfirmationReply")
		}
		return nil
	}
	return m.SerializeParent(writeBuffer, m, ser)
}

func (m *_ConfirmationReply) isConfirmationReply() bool {
	return true
}

func (m *_ConfirmationReply) String() string {
	if m == nil {
		return "<nil>"
	}
	writeBuffer := utils.NewBoxedWriteBufferWithOptions(true, true)
	if err := writeBuffer.WriteSerializable(m); err != nil {
		return err.Error()
	}
	return writeBuffer.GetBox().String()
}
