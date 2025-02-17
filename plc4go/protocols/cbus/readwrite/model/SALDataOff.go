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

// SALDataOff is the corresponding interface of SALDataOff
type SALDataOff interface {
	utils.LengthAware
	utils.Serializable
	SALData
	// GetGroup returns Group (property field)
	GetGroup() byte
}

// SALDataOffExactly can be used when we want exactly this type and not a type which fulfills SALDataOff.
// This is useful for switch cases.
type SALDataOffExactly interface {
	SALDataOff
	isSALDataOff() bool
}

// _SALDataOff is the data-structure of this message
type _SALDataOff struct {
	*_SALData
	Group byte
}

///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
/////////////////////// Accessors for discriminator values.
///////////////////////

///////////////////////
///////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////

func (m *_SALDataOff) InitializeParent(parent SALData, commandTypeContainer SALCommandTypeContainer) {
	m.CommandTypeContainer = commandTypeContainer
}

func (m *_SALDataOff) GetParent() SALData {
	return m._SALData
}

///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
/////////////////////// Accessors for property fields.
///////////////////////

func (m *_SALDataOff) GetGroup() byte {
	return m.Group
}

///////////////////////
///////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////

// NewSALDataOff factory function for _SALDataOff
func NewSALDataOff(group byte, commandTypeContainer SALCommandTypeContainer) *_SALDataOff {
	_result := &_SALDataOff{
		Group:    group,
		_SALData: NewSALData(commandTypeContainer),
	}
	_result._SALData._SALDataChildRequirements = _result
	return _result
}

// Deprecated: use the interface for direct cast
func CastSALDataOff(structType interface{}) SALDataOff {
	if casted, ok := structType.(SALDataOff); ok {
		return casted
	}
	if casted, ok := structType.(*SALDataOff); ok {
		return *casted
	}
	return nil
}

func (m *_SALDataOff) GetTypeName() string {
	return "SALDataOff"
}

func (m *_SALDataOff) GetLengthInBits() uint16 {
	return m.GetLengthInBitsConditional(false)
}

func (m *_SALDataOff) GetLengthInBitsConditional(lastItem bool) uint16 {
	lengthInBits := uint16(m.GetParentLengthInBits())

	// Simple field (group)
	lengthInBits += 8

	return lengthInBits
}

func (m *_SALDataOff) GetLengthInBytes() uint16 {
	return m.GetLengthInBits() / 8
}

func SALDataOffParse(readBuffer utils.ReadBuffer) (SALDataOff, error) {
	positionAware := readBuffer
	_ = positionAware
	if pullErr := readBuffer.PullContext("SALDataOff"); pullErr != nil {
		return nil, errors.Wrap(pullErr, "Error pulling for SALDataOff")
	}
	currentPos := positionAware.GetPos()
	_ = currentPos

	// Simple Field (group)
	_group, _groupErr := readBuffer.ReadByte("group")
	if _groupErr != nil {
		return nil, errors.Wrap(_groupErr, "Error parsing 'group' field")
	}
	group := _group

	if closeErr := readBuffer.CloseContext("SALDataOff"); closeErr != nil {
		return nil, errors.Wrap(closeErr, "Error closing for SALDataOff")
	}

	// Create a partially initialized instance
	_child := &_SALDataOff{
		Group:    group,
		_SALData: &_SALData{},
	}
	_child._SALData._SALDataChildRequirements = _child
	return _child, nil
}

func (m *_SALDataOff) Serialize(writeBuffer utils.WriteBuffer) error {
	positionAware := writeBuffer
	_ = positionAware
	ser := func() error {
		if pushErr := writeBuffer.PushContext("SALDataOff"); pushErr != nil {
			return errors.Wrap(pushErr, "Error pushing for SALDataOff")
		}

		// Simple Field (group)
		group := byte(m.GetGroup())
		_groupErr := writeBuffer.WriteByte("group", (group))
		if _groupErr != nil {
			return errors.Wrap(_groupErr, "Error serializing 'group' field")
		}

		if popErr := writeBuffer.PopContext("SALDataOff"); popErr != nil {
			return errors.Wrap(popErr, "Error popping for SALDataOff")
		}
		return nil
	}
	return m.SerializeParent(writeBuffer, m, ser)
}

func (m *_SALDataOff) isSALDataOff() bool {
	return true
}

func (m *_SALDataOff) String() string {
	if m == nil {
		return "<nil>"
	}
	writeBuffer := utils.NewBoxedWriteBufferWithOptions(true, true)
	if err := writeBuffer.WriteSerializable(m); err != nil {
		return err.Error()
	}
	return writeBuffer.GetBox().String()
}
