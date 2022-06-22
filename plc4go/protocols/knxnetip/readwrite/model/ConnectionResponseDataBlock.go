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

// ConnectionResponseDataBlock is the corresponding interface of ConnectionResponseDataBlock
type ConnectionResponseDataBlock interface {
	utils.LengthAware
	utils.Serializable
	// GetConnectionType returns ConnectionType (discriminator field)
	GetConnectionType() uint8
}

// ConnectionResponseDataBlockExactly can be used when we want exactly this type and not a type which fulfills ConnectionResponseDataBlock.
// This is useful for switch cases.
type ConnectionResponseDataBlockExactly interface {
	ConnectionResponseDataBlock
	isConnectionResponseDataBlock() bool
}

// _ConnectionResponseDataBlock is the data-structure of this message
type _ConnectionResponseDataBlock struct {
	_ConnectionResponseDataBlockChildRequirements
}

type _ConnectionResponseDataBlockChildRequirements interface {
	utils.Serializable
	GetLengthInBits() uint16
	GetLengthInBitsConditional(lastItem bool) uint16
	GetConnectionType() uint8
}

type ConnectionResponseDataBlockParent interface {
	SerializeParent(writeBuffer utils.WriteBuffer, child ConnectionResponseDataBlock, serializeChildFunction func() error) error
	GetTypeName() string
}

type ConnectionResponseDataBlockChild interface {
	utils.Serializable
	InitializeParent(parent ConnectionResponseDataBlock)
	GetParent() *ConnectionResponseDataBlock

	GetTypeName() string
	ConnectionResponseDataBlock
}

// NewConnectionResponseDataBlock factory function for _ConnectionResponseDataBlock
func NewConnectionResponseDataBlock() *_ConnectionResponseDataBlock {
	return &_ConnectionResponseDataBlock{}
}

// Deprecated: use the interface for direct cast
func CastConnectionResponseDataBlock(structType interface{}) ConnectionResponseDataBlock {
	if casted, ok := structType.(ConnectionResponseDataBlock); ok {
		return casted
	}
	if casted, ok := structType.(*ConnectionResponseDataBlock); ok {
		return *casted
	}
	return nil
}

func (m *_ConnectionResponseDataBlock) GetTypeName() string {
	return "ConnectionResponseDataBlock"
}

func (m *_ConnectionResponseDataBlock) GetParentLengthInBits() uint16 {
	lengthInBits := uint16(0)

	// Implicit Field (structureLength)
	lengthInBits += 8
	// Discriminator Field (connectionType)
	lengthInBits += 8

	return lengthInBits
}

func (m *_ConnectionResponseDataBlock) GetLengthInBytes() uint16 {
	return m.GetLengthInBits() / 8
}

func ConnectionResponseDataBlockParse(readBuffer utils.ReadBuffer) (ConnectionResponseDataBlock, error) {
	positionAware := readBuffer
	_ = positionAware
	if pullErr := readBuffer.PullContext("ConnectionResponseDataBlock"); pullErr != nil {
		return nil, errors.Wrap(pullErr, "Error pulling for ConnectionResponseDataBlock")
	}
	currentPos := positionAware.GetPos()
	_ = currentPos

	// Implicit Field (structureLength) (Used for parsing, but its value is not stored as it's implicitly given by the objects content)
	structureLength, _structureLengthErr := readBuffer.ReadUint8("structureLength", 8)
	_ = structureLength
	if _structureLengthErr != nil {
		return nil, errors.Wrap(_structureLengthErr, "Error parsing 'structureLength' field")
	}

	// Discriminator Field (connectionType) (Used as input to a switch field)
	connectionType, _connectionTypeErr := readBuffer.ReadUint8("connectionType", 8)
	if _connectionTypeErr != nil {
		return nil, errors.Wrap(_connectionTypeErr, "Error parsing 'connectionType' field")
	}

	// Switch Field (Depending on the discriminator values, passes the instantiation to a sub-type)
	type ConnectionResponseDataBlockChildSerializeRequirement interface {
		ConnectionResponseDataBlock
		InitializeParent(ConnectionResponseDataBlock)
		GetParent() ConnectionResponseDataBlock
	}
	var _childTemp interface{}
	var _child ConnectionResponseDataBlockChildSerializeRequirement
	var typeSwitchError error
	switch {
	case connectionType == 0x03: // ConnectionResponseDataBlockDeviceManagement
		_childTemp, typeSwitchError = ConnectionResponseDataBlockDeviceManagementParse(readBuffer)
	case connectionType == 0x04: // ConnectionResponseDataBlockTunnelConnection
		_childTemp, typeSwitchError = ConnectionResponseDataBlockTunnelConnectionParse(readBuffer)
	default:
		// TODO: return actual type
		typeSwitchError = errors.New("Unmapped type")
	}
	if typeSwitchError != nil {
		return nil, errors.Wrap(typeSwitchError, "Error parsing sub-type for type-switch.")
	}
	_child = _childTemp.(ConnectionResponseDataBlockChildSerializeRequirement)

	if closeErr := readBuffer.CloseContext("ConnectionResponseDataBlock"); closeErr != nil {
		return nil, errors.Wrap(closeErr, "Error closing for ConnectionResponseDataBlock")
	}

	// Finish initializing
	_child.InitializeParent(_child)
	return _child, nil
}

func (pm *_ConnectionResponseDataBlock) SerializeParent(writeBuffer utils.WriteBuffer, child ConnectionResponseDataBlock, serializeChildFunction func() error) error {
	// We redirect all calls through client as some methods are only implemented there
	m := child
	_ = m
	positionAware := writeBuffer
	_ = positionAware
	if pushErr := writeBuffer.PushContext("ConnectionResponseDataBlock"); pushErr != nil {
		return errors.Wrap(pushErr, "Error pushing for ConnectionResponseDataBlock")
	}

	// Implicit Field (structureLength) (Used for parsing, but it's value is not stored as it's implicitly given by the objects content)
	structureLength := uint8(uint8(m.GetLengthInBytes()))
	_structureLengthErr := writeBuffer.WriteUint8("structureLength", 8, (structureLength))
	if _structureLengthErr != nil {
		return errors.Wrap(_structureLengthErr, "Error serializing 'structureLength' field")
	}

	// Discriminator Field (connectionType) (Used as input to a switch field)
	connectionType := uint8(child.GetConnectionType())
	_connectionTypeErr := writeBuffer.WriteUint8("connectionType", 8, (connectionType))

	if _connectionTypeErr != nil {
		return errors.Wrap(_connectionTypeErr, "Error serializing 'connectionType' field")
	}

	// Switch field (Depending on the discriminator values, passes the serialization to a sub-type)
	if _typeSwitchErr := serializeChildFunction(); _typeSwitchErr != nil {
		return errors.Wrap(_typeSwitchErr, "Error serializing sub-type field")
	}

	if popErr := writeBuffer.PopContext("ConnectionResponseDataBlock"); popErr != nil {
		return errors.Wrap(popErr, "Error popping for ConnectionResponseDataBlock")
	}
	return nil
}

func (m *_ConnectionResponseDataBlock) isConnectionResponseDataBlock() bool {
	return true
}

func (m *_ConnectionResponseDataBlock) String() string {
	if m == nil {
		return "<nil>"
	}
	writeBuffer := utils.NewBoxedWriteBufferWithOptions(true, true)
	if err := writeBuffer.WriteSerializable(m); err != nil {
		return err.Error()
	}
	return writeBuffer.GetBox().String()
}
