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

// BACnetPropertyStatesLightningOperation is the corresponding interface of BACnetPropertyStatesLightningOperation
type BACnetPropertyStatesLightningOperation interface {
	utils.LengthAware
	utils.Serializable
	BACnetPropertyStates
	// GetLightningOperation returns LightningOperation (property field)
	GetLightningOperation() BACnetLightingOperationTagged
}

// BACnetPropertyStatesLightningOperationExactly can be used when we want exactly this type and not a type which fulfills BACnetPropertyStatesLightningOperation.
// This is useful for switch cases.
type BACnetPropertyStatesLightningOperationExactly interface {
	BACnetPropertyStatesLightningOperation
	isBACnetPropertyStatesLightningOperation() bool
}

// _BACnetPropertyStatesLightningOperation is the data-structure of this message
type _BACnetPropertyStatesLightningOperation struct {
	*_BACnetPropertyStates
	LightningOperation BACnetLightingOperationTagged
}

///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
/////////////////////// Accessors for discriminator values.
///////////////////////

///////////////////////
///////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////

func (m *_BACnetPropertyStatesLightningOperation) InitializeParent(parent BACnetPropertyStates, peekedTagHeader BACnetTagHeader) {
	m.PeekedTagHeader = peekedTagHeader
}

func (m *_BACnetPropertyStatesLightningOperation) GetParent() BACnetPropertyStates {
	return m._BACnetPropertyStates
}

///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
/////////////////////// Accessors for property fields.
///////////////////////

func (m *_BACnetPropertyStatesLightningOperation) GetLightningOperation() BACnetLightingOperationTagged {
	return m.LightningOperation
}

///////////////////////
///////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////

// NewBACnetPropertyStatesLightningOperation factory function for _BACnetPropertyStatesLightningOperation
func NewBACnetPropertyStatesLightningOperation(lightningOperation BACnetLightingOperationTagged, peekedTagHeader BACnetTagHeader) *_BACnetPropertyStatesLightningOperation {
	_result := &_BACnetPropertyStatesLightningOperation{
		LightningOperation:    lightningOperation,
		_BACnetPropertyStates: NewBACnetPropertyStates(peekedTagHeader),
	}
	_result._BACnetPropertyStates._BACnetPropertyStatesChildRequirements = _result
	return _result
}

// Deprecated: use the interface for direct cast
func CastBACnetPropertyStatesLightningOperation(structType interface{}) BACnetPropertyStatesLightningOperation {
	if casted, ok := structType.(BACnetPropertyStatesLightningOperation); ok {
		return casted
	}
	if casted, ok := structType.(*BACnetPropertyStatesLightningOperation); ok {
		return *casted
	}
	return nil
}

func (m *_BACnetPropertyStatesLightningOperation) GetTypeName() string {
	return "BACnetPropertyStatesLightningOperation"
}

func (m *_BACnetPropertyStatesLightningOperation) GetLengthInBits() uint16 {
	return m.GetLengthInBitsConditional(false)
}

func (m *_BACnetPropertyStatesLightningOperation) GetLengthInBitsConditional(lastItem bool) uint16 {
	lengthInBits := uint16(m.GetParentLengthInBits())

	// Simple field (lightningOperation)
	lengthInBits += m.LightningOperation.GetLengthInBits()

	return lengthInBits
}

func (m *_BACnetPropertyStatesLightningOperation) GetLengthInBytes() uint16 {
	return m.GetLengthInBits() / 8
}

func BACnetPropertyStatesLightningOperationParse(readBuffer utils.ReadBuffer, peekedTagNumber uint8) (BACnetPropertyStatesLightningOperation, error) {
	positionAware := readBuffer
	_ = positionAware
	if pullErr := readBuffer.PullContext("BACnetPropertyStatesLightningOperation"); pullErr != nil {
		return nil, errors.Wrap(pullErr, "Error pulling for BACnetPropertyStatesLightningOperation")
	}
	currentPos := positionAware.GetPos()
	_ = currentPos

	// Simple Field (lightningOperation)
	if pullErr := readBuffer.PullContext("lightningOperation"); pullErr != nil {
		return nil, errors.Wrap(pullErr, "Error pulling for lightningOperation")
	}
	_lightningOperation, _lightningOperationErr := BACnetLightingOperationTaggedParse(readBuffer, uint8(peekedTagNumber), TagClass(TagClass_CONTEXT_SPECIFIC_TAGS))
	if _lightningOperationErr != nil {
		return nil, errors.Wrap(_lightningOperationErr, "Error parsing 'lightningOperation' field")
	}
	lightningOperation := _lightningOperation.(BACnetLightingOperationTagged)
	if closeErr := readBuffer.CloseContext("lightningOperation"); closeErr != nil {
		return nil, errors.Wrap(closeErr, "Error closing for lightningOperation")
	}

	if closeErr := readBuffer.CloseContext("BACnetPropertyStatesLightningOperation"); closeErr != nil {
		return nil, errors.Wrap(closeErr, "Error closing for BACnetPropertyStatesLightningOperation")
	}

	// Create a partially initialized instance
	_child := &_BACnetPropertyStatesLightningOperation{
		LightningOperation:    lightningOperation,
		_BACnetPropertyStates: &_BACnetPropertyStates{},
	}
	_child._BACnetPropertyStates._BACnetPropertyStatesChildRequirements = _child
	return _child, nil
}

func (m *_BACnetPropertyStatesLightningOperation) Serialize(writeBuffer utils.WriteBuffer) error {
	positionAware := writeBuffer
	_ = positionAware
	ser := func() error {
		if pushErr := writeBuffer.PushContext("BACnetPropertyStatesLightningOperation"); pushErr != nil {
			return errors.Wrap(pushErr, "Error pushing for BACnetPropertyStatesLightningOperation")
		}

		// Simple Field (lightningOperation)
		if pushErr := writeBuffer.PushContext("lightningOperation"); pushErr != nil {
			return errors.Wrap(pushErr, "Error pushing for lightningOperation")
		}
		_lightningOperationErr := writeBuffer.WriteSerializable(m.GetLightningOperation())
		if popErr := writeBuffer.PopContext("lightningOperation"); popErr != nil {
			return errors.Wrap(popErr, "Error popping for lightningOperation")
		}
		if _lightningOperationErr != nil {
			return errors.Wrap(_lightningOperationErr, "Error serializing 'lightningOperation' field")
		}

		if popErr := writeBuffer.PopContext("BACnetPropertyStatesLightningOperation"); popErr != nil {
			return errors.Wrap(popErr, "Error popping for BACnetPropertyStatesLightningOperation")
		}
		return nil
	}
	return m.SerializeParent(writeBuffer, m, ser)
}

func (m *_BACnetPropertyStatesLightningOperation) isBACnetPropertyStatesLightningOperation() bool {
	return true
}

func (m *_BACnetPropertyStatesLightningOperation) String() string {
	if m == nil {
		return "<nil>"
	}
	writeBuffer := utils.NewBoxedWriteBufferWithOptions(true, true)
	if err := writeBuffer.WriteSerializable(m); err != nil {
		return err.Error()
	}
	return writeBuffer.GetBox().String()
}
