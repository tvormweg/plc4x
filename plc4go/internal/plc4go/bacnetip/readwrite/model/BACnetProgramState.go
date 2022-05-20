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
	"github.com/apache/plc4x/plc4go/internal/plc4go/spi/utils"
	"github.com/pkg/errors"
)

// Code generated by code-generation. DO NOT EDIT.

// BACnetProgramState is an enum
type BACnetProgramState uint8

type IBACnetProgramState interface {
	Serialize(writeBuffer utils.WriteBuffer) error
}

const (
	BACnetProgramState_IDLE      BACnetProgramState = 0
	BACnetProgramState_LOADING   BACnetProgramState = 1
	BACnetProgramState_RUNNING   BACnetProgramState = 2
	BACnetProgramState_WAITING   BACnetProgramState = 3
	BACnetProgramState_HALTED    BACnetProgramState = 4
	BACnetProgramState_UNLOADING BACnetProgramState = 5
)

var BACnetProgramStateValues []BACnetProgramState

func init() {
	_ = errors.New
	BACnetProgramStateValues = []BACnetProgramState{
		BACnetProgramState_IDLE,
		BACnetProgramState_LOADING,
		BACnetProgramState_RUNNING,
		BACnetProgramState_WAITING,
		BACnetProgramState_HALTED,
		BACnetProgramState_UNLOADING,
	}
}

func BACnetProgramStateByValue(value uint8) BACnetProgramState {
	switch value {
	case 0:
		return BACnetProgramState_IDLE
	case 1:
		return BACnetProgramState_LOADING
	case 2:
		return BACnetProgramState_RUNNING
	case 3:
		return BACnetProgramState_WAITING
	case 4:
		return BACnetProgramState_HALTED
	case 5:
		return BACnetProgramState_UNLOADING
	}
	return 0
}

func BACnetProgramStateByName(value string) BACnetProgramState {
	switch value {
	case "IDLE":
		return BACnetProgramState_IDLE
	case "LOADING":
		return BACnetProgramState_LOADING
	case "RUNNING":
		return BACnetProgramState_RUNNING
	case "WAITING":
		return BACnetProgramState_WAITING
	case "HALTED":
		return BACnetProgramState_HALTED
	case "UNLOADING":
		return BACnetProgramState_UNLOADING
	}
	return 0
}

func BACnetProgramStateKnows(value uint8) bool {
	for _, typeValue := range BACnetProgramStateValues {
		if uint8(typeValue) == value {
			return true
		}
	}
	return false
}

func CastBACnetProgramState(structType interface{}) BACnetProgramState {
	castFunc := func(typ interface{}) BACnetProgramState {
		if sBACnetProgramState, ok := typ.(BACnetProgramState); ok {
			return sBACnetProgramState
		}
		return 0
	}
	return castFunc(structType)
}

func (m BACnetProgramState) GetLengthInBits() uint16 {
	return 8
}

func (m BACnetProgramState) GetLengthInBytes() uint16 {
	return m.GetLengthInBits() / 8
}

func BACnetProgramStateParse(readBuffer utils.ReadBuffer) (BACnetProgramState, error) {
	val, err := readBuffer.ReadUint8("BACnetProgramState", 8)
	if err != nil {
		return 0, nil
	}
	return BACnetProgramStateByValue(val), nil
}

func (e BACnetProgramState) Serialize(writeBuffer utils.WriteBuffer) error {
	return writeBuffer.WriteUint8("BACnetProgramState", 8, uint8(e), utils.WithAdditionalStringRepresentation(e.name()))
}

func (e BACnetProgramState) name() string {
	switch e {
	case BACnetProgramState_IDLE:
		return "IDLE"
	case BACnetProgramState_LOADING:
		return "LOADING"
	case BACnetProgramState_RUNNING:
		return "RUNNING"
	case BACnetProgramState_WAITING:
		return "WAITING"
	case BACnetProgramState_HALTED:
		return "HALTED"
	case BACnetProgramState_UNLOADING:
		return "UNLOADING"
	}
	return ""
}

func (e BACnetProgramState) String() string {
	return e.name()
}