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

// BACnetBackupState is an enum
type BACnetBackupState uint8

type IBACnetBackupState interface {
	Serialize(writeBuffer utils.WriteBuffer) error
}

const (
	BACnetBackupState_IDLE                  BACnetBackupState = 0
	BACnetBackupState_PREPARING_FOR_BACKUP  BACnetBackupState = 1
	BACnetBackupState_PREPARING_FOR_RESTORE BACnetBackupState = 2
	BACnetBackupState_PERFORMING_A_BACKUP   BACnetBackupState = 3
	BACnetBackupState_PERFORMING_A_RESTORE  BACnetBackupState = 4
	BACnetBackupState_BACKUP_FAILURE        BACnetBackupState = 5
	BACnetBackupState_RESTORE_FAILURE       BACnetBackupState = 6
)

var BACnetBackupStateValues []BACnetBackupState

func init() {
	_ = errors.New
	BACnetBackupStateValues = []BACnetBackupState{
		BACnetBackupState_IDLE,
		BACnetBackupState_PREPARING_FOR_BACKUP,
		BACnetBackupState_PREPARING_FOR_RESTORE,
		BACnetBackupState_PERFORMING_A_BACKUP,
		BACnetBackupState_PERFORMING_A_RESTORE,
		BACnetBackupState_BACKUP_FAILURE,
		BACnetBackupState_RESTORE_FAILURE,
	}
}

func BACnetBackupStateByValue(value uint8) BACnetBackupState {
	switch value {
	case 0:
		return BACnetBackupState_IDLE
	case 1:
		return BACnetBackupState_PREPARING_FOR_BACKUP
	case 2:
		return BACnetBackupState_PREPARING_FOR_RESTORE
	case 3:
		return BACnetBackupState_PERFORMING_A_BACKUP
	case 4:
		return BACnetBackupState_PERFORMING_A_RESTORE
	case 5:
		return BACnetBackupState_BACKUP_FAILURE
	case 6:
		return BACnetBackupState_RESTORE_FAILURE
	}
	return 0
}

func BACnetBackupStateByName(value string) BACnetBackupState {
	switch value {
	case "IDLE":
		return BACnetBackupState_IDLE
	case "PREPARING_FOR_BACKUP":
		return BACnetBackupState_PREPARING_FOR_BACKUP
	case "PREPARING_FOR_RESTORE":
		return BACnetBackupState_PREPARING_FOR_RESTORE
	case "PERFORMING_A_BACKUP":
		return BACnetBackupState_PERFORMING_A_BACKUP
	case "PERFORMING_A_RESTORE":
		return BACnetBackupState_PERFORMING_A_RESTORE
	case "BACKUP_FAILURE":
		return BACnetBackupState_BACKUP_FAILURE
	case "RESTORE_FAILURE":
		return BACnetBackupState_RESTORE_FAILURE
	}
	return 0
}

func BACnetBackupStateKnows(value uint8) bool {
	for _, typeValue := range BACnetBackupStateValues {
		if uint8(typeValue) == value {
			return true
		}
	}
	return false
}

func CastBACnetBackupState(structType interface{}) BACnetBackupState {
	castFunc := func(typ interface{}) BACnetBackupState {
		if sBACnetBackupState, ok := typ.(BACnetBackupState); ok {
			return sBACnetBackupState
		}
		return 0
	}
	return castFunc(structType)
}

func (m BACnetBackupState) GetLengthInBits() uint16 {
	return 8
}

func (m BACnetBackupState) GetLengthInBytes() uint16 {
	return m.GetLengthInBits() / 8
}

func BACnetBackupStateParse(readBuffer utils.ReadBuffer) (BACnetBackupState, error) {
	val, err := readBuffer.ReadUint8("BACnetBackupState", 8)
	if err != nil {
		return 0, nil
	}
	return BACnetBackupStateByValue(val), nil
}

func (e BACnetBackupState) Serialize(writeBuffer utils.WriteBuffer) error {
	return writeBuffer.WriteUint8("BACnetBackupState", 8, uint8(e), utils.WithAdditionalStringRepresentation(e.name()))
}

func (e BACnetBackupState) name() string {
	switch e {
	case BACnetBackupState_IDLE:
		return "IDLE"
	case BACnetBackupState_PREPARING_FOR_BACKUP:
		return "PREPARING_FOR_BACKUP"
	case BACnetBackupState_PREPARING_FOR_RESTORE:
		return "PREPARING_FOR_RESTORE"
	case BACnetBackupState_PERFORMING_A_BACKUP:
		return "PERFORMING_A_BACKUP"
	case BACnetBackupState_PERFORMING_A_RESTORE:
		return "PERFORMING_A_RESTORE"
	case BACnetBackupState_BACKUP_FAILURE:
		return "BACKUP_FAILURE"
	case BACnetBackupState_RESTORE_FAILURE:
		return "RESTORE_FAILURE"
	}
	return ""
}

func (e BACnetBackupState) String() string {
	return e.name()
}
