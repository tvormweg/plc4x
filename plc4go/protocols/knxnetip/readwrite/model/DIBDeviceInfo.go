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

// DIBDeviceInfo is the corresponding interface of DIBDeviceInfo
type DIBDeviceInfo interface {
	utils.LengthAware
	utils.Serializable
	// GetDescriptionType returns DescriptionType (property field)
	GetDescriptionType() uint8
	// GetKnxMedium returns KnxMedium (property field)
	GetKnxMedium() KnxMedium
	// GetDeviceStatus returns DeviceStatus (property field)
	GetDeviceStatus() DeviceStatus
	// GetKnxAddress returns KnxAddress (property field)
	GetKnxAddress() KnxAddress
	// GetProjectInstallationIdentifier returns ProjectInstallationIdentifier (property field)
	GetProjectInstallationIdentifier() ProjectInstallationIdentifier
	// GetKnxNetIpDeviceSerialNumber returns KnxNetIpDeviceSerialNumber (property field)
	GetKnxNetIpDeviceSerialNumber() []byte
	// GetKnxNetIpDeviceMulticastAddress returns KnxNetIpDeviceMulticastAddress (property field)
	GetKnxNetIpDeviceMulticastAddress() IPAddress
	// GetKnxNetIpDeviceMacAddress returns KnxNetIpDeviceMacAddress (property field)
	GetKnxNetIpDeviceMacAddress() MACAddress
	// GetDeviceFriendlyName returns DeviceFriendlyName (property field)
	GetDeviceFriendlyName() []byte
}

// DIBDeviceInfoExactly can be used when we want exactly this type and not a type which fulfills DIBDeviceInfo.
// This is useful for switch cases.
type DIBDeviceInfoExactly interface {
	DIBDeviceInfo
	isDIBDeviceInfo() bool
}

// _DIBDeviceInfo is the data-structure of this message
type _DIBDeviceInfo struct {
	DescriptionType                uint8
	KnxMedium                      KnxMedium
	DeviceStatus                   DeviceStatus
	KnxAddress                     KnxAddress
	ProjectInstallationIdentifier  ProjectInstallationIdentifier
	KnxNetIpDeviceSerialNumber     []byte
	KnxNetIpDeviceMulticastAddress IPAddress
	KnxNetIpDeviceMacAddress       MACAddress
	DeviceFriendlyName             []byte
}

///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
/////////////////////// Accessors for property fields.
///////////////////////

func (m *_DIBDeviceInfo) GetDescriptionType() uint8 {
	return m.DescriptionType
}

func (m *_DIBDeviceInfo) GetKnxMedium() KnxMedium {
	return m.KnxMedium
}

func (m *_DIBDeviceInfo) GetDeviceStatus() DeviceStatus {
	return m.DeviceStatus
}

func (m *_DIBDeviceInfo) GetKnxAddress() KnxAddress {
	return m.KnxAddress
}

func (m *_DIBDeviceInfo) GetProjectInstallationIdentifier() ProjectInstallationIdentifier {
	return m.ProjectInstallationIdentifier
}

func (m *_DIBDeviceInfo) GetKnxNetIpDeviceSerialNumber() []byte {
	return m.KnxNetIpDeviceSerialNumber
}

func (m *_DIBDeviceInfo) GetKnxNetIpDeviceMulticastAddress() IPAddress {
	return m.KnxNetIpDeviceMulticastAddress
}

func (m *_DIBDeviceInfo) GetKnxNetIpDeviceMacAddress() MACAddress {
	return m.KnxNetIpDeviceMacAddress
}

func (m *_DIBDeviceInfo) GetDeviceFriendlyName() []byte {
	return m.DeviceFriendlyName
}

///////////////////////
///////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////

// NewDIBDeviceInfo factory function for _DIBDeviceInfo
func NewDIBDeviceInfo(descriptionType uint8, knxMedium KnxMedium, deviceStatus DeviceStatus, knxAddress KnxAddress, projectInstallationIdentifier ProjectInstallationIdentifier, knxNetIpDeviceSerialNumber []byte, knxNetIpDeviceMulticastAddress IPAddress, knxNetIpDeviceMacAddress MACAddress, deviceFriendlyName []byte) *_DIBDeviceInfo {
	return &_DIBDeviceInfo{DescriptionType: descriptionType, KnxMedium: knxMedium, DeviceStatus: deviceStatus, KnxAddress: knxAddress, ProjectInstallationIdentifier: projectInstallationIdentifier, KnxNetIpDeviceSerialNumber: knxNetIpDeviceSerialNumber, KnxNetIpDeviceMulticastAddress: knxNetIpDeviceMulticastAddress, KnxNetIpDeviceMacAddress: knxNetIpDeviceMacAddress, DeviceFriendlyName: deviceFriendlyName}
}

// Deprecated: use the interface for direct cast
func CastDIBDeviceInfo(structType interface{}) DIBDeviceInfo {
	if casted, ok := structType.(DIBDeviceInfo); ok {
		return casted
	}
	if casted, ok := structType.(*DIBDeviceInfo); ok {
		return *casted
	}
	return nil
}

func (m *_DIBDeviceInfo) GetTypeName() string {
	return "DIBDeviceInfo"
}

func (m *_DIBDeviceInfo) GetLengthInBits() uint16 {
	return m.GetLengthInBitsConditional(false)
}

func (m *_DIBDeviceInfo) GetLengthInBitsConditional(lastItem bool) uint16 {
	lengthInBits := uint16(0)

	// Implicit Field (structureLength)
	lengthInBits += 8

	// Simple field (descriptionType)
	lengthInBits += 8

	// Simple field (knxMedium)
	lengthInBits += 8

	// Simple field (deviceStatus)
	lengthInBits += m.DeviceStatus.GetLengthInBits()

	// Simple field (knxAddress)
	lengthInBits += m.KnxAddress.GetLengthInBits()

	// Simple field (projectInstallationIdentifier)
	lengthInBits += m.ProjectInstallationIdentifier.GetLengthInBits()

	// Array field
	if len(m.KnxNetIpDeviceSerialNumber) > 0 {
		lengthInBits += 8 * uint16(len(m.KnxNetIpDeviceSerialNumber))
	}

	// Simple field (knxNetIpDeviceMulticastAddress)
	lengthInBits += m.KnxNetIpDeviceMulticastAddress.GetLengthInBits()

	// Simple field (knxNetIpDeviceMacAddress)
	lengthInBits += m.KnxNetIpDeviceMacAddress.GetLengthInBits()

	// Array field
	if len(m.DeviceFriendlyName) > 0 {
		lengthInBits += 8 * uint16(len(m.DeviceFriendlyName))
	}

	return lengthInBits
}

func (m *_DIBDeviceInfo) GetLengthInBytes() uint16 {
	return m.GetLengthInBits() / 8
}

func DIBDeviceInfoParse(readBuffer utils.ReadBuffer) (DIBDeviceInfo, error) {
	positionAware := readBuffer
	_ = positionAware
	if pullErr := readBuffer.PullContext("DIBDeviceInfo"); pullErr != nil {
		return nil, errors.Wrap(pullErr, "Error pulling for DIBDeviceInfo")
	}
	currentPos := positionAware.GetPos()
	_ = currentPos

	// Implicit Field (structureLength) (Used for parsing, but its value is not stored as it's implicitly given by the objects content)
	structureLength, _structureLengthErr := readBuffer.ReadUint8("structureLength", 8)
	_ = structureLength
	if _structureLengthErr != nil {
		return nil, errors.Wrap(_structureLengthErr, "Error parsing 'structureLength' field")
	}

	// Simple Field (descriptionType)
	_descriptionType, _descriptionTypeErr := readBuffer.ReadUint8("descriptionType", 8)
	if _descriptionTypeErr != nil {
		return nil, errors.Wrap(_descriptionTypeErr, "Error parsing 'descriptionType' field")
	}
	descriptionType := _descriptionType

	// Simple Field (knxMedium)
	if pullErr := readBuffer.PullContext("knxMedium"); pullErr != nil {
		return nil, errors.Wrap(pullErr, "Error pulling for knxMedium")
	}
	_knxMedium, _knxMediumErr := KnxMediumParse(readBuffer)
	if _knxMediumErr != nil {
		return nil, errors.Wrap(_knxMediumErr, "Error parsing 'knxMedium' field")
	}
	knxMedium := _knxMedium
	if closeErr := readBuffer.CloseContext("knxMedium"); closeErr != nil {
		return nil, errors.Wrap(closeErr, "Error closing for knxMedium")
	}

	// Simple Field (deviceStatus)
	if pullErr := readBuffer.PullContext("deviceStatus"); pullErr != nil {
		return nil, errors.Wrap(pullErr, "Error pulling for deviceStatus")
	}
	_deviceStatus, _deviceStatusErr := DeviceStatusParse(readBuffer)
	if _deviceStatusErr != nil {
		return nil, errors.Wrap(_deviceStatusErr, "Error parsing 'deviceStatus' field")
	}
	deviceStatus := _deviceStatus.(DeviceStatus)
	if closeErr := readBuffer.CloseContext("deviceStatus"); closeErr != nil {
		return nil, errors.Wrap(closeErr, "Error closing for deviceStatus")
	}

	// Simple Field (knxAddress)
	if pullErr := readBuffer.PullContext("knxAddress"); pullErr != nil {
		return nil, errors.Wrap(pullErr, "Error pulling for knxAddress")
	}
	_knxAddress, _knxAddressErr := KnxAddressParse(readBuffer)
	if _knxAddressErr != nil {
		return nil, errors.Wrap(_knxAddressErr, "Error parsing 'knxAddress' field")
	}
	knxAddress := _knxAddress.(KnxAddress)
	if closeErr := readBuffer.CloseContext("knxAddress"); closeErr != nil {
		return nil, errors.Wrap(closeErr, "Error closing for knxAddress")
	}

	// Simple Field (projectInstallationIdentifier)
	if pullErr := readBuffer.PullContext("projectInstallationIdentifier"); pullErr != nil {
		return nil, errors.Wrap(pullErr, "Error pulling for projectInstallationIdentifier")
	}
	_projectInstallationIdentifier, _projectInstallationIdentifierErr := ProjectInstallationIdentifierParse(readBuffer)
	if _projectInstallationIdentifierErr != nil {
		return nil, errors.Wrap(_projectInstallationIdentifierErr, "Error parsing 'projectInstallationIdentifier' field")
	}
	projectInstallationIdentifier := _projectInstallationIdentifier.(ProjectInstallationIdentifier)
	if closeErr := readBuffer.CloseContext("projectInstallationIdentifier"); closeErr != nil {
		return nil, errors.Wrap(closeErr, "Error closing for projectInstallationIdentifier")
	}
	// Byte Array field (knxNetIpDeviceSerialNumber)
	numberOfBytesknxNetIpDeviceSerialNumber := int(uint16(6))
	knxNetIpDeviceSerialNumber, _readArrayErr := readBuffer.ReadByteArray("knxNetIpDeviceSerialNumber", numberOfBytesknxNetIpDeviceSerialNumber)
	if _readArrayErr != nil {
		return nil, errors.Wrap(_readArrayErr, "Error parsing 'knxNetIpDeviceSerialNumber' field")
	}

	// Simple Field (knxNetIpDeviceMulticastAddress)
	if pullErr := readBuffer.PullContext("knxNetIpDeviceMulticastAddress"); pullErr != nil {
		return nil, errors.Wrap(pullErr, "Error pulling for knxNetIpDeviceMulticastAddress")
	}
	_knxNetIpDeviceMulticastAddress, _knxNetIpDeviceMulticastAddressErr := IPAddressParse(readBuffer)
	if _knxNetIpDeviceMulticastAddressErr != nil {
		return nil, errors.Wrap(_knxNetIpDeviceMulticastAddressErr, "Error parsing 'knxNetIpDeviceMulticastAddress' field")
	}
	knxNetIpDeviceMulticastAddress := _knxNetIpDeviceMulticastAddress.(IPAddress)
	if closeErr := readBuffer.CloseContext("knxNetIpDeviceMulticastAddress"); closeErr != nil {
		return nil, errors.Wrap(closeErr, "Error closing for knxNetIpDeviceMulticastAddress")
	}

	// Simple Field (knxNetIpDeviceMacAddress)
	if pullErr := readBuffer.PullContext("knxNetIpDeviceMacAddress"); pullErr != nil {
		return nil, errors.Wrap(pullErr, "Error pulling for knxNetIpDeviceMacAddress")
	}
	_knxNetIpDeviceMacAddress, _knxNetIpDeviceMacAddressErr := MACAddressParse(readBuffer)
	if _knxNetIpDeviceMacAddressErr != nil {
		return nil, errors.Wrap(_knxNetIpDeviceMacAddressErr, "Error parsing 'knxNetIpDeviceMacAddress' field")
	}
	knxNetIpDeviceMacAddress := _knxNetIpDeviceMacAddress.(MACAddress)
	if closeErr := readBuffer.CloseContext("knxNetIpDeviceMacAddress"); closeErr != nil {
		return nil, errors.Wrap(closeErr, "Error closing for knxNetIpDeviceMacAddress")
	}
	// Byte Array field (deviceFriendlyName)
	numberOfBytesdeviceFriendlyName := int(uint16(30))
	deviceFriendlyName, _readArrayErr := readBuffer.ReadByteArray("deviceFriendlyName", numberOfBytesdeviceFriendlyName)
	if _readArrayErr != nil {
		return nil, errors.Wrap(_readArrayErr, "Error parsing 'deviceFriendlyName' field")
	}

	if closeErr := readBuffer.CloseContext("DIBDeviceInfo"); closeErr != nil {
		return nil, errors.Wrap(closeErr, "Error closing for DIBDeviceInfo")
	}

	// Create the instance
	return NewDIBDeviceInfo(descriptionType, knxMedium, deviceStatus, knxAddress, projectInstallationIdentifier, knxNetIpDeviceSerialNumber, knxNetIpDeviceMulticastAddress, knxNetIpDeviceMacAddress, deviceFriendlyName), nil
}

func (m *_DIBDeviceInfo) Serialize(writeBuffer utils.WriteBuffer) error {
	positionAware := writeBuffer
	_ = positionAware
	if pushErr := writeBuffer.PushContext("DIBDeviceInfo"); pushErr != nil {
		return errors.Wrap(pushErr, "Error pushing for DIBDeviceInfo")
	}

	// Implicit Field (structureLength) (Used for parsing, but it's value is not stored as it's implicitly given by the objects content)
	structureLength := uint8(uint8(m.GetLengthInBytes()))
	_structureLengthErr := writeBuffer.WriteUint8("structureLength", 8, (structureLength))
	if _structureLengthErr != nil {
		return errors.Wrap(_structureLengthErr, "Error serializing 'structureLength' field")
	}

	// Simple Field (descriptionType)
	descriptionType := uint8(m.GetDescriptionType())
	_descriptionTypeErr := writeBuffer.WriteUint8("descriptionType", 8, (descriptionType))
	if _descriptionTypeErr != nil {
		return errors.Wrap(_descriptionTypeErr, "Error serializing 'descriptionType' field")
	}

	// Simple Field (knxMedium)
	if pushErr := writeBuffer.PushContext("knxMedium"); pushErr != nil {
		return errors.Wrap(pushErr, "Error pushing for knxMedium")
	}
	_knxMediumErr := writeBuffer.WriteSerializable(m.GetKnxMedium())
	if popErr := writeBuffer.PopContext("knxMedium"); popErr != nil {
		return errors.Wrap(popErr, "Error popping for knxMedium")
	}
	if _knxMediumErr != nil {
		return errors.Wrap(_knxMediumErr, "Error serializing 'knxMedium' field")
	}

	// Simple Field (deviceStatus)
	if pushErr := writeBuffer.PushContext("deviceStatus"); pushErr != nil {
		return errors.Wrap(pushErr, "Error pushing for deviceStatus")
	}
	_deviceStatusErr := writeBuffer.WriteSerializable(m.GetDeviceStatus())
	if popErr := writeBuffer.PopContext("deviceStatus"); popErr != nil {
		return errors.Wrap(popErr, "Error popping for deviceStatus")
	}
	if _deviceStatusErr != nil {
		return errors.Wrap(_deviceStatusErr, "Error serializing 'deviceStatus' field")
	}

	// Simple Field (knxAddress)
	if pushErr := writeBuffer.PushContext("knxAddress"); pushErr != nil {
		return errors.Wrap(pushErr, "Error pushing for knxAddress")
	}
	_knxAddressErr := writeBuffer.WriteSerializable(m.GetKnxAddress())
	if popErr := writeBuffer.PopContext("knxAddress"); popErr != nil {
		return errors.Wrap(popErr, "Error popping for knxAddress")
	}
	if _knxAddressErr != nil {
		return errors.Wrap(_knxAddressErr, "Error serializing 'knxAddress' field")
	}

	// Simple Field (projectInstallationIdentifier)
	if pushErr := writeBuffer.PushContext("projectInstallationIdentifier"); pushErr != nil {
		return errors.Wrap(pushErr, "Error pushing for projectInstallationIdentifier")
	}
	_projectInstallationIdentifierErr := writeBuffer.WriteSerializable(m.GetProjectInstallationIdentifier())
	if popErr := writeBuffer.PopContext("projectInstallationIdentifier"); popErr != nil {
		return errors.Wrap(popErr, "Error popping for projectInstallationIdentifier")
	}
	if _projectInstallationIdentifierErr != nil {
		return errors.Wrap(_projectInstallationIdentifierErr, "Error serializing 'projectInstallationIdentifier' field")
	}

	// Array Field (knxNetIpDeviceSerialNumber)
	// Byte Array field (knxNetIpDeviceSerialNumber)
	if err := writeBuffer.WriteByteArray("knxNetIpDeviceSerialNumber", m.GetKnxNetIpDeviceSerialNumber()); err != nil {
		return errors.Wrap(err, "Error serializing 'knxNetIpDeviceSerialNumber' field")
	}

	// Simple Field (knxNetIpDeviceMulticastAddress)
	if pushErr := writeBuffer.PushContext("knxNetIpDeviceMulticastAddress"); pushErr != nil {
		return errors.Wrap(pushErr, "Error pushing for knxNetIpDeviceMulticastAddress")
	}
	_knxNetIpDeviceMulticastAddressErr := writeBuffer.WriteSerializable(m.GetKnxNetIpDeviceMulticastAddress())
	if popErr := writeBuffer.PopContext("knxNetIpDeviceMulticastAddress"); popErr != nil {
		return errors.Wrap(popErr, "Error popping for knxNetIpDeviceMulticastAddress")
	}
	if _knxNetIpDeviceMulticastAddressErr != nil {
		return errors.Wrap(_knxNetIpDeviceMulticastAddressErr, "Error serializing 'knxNetIpDeviceMulticastAddress' field")
	}

	// Simple Field (knxNetIpDeviceMacAddress)
	if pushErr := writeBuffer.PushContext("knxNetIpDeviceMacAddress"); pushErr != nil {
		return errors.Wrap(pushErr, "Error pushing for knxNetIpDeviceMacAddress")
	}
	_knxNetIpDeviceMacAddressErr := writeBuffer.WriteSerializable(m.GetKnxNetIpDeviceMacAddress())
	if popErr := writeBuffer.PopContext("knxNetIpDeviceMacAddress"); popErr != nil {
		return errors.Wrap(popErr, "Error popping for knxNetIpDeviceMacAddress")
	}
	if _knxNetIpDeviceMacAddressErr != nil {
		return errors.Wrap(_knxNetIpDeviceMacAddressErr, "Error serializing 'knxNetIpDeviceMacAddress' field")
	}

	// Array Field (deviceFriendlyName)
	// Byte Array field (deviceFriendlyName)
	if err := writeBuffer.WriteByteArray("deviceFriendlyName", m.GetDeviceFriendlyName()); err != nil {
		return errors.Wrap(err, "Error serializing 'deviceFriendlyName' field")
	}

	if popErr := writeBuffer.PopContext("DIBDeviceInfo"); popErr != nil {
		return errors.Wrap(popErr, "Error popping for DIBDeviceInfo")
	}
	return nil
}

func (m *_DIBDeviceInfo) isDIBDeviceInfo() bool {
	return true
}

func (m *_DIBDeviceInfo) String() string {
	if m == nil {
		return "<nil>"
	}
	writeBuffer := utils.NewBoxedWriteBufferWithOptions(true, true)
	if err := writeBuffer.WriteSerializable(m); err != nil {
		return err.Error()
	}
	return writeBuffer.GetBox().String()
}
