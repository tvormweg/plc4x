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
	"github.com/apache/plc4x/plc4go/internal/plc4go/spi/utils"
	"github.com/pkg/errors"
)

	// Code generated by code-generation. DO NOT EDIT.


// The data-structure of this message
type MQTT_ControlPacket_PUBLISH struct {
	*MQTT_ControlPacket
	Dup bool
	Qos MQTT_QOS
	Retain bool
	RemainingLength uint8
	TopicName *MQTT_String
	PacketIdentifier *uint16
	PropertyLength *uint32
	Properties []*MQTT_Property
	Payload []byte
}

// The corresponding interface
type IMQTT_ControlPacket_PUBLISH interface {
	LengthInBytes() uint16
	LengthInBits() uint16
	Serialize(writeBuffer utils.WriteBuffer) error
}

///////////////////////////////////////////////////////////
// Accessors for discriminator values.
///////////////////////////////////////////////////////////
func (m *MQTT_ControlPacket_PUBLISH) PacketType() MQTT_ControlPacketType {
	return MQTT_ControlPacketType_PUBLISH
}


func (m *MQTT_ControlPacket_PUBLISH) InitializeParent(parent *MQTT_ControlPacket) {
}

func NewMQTT_ControlPacket_PUBLISH(dup bool, qos MQTT_QOS, retain bool, remainingLength uint8, topicName *MQTT_String, packetIdentifier *uint16, propertyLength *uint32, properties []*MQTT_Property, payload []byte) *MQTT_ControlPacket {
	child := &MQTT_ControlPacket_PUBLISH{
		Dup: dup,
		Qos: qos,
		Retain: retain,
		RemainingLength: remainingLength,
		TopicName: topicName,
		PacketIdentifier: packetIdentifier,
		PropertyLength: propertyLength,
		Properties: properties,
		Payload: payload,
    	MQTT_ControlPacket: NewMQTT_ControlPacket(),
	}
	child.Child = child
	return child.MQTT_ControlPacket
}

func CastMQTT_ControlPacket_PUBLISH(structType interface{}) *MQTT_ControlPacket_PUBLISH {
	castFunc := func(typ interface{}) *MQTT_ControlPacket_PUBLISH {
		if casted, ok := typ.(MQTT_ControlPacket_PUBLISH); ok {
			return &casted
		}
		if casted, ok := typ.(*MQTT_ControlPacket_PUBLISH); ok {
			return casted
		}
		if casted, ok := typ.(MQTT_ControlPacket); ok {
			return CastMQTT_ControlPacket_PUBLISH(casted.Child)
		}
		if casted, ok := typ.(*MQTT_ControlPacket); ok {
			return CastMQTT_ControlPacket_PUBLISH(casted.Child)
		}
		return nil
	}
	return castFunc(structType)
}

func (m *MQTT_ControlPacket_PUBLISH) GetTypeName() string {
	return "MQTT_ControlPacket_PUBLISH"
}

func (m *MQTT_ControlPacket_PUBLISH) LengthInBits() uint16 {
	return m.LengthInBitsConditional(false)
}

func (m *MQTT_ControlPacket_PUBLISH) LengthInBitsConditional(lastItem bool) uint16 {
	lengthInBits := uint16(m.ParentLengthInBits())

	// Simple field (dup)
	lengthInBits += 1;

	// Simple field (qos)
	lengthInBits += 2

	// Simple field (retain)
	lengthInBits += 1;

	// Simple field (remainingLength)
	lengthInBits += 8;

	// Simple field (topicName)
	lengthInBits += m.TopicName.LengthInBits()

	// Optional Field (packetIdentifier)
	if m.PacketIdentifier != nil {
		lengthInBits += 16
	}

	// Optional Field (propertyLength)
	if m.PropertyLength != nil {
		lengthInBits += 32
	}

	// Array field
	if len(m.Properties) > 0 {
		for _, element := range m.Properties {
			lengthInBits += element.LengthInBits()
		}
	}

	// Array field
	if len(m.Payload) > 0 {
		lengthInBits += 8 * uint16(len(m.Payload))
	}

	return lengthInBits
}


func (m *MQTT_ControlPacket_PUBLISH) LengthInBytes() uint16 {
	return m.LengthInBits() / 8
}

func MQTT_ControlPacket_PUBLISHParse(readBuffer utils.ReadBuffer) (*MQTT_ControlPacket, error) {
	if pullErr := readBuffer.PullContext("MQTT_ControlPacket_PUBLISH"); pullErr != nil {
		return nil, pullErr
	}
	var startPos = readBuffer.GetPos()
	var curPos uint16

	// Simple Field (dup)
_dup, _dupErr := readBuffer.ReadBit("dup")
	if _dupErr != nil {
		return nil, errors.Wrap(_dupErr, "Error parsing 'dup' field")
	}
	dup := _dup

	// Simple Field (qos)
	if pullErr := readBuffer.PullContext("qos"); pullErr != nil {
		return nil, pullErr
	}
_qos, _qosErr := MQTT_QOSParse(readBuffer)
	if _qosErr != nil {
		return nil, errors.Wrap(_qosErr, "Error parsing 'qos' field")
	}
	qos := _qos
	if closeErr := readBuffer.CloseContext("qos"); closeErr != nil {
		return nil, closeErr
	}

	// Simple Field (retain)
_retain, _retainErr := readBuffer.ReadBit("retain")
	if _retainErr != nil {
		return nil, errors.Wrap(_retainErr, "Error parsing 'retain' field")
	}
	retain := _retain

	// Simple Field (remainingLength)
_remainingLength, _remainingLengthErr := readBuffer.ReadUint8("remainingLength", 8)
	if _remainingLengthErr != nil {
		return nil, errors.Wrap(_remainingLengthErr, "Error parsing 'remainingLength' field")
	}
	remainingLength := _remainingLength

	// Simple Field (topicName)
	if pullErr := readBuffer.PullContext("topicName"); pullErr != nil {
		return nil, pullErr
	}
_topicName, _topicNameErr := MQTT_StringParse(readBuffer)
	if _topicNameErr != nil {
		return nil, errors.Wrap(_topicNameErr, "Error parsing 'topicName' field")
	}
	topicName := CastMQTT_String(_topicName)
	if closeErr := readBuffer.CloseContext("topicName"); closeErr != nil {
		return nil, closeErr
	}

	// Optional Field (packetIdentifier) (Can be skipped, if a given expression evaluates to false)
	var packetIdentifier *uint16 = nil
	if bool((qos) != (MQTT_QOS_AT_MOST_ONCE)) {
		_val, _err := readBuffer.ReadUint16("packetIdentifier", 16)
		if _err != nil {
			return nil, errors.Wrap(_err, "Error parsing 'packetIdentifier' field")
		}
		packetIdentifier = &_val
	}

	// Optional Field (propertyLength) (Can be skipped, if a given expression evaluates to false)
	curPos = readBuffer.GetPos() - startPos
	var propertyLength *uint32 = nil
	if bool(((remainingLength) - (curPos)) < ((4))) {
		_val, _err := readBuffer.ReadUint32("propertyLength", 32)
		if _err != nil {
			return nil, errors.Wrap(_err, "Error parsing 'propertyLength' field")
		}
		propertyLength = &_val
	}

	// Array field (properties)
	if pullErr := readBuffer.PullContext("properties", utils.WithRenderAsList(true)); pullErr != nil {
		return nil, pullErr
	}
	// Length array
	properties := make([]*MQTT_Property, 0)
	{
		_propertiesLength := utils.InlineIf(bool(bool(((propertyLength)) != (nil))), func() interface{} {return uint16((*propertyLength))}, func() interface{} {return uint16(uint16(0))}).(uint16)
		_propertiesEndPos := readBuffer.GetPos() + uint16(_propertiesLength)
		for ;readBuffer.GetPos() < _propertiesEndPos; {
			_item, _err := MQTT_PropertyParse(readBuffer)
			if _err != nil {
				return nil, errors.Wrap(_err, "Error parsing 'properties' field")
			}
			properties = append(properties, _item)
		}
	}
	if closeErr := readBuffer.CloseContext("properties", utils.WithRenderAsList(true)); closeErr != nil {
		return nil, closeErr
	}
	// Byte Array field (payload)
	numberOfBytespayload := int(uint16(remainingLength) - uint16(curPos))
	payload, _readArrayErr := readBuffer.ReadByteArray("payload", numberOfBytespayload)
	if _readArrayErr != nil {
		return nil, errors.Wrap(_readArrayErr, "Error parsing 'payload' field")
	}

	if closeErr := readBuffer.CloseContext("MQTT_ControlPacket_PUBLISH"); closeErr != nil {
		return nil, closeErr
	}

	// Create a partially initialized instance
	_child := &MQTT_ControlPacket_PUBLISH{
		Dup: dup,
		Qos: qos,
		Retain: retain,
		RemainingLength: remainingLength,
		TopicName: CastMQTT_String(topicName),
		PacketIdentifier: packetIdentifier,
		PropertyLength: propertyLength,
		Properties: properties,
		Payload: payload,
        MQTT_ControlPacket: &MQTT_ControlPacket{},
	}
	_child.MQTT_ControlPacket.Child = _child
	return _child.MQTT_ControlPacket, nil
}

func (m *MQTT_ControlPacket_PUBLISH) Serialize(writeBuffer utils.WriteBuffer) error {
	ser := func() error {
		if pushErr := writeBuffer.PushContext("MQTT_ControlPacket_PUBLISH"); pushErr != nil {
			return pushErr
		}

	// Simple Field (dup)
	dup := bool(m.Dup)
	_dupErr := writeBuffer.WriteBit("dup", (dup))
	if _dupErr != nil {
		return errors.Wrap(_dupErr, "Error serializing 'dup' field")
	}

	// Simple Field (qos)
	if pushErr := writeBuffer.PushContext("qos"); pushErr != nil {
		return pushErr
	}
	_qosErr := m.Qos.Serialize(writeBuffer)
	if popErr := writeBuffer.PopContext("qos"); popErr != nil {
		return popErr
	}
	if _qosErr != nil {
		return errors.Wrap(_qosErr, "Error serializing 'qos' field")
	}

	// Simple Field (retain)
	retain := bool(m.Retain)
	_retainErr := writeBuffer.WriteBit("retain", (retain))
	if _retainErr != nil {
		return errors.Wrap(_retainErr, "Error serializing 'retain' field")
	}

	// Simple Field (remainingLength)
	remainingLength := uint8(m.RemainingLength)
	_remainingLengthErr := writeBuffer.WriteUint8("remainingLength", 8, (remainingLength))
	if _remainingLengthErr != nil {
		return errors.Wrap(_remainingLengthErr, "Error serializing 'remainingLength' field")
	}

	// Simple Field (topicName)
	if pushErr := writeBuffer.PushContext("topicName"); pushErr != nil {
		return pushErr
	}
	_topicNameErr := m.TopicName.Serialize(writeBuffer)
	if popErr := writeBuffer.PopContext("topicName"); popErr != nil {
		return popErr
	}
	if _topicNameErr != nil {
		return errors.Wrap(_topicNameErr, "Error serializing 'topicName' field")
	}

	// Optional Field (packetIdentifier) (Can be skipped, if the value is null)
	var packetIdentifier *uint16 = nil
	if m.PacketIdentifier != nil {
		packetIdentifier = m.PacketIdentifier
		_packetIdentifierErr := writeBuffer.WriteUint16("packetIdentifier", 16, *(packetIdentifier))
		if _packetIdentifierErr != nil {
			return errors.Wrap(_packetIdentifierErr, "Error serializing 'packetIdentifier' field")
		}
	}

	// Optional Field (propertyLength) (Can be skipped, if the value is null)
	var propertyLength *uint32 = nil
	if m.PropertyLength != nil {
		propertyLength = m.PropertyLength
		_propertyLengthErr := writeBuffer.WriteUint32("propertyLength", 32, *(propertyLength))
		if _propertyLengthErr != nil {
			return errors.Wrap(_propertyLengthErr, "Error serializing 'propertyLength' field")
		}
	}

	// Array Field (properties)
	if m.Properties != nil {
		if pushErr := writeBuffer.PushContext("properties", utils.WithRenderAsList(true)); pushErr != nil {
			return pushErr
		}
		for _, _element := range m.Properties {
			_elementErr := _element.Serialize(writeBuffer)
			if _elementErr != nil {
				return errors.Wrap(_elementErr, "Error serializing 'properties' field")
			}
		}
		if popErr := writeBuffer.PopContext("properties", utils.WithRenderAsList(true)); popErr != nil {
			return popErr
		}
	}

	// Array Field (payload)
	if m.Payload != nil {
		// Byte Array field (payload)
		_writeArrayErr := writeBuffer.WriteByteArray("payload", m.Payload)
		if _writeArrayErr != nil {
			return errors.Wrap(_writeArrayErr, "Error serializing 'payload' field")
		}
	}

		if popErr := writeBuffer.PopContext("MQTT_ControlPacket_PUBLISH"); popErr != nil {
			return popErr
		}
		return nil
	}
	return m.SerializeParent(writeBuffer, m, ser)
}

func (m *MQTT_ControlPacket_PUBLISH) String() string {
	if m == nil {
		return "<nil>"
	}
	buffer := utils.NewBoxedWriteBufferWithOptions(true, true)
	m.Serialize(buffer)
	return buffer.GetBox().String()
}



