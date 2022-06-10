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
	"github.com/apache/plc4x/plc4go/internal/spi/utils"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"io"
)

// Code generated by code-generation. DO NOT EDIT.

// BACnetServiceAckGetEnrollmentSummary is the data-structure of this message
type BACnetServiceAckGetEnrollmentSummary struct {
	*BACnetServiceAck
	ObjectIdentifier  *BACnetApplicationTagObjectIdentifier
	EventType         *BACnetEventTypeTagged
	EventState        *BACnetEventStateTagged
	Priority          *BACnetApplicationTagUnsignedInteger
	NotificationClass *BACnetApplicationTagUnsignedInteger

	// Arguments.
	ServiceAckLength uint16
}

// IBACnetServiceAckGetEnrollmentSummary is the corresponding interface of BACnetServiceAckGetEnrollmentSummary
type IBACnetServiceAckGetEnrollmentSummary interface {
	IBACnetServiceAck
	// GetObjectIdentifier returns ObjectIdentifier (property field)
	GetObjectIdentifier() *BACnetApplicationTagObjectIdentifier
	// GetEventType returns EventType (property field)
	GetEventType() *BACnetEventTypeTagged
	// GetEventState returns EventState (property field)
	GetEventState() *BACnetEventStateTagged
	// GetPriority returns Priority (property field)
	GetPriority() *BACnetApplicationTagUnsignedInteger
	// GetNotificationClass returns NotificationClass (property field)
	GetNotificationClass() *BACnetApplicationTagUnsignedInteger
	// GetLengthInBytes returns the length in bytes
	GetLengthInBytes() uint16
	// GetLengthInBits returns the length in bits
	GetLengthInBits() uint16
	// Serialize serializes this type
	Serialize(writeBuffer utils.WriteBuffer) error
}

///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
/////////////////////// Accessors for discriminator values.
///////////////////////

func (m *BACnetServiceAckGetEnrollmentSummary) GetServiceChoice() BACnetConfirmedServiceChoice {
	return BACnetConfirmedServiceChoice_GET_ENROLLMENT_SUMMARY
}

///////////////////////
///////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////

func (m *BACnetServiceAckGetEnrollmentSummary) InitializeParent(parent *BACnetServiceAck) {}

func (m *BACnetServiceAckGetEnrollmentSummary) GetParent() *BACnetServiceAck {
	return m.BACnetServiceAck
}

///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
/////////////////////// Accessors for property fields.
///////////////////////

func (m *BACnetServiceAckGetEnrollmentSummary) GetObjectIdentifier() *BACnetApplicationTagObjectIdentifier {
	return m.ObjectIdentifier
}

func (m *BACnetServiceAckGetEnrollmentSummary) GetEventType() *BACnetEventTypeTagged {
	return m.EventType
}

func (m *BACnetServiceAckGetEnrollmentSummary) GetEventState() *BACnetEventStateTagged {
	return m.EventState
}

func (m *BACnetServiceAckGetEnrollmentSummary) GetPriority() *BACnetApplicationTagUnsignedInteger {
	return m.Priority
}

func (m *BACnetServiceAckGetEnrollmentSummary) GetNotificationClass() *BACnetApplicationTagUnsignedInteger {
	return m.NotificationClass
}

///////////////////////
///////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////

// NewBACnetServiceAckGetEnrollmentSummary factory function for BACnetServiceAckGetEnrollmentSummary
func NewBACnetServiceAckGetEnrollmentSummary(objectIdentifier *BACnetApplicationTagObjectIdentifier, eventType *BACnetEventTypeTagged, eventState *BACnetEventStateTagged, priority *BACnetApplicationTagUnsignedInteger, notificationClass *BACnetApplicationTagUnsignedInteger, serviceAckLength uint16) *BACnetServiceAckGetEnrollmentSummary {
	_result := &BACnetServiceAckGetEnrollmentSummary{
		ObjectIdentifier:  objectIdentifier,
		EventType:         eventType,
		EventState:        eventState,
		Priority:          priority,
		NotificationClass: notificationClass,
		BACnetServiceAck:  NewBACnetServiceAck(serviceAckLength),
	}
	_result.Child = _result
	return _result
}

func CastBACnetServiceAckGetEnrollmentSummary(structType interface{}) *BACnetServiceAckGetEnrollmentSummary {
	if casted, ok := structType.(BACnetServiceAckGetEnrollmentSummary); ok {
		return &casted
	}
	if casted, ok := structType.(*BACnetServiceAckGetEnrollmentSummary); ok {
		return casted
	}
	if casted, ok := structType.(BACnetServiceAck); ok {
		return CastBACnetServiceAckGetEnrollmentSummary(casted.Child)
	}
	if casted, ok := structType.(*BACnetServiceAck); ok {
		return CastBACnetServiceAckGetEnrollmentSummary(casted.Child)
	}
	return nil
}

func (m *BACnetServiceAckGetEnrollmentSummary) GetTypeName() string {
	return "BACnetServiceAckGetEnrollmentSummary"
}

func (m *BACnetServiceAckGetEnrollmentSummary) GetLengthInBits() uint16 {
	return m.GetLengthInBitsConditional(false)
}

func (m *BACnetServiceAckGetEnrollmentSummary) GetLengthInBitsConditional(lastItem bool) uint16 {
	lengthInBits := uint16(m.GetParentLengthInBits())

	// Simple field (objectIdentifier)
	lengthInBits += m.ObjectIdentifier.GetLengthInBits()

	// Simple field (eventType)
	lengthInBits += m.EventType.GetLengthInBits()

	// Simple field (eventState)
	lengthInBits += m.EventState.GetLengthInBits()

	// Simple field (priority)
	lengthInBits += m.Priority.GetLengthInBits()

	// Optional Field (notificationClass)
	if m.NotificationClass != nil {
		lengthInBits += (*m.NotificationClass).GetLengthInBits()
	}

	return lengthInBits
}

func (m *BACnetServiceAckGetEnrollmentSummary) GetLengthInBytes() uint16 {
	return m.GetLengthInBits() / 8
}

func BACnetServiceAckGetEnrollmentSummaryParse(readBuffer utils.ReadBuffer, serviceAckLength uint16) (*BACnetServiceAckGetEnrollmentSummary, error) {
	positionAware := readBuffer
	_ = positionAware
	if pullErr := readBuffer.PullContext("BACnetServiceAckGetEnrollmentSummary"); pullErr != nil {
		return nil, pullErr
	}
	currentPos := positionAware.GetPos()
	_ = currentPos

	// Simple Field (objectIdentifier)
	if pullErr := readBuffer.PullContext("objectIdentifier"); pullErr != nil {
		return nil, pullErr
	}
	_objectIdentifier, _objectIdentifierErr := BACnetApplicationTagParse(readBuffer)
	if _objectIdentifierErr != nil {
		return nil, errors.Wrap(_objectIdentifierErr, "Error parsing 'objectIdentifier' field")
	}
	objectIdentifier := CastBACnetApplicationTagObjectIdentifier(_objectIdentifier)
	if closeErr := readBuffer.CloseContext("objectIdentifier"); closeErr != nil {
		return nil, closeErr
	}

	// Simple Field (eventType)
	if pullErr := readBuffer.PullContext("eventType"); pullErr != nil {
		return nil, pullErr
	}
	_eventType, _eventTypeErr := BACnetEventTypeTaggedParse(readBuffer, uint8(uint8(0)), TagClass(TagClass_APPLICATION_TAGS))
	if _eventTypeErr != nil {
		return nil, errors.Wrap(_eventTypeErr, "Error parsing 'eventType' field")
	}
	eventType := CastBACnetEventTypeTagged(_eventType)
	if closeErr := readBuffer.CloseContext("eventType"); closeErr != nil {
		return nil, closeErr
	}

	// Simple Field (eventState)
	if pullErr := readBuffer.PullContext("eventState"); pullErr != nil {
		return nil, pullErr
	}
	_eventState, _eventStateErr := BACnetEventStateTaggedParse(readBuffer, uint8(uint8(0)), TagClass(TagClass_APPLICATION_TAGS))
	if _eventStateErr != nil {
		return nil, errors.Wrap(_eventStateErr, "Error parsing 'eventState' field")
	}
	eventState := CastBACnetEventStateTagged(_eventState)
	if closeErr := readBuffer.CloseContext("eventState"); closeErr != nil {
		return nil, closeErr
	}

	// Simple Field (priority)
	if pullErr := readBuffer.PullContext("priority"); pullErr != nil {
		return nil, pullErr
	}
	_priority, _priorityErr := BACnetApplicationTagParse(readBuffer)
	if _priorityErr != nil {
		return nil, errors.Wrap(_priorityErr, "Error parsing 'priority' field")
	}
	priority := CastBACnetApplicationTagUnsignedInteger(_priority)
	if closeErr := readBuffer.CloseContext("priority"); closeErr != nil {
		return nil, closeErr
	}

	// Optional Field (notificationClass) (Can be skipped, if a given expression evaluates to false)
	var notificationClass *BACnetApplicationTagUnsignedInteger = nil
	{
		currentPos = positionAware.GetPos()
		if pullErr := readBuffer.PullContext("notificationClass"); pullErr != nil {
			return nil, pullErr
		}
		_val, _err := BACnetApplicationTagParse(readBuffer)
		switch {
		case errors.Is(_err, utils.ParseAssertError{}) || errors.Is(_err, io.EOF):
			log.Debug().Err(_err).Msg("Resetting position because optional threw an error")
			readBuffer.Reset(currentPos)
		case _err != nil:
			return nil, errors.Wrap(_err, "Error parsing 'notificationClass' field")
		default:
			notificationClass = CastBACnetApplicationTagUnsignedInteger(_val)
			if closeErr := readBuffer.CloseContext("notificationClass"); closeErr != nil {
				return nil, closeErr
			}
		}
	}

	if closeErr := readBuffer.CloseContext("BACnetServiceAckGetEnrollmentSummary"); closeErr != nil {
		return nil, closeErr
	}

	// Create a partially initialized instance
	_child := &BACnetServiceAckGetEnrollmentSummary{
		ObjectIdentifier:  CastBACnetApplicationTagObjectIdentifier(objectIdentifier),
		EventType:         CastBACnetEventTypeTagged(eventType),
		EventState:        CastBACnetEventStateTagged(eventState),
		Priority:          CastBACnetApplicationTagUnsignedInteger(priority),
		NotificationClass: CastBACnetApplicationTagUnsignedInteger(notificationClass),
		BACnetServiceAck:  &BACnetServiceAck{},
	}
	_child.BACnetServiceAck.Child = _child
	return _child, nil
}

func (m *BACnetServiceAckGetEnrollmentSummary) Serialize(writeBuffer utils.WriteBuffer) error {
	positionAware := writeBuffer
	_ = positionAware
	ser := func() error {
		if pushErr := writeBuffer.PushContext("BACnetServiceAckGetEnrollmentSummary"); pushErr != nil {
			return pushErr
		}

		// Simple Field (objectIdentifier)
		if pushErr := writeBuffer.PushContext("objectIdentifier"); pushErr != nil {
			return pushErr
		}
		_objectIdentifierErr := m.ObjectIdentifier.Serialize(writeBuffer)
		if popErr := writeBuffer.PopContext("objectIdentifier"); popErr != nil {
			return popErr
		}
		if _objectIdentifierErr != nil {
			return errors.Wrap(_objectIdentifierErr, "Error serializing 'objectIdentifier' field")
		}

		// Simple Field (eventType)
		if pushErr := writeBuffer.PushContext("eventType"); pushErr != nil {
			return pushErr
		}
		_eventTypeErr := m.EventType.Serialize(writeBuffer)
		if popErr := writeBuffer.PopContext("eventType"); popErr != nil {
			return popErr
		}
		if _eventTypeErr != nil {
			return errors.Wrap(_eventTypeErr, "Error serializing 'eventType' field")
		}

		// Simple Field (eventState)
		if pushErr := writeBuffer.PushContext("eventState"); pushErr != nil {
			return pushErr
		}
		_eventStateErr := m.EventState.Serialize(writeBuffer)
		if popErr := writeBuffer.PopContext("eventState"); popErr != nil {
			return popErr
		}
		if _eventStateErr != nil {
			return errors.Wrap(_eventStateErr, "Error serializing 'eventState' field")
		}

		// Simple Field (priority)
		if pushErr := writeBuffer.PushContext("priority"); pushErr != nil {
			return pushErr
		}
		_priorityErr := m.Priority.Serialize(writeBuffer)
		if popErr := writeBuffer.PopContext("priority"); popErr != nil {
			return popErr
		}
		if _priorityErr != nil {
			return errors.Wrap(_priorityErr, "Error serializing 'priority' field")
		}

		// Optional Field (notificationClass) (Can be skipped, if the value is null)
		var notificationClass *BACnetApplicationTagUnsignedInteger = nil
		if m.NotificationClass != nil {
			if pushErr := writeBuffer.PushContext("notificationClass"); pushErr != nil {
				return pushErr
			}
			notificationClass = m.NotificationClass
			_notificationClassErr := notificationClass.Serialize(writeBuffer)
			if popErr := writeBuffer.PopContext("notificationClass"); popErr != nil {
				return popErr
			}
			if _notificationClassErr != nil {
				return errors.Wrap(_notificationClassErr, "Error serializing 'notificationClass' field")
			}
		}

		if popErr := writeBuffer.PopContext("BACnetServiceAckGetEnrollmentSummary"); popErr != nil {
			return popErr
		}
		return nil
	}
	return m.SerializeParent(writeBuffer, m, ser)
}

func (m *BACnetServiceAckGetEnrollmentSummary) String() string {
	if m == nil {
		return "<nil>"
	}
	buffer := utils.NewBoxedWriteBufferWithOptions(true, true)
	if err := m.Serialize(buffer); err != nil {
		return err.Error()
	}
	return buffer.GetBox().String()
}
