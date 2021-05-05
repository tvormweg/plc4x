//
// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.
//

package model

import (
	"encoding/hex"
	"encoding/xml"
	"github.com/apache/plc4x/plc4go/internal/plc4go/spi/utils"
	"github.com/pkg/errors"
	"io"
	"strings"
)

// Code generated by build-utils. DO NOT EDIT.

// The data-structure of this message
type CipWriteRequest struct {
	RequestPathSize int8
	Tag             []int8
	DataType        CIPDataTypeCode
	ElementNb       uint16
	Data            []int8
	Parent          *CipService
}

// The corresponding interface
type ICipWriteRequest interface {
	LengthInBytes() uint16
	LengthInBits() uint16
	Serialize(io utils.WriteBuffer) error
	xml.Marshaler
	xml.Unmarshaler
}

///////////////////////////////////////////////////////////
// Accessors for discriminator values.
///////////////////////////////////////////////////////////
func (m *CipWriteRequest) Service() uint8 {
	return 0x4D
}

func (m *CipWriteRequest) InitializeParent(parent *CipService) {
}

func NewCipWriteRequest(RequestPathSize int8, tag []int8, dataType CIPDataTypeCode, elementNb uint16, data []int8) *CipService {
	child := &CipWriteRequest{
		RequestPathSize: RequestPathSize,
		Tag:             tag,
		DataType:        dataType,
		ElementNb:       elementNb,
		Data:            data,
		Parent:          NewCipService(),
	}
	child.Parent.Child = child
	return child.Parent
}

func CastCipWriteRequest(structType interface{}) *CipWriteRequest {
	castFunc := func(typ interface{}) *CipWriteRequest {
		if casted, ok := typ.(CipWriteRequest); ok {
			return &casted
		}
		if casted, ok := typ.(*CipWriteRequest); ok {
			return casted
		}
		if casted, ok := typ.(CipService); ok {
			return CastCipWriteRequest(casted.Child)
		}
		if casted, ok := typ.(*CipService); ok {
			return CastCipWriteRequest(casted.Child)
		}
		return nil
	}
	return castFunc(structType)
}

func (m *CipWriteRequest) GetTypeName() string {
	return "CipWriteRequest"
}

func (m *CipWriteRequest) LengthInBits() uint16 {
	return m.LengthInBitsConditional(false)
}

func (m *CipWriteRequest) LengthInBitsConditional(lastItem bool) uint16 {
	lengthInBits := uint16(m.Parent.ParentLengthInBits())

	// Simple field (RequestPathSize)
	lengthInBits += 8

	// Array field
	if len(m.Tag) > 0 {
		lengthInBits += 8 * uint16(len(m.Tag))
	}

	// Enum Field (dataType)
	lengthInBits += 16

	// Simple field (elementNb)
	lengthInBits += 16

	// Array field
	if len(m.Data) > 0 {
		lengthInBits += 8 * uint16(len(m.Data))
	}

	return lengthInBits
}

func (m *CipWriteRequest) LengthInBytes() uint16 {
	return m.LengthInBits() / 8
}

func CipWriteRequestParse(io utils.ReadBuffer) (*CipService, error) {
	if pullErr := io.PullContext("CipWriteRequest"); pullErr != nil {
		return nil, pullErr
	}

	// Simple Field (RequestPathSize)
	RequestPathSize, _RequestPathSizeErr := io.ReadInt8("RequestPathSize", 8)
	if _RequestPathSizeErr != nil {
		return nil, errors.Wrap(_RequestPathSizeErr, "Error parsing 'RequestPathSize' field")
	}

	// Array field (tag)
	if pullErr := io.PullContext("tag", utils.WithRenderAsList(true)); pullErr != nil {
		return nil, pullErr
	}
	// Length array
	tag := make([]int8, 0)
	_tagLength := uint16(uint16(RequestPathSize) * uint16(uint16(2)))
	_tagEndPos := io.GetPos() + uint16(_tagLength)
	for io.GetPos() < _tagEndPos {
		_item, _err := io.ReadInt8("", 8)
		if _err != nil {
			return nil, errors.Wrap(_err, "Error parsing 'tag' field")
		}
		tag = append(tag, _item)
	}
	if closeErr := io.CloseContext("tag", utils.WithRenderAsList(true)); closeErr != nil {
		return nil, closeErr
	}

	if pullErr := io.PullContext("dataType"); pullErr != nil {
		return nil, pullErr
	}
	// Enum field (dataType)
	dataType, _dataTypeErr := CIPDataTypeCodeParse(io)
	if _dataTypeErr != nil {
		return nil, errors.Wrap(_dataTypeErr, "Error parsing 'dataType' field")
	}
	if closeErr := io.CloseContext("dataType"); closeErr != nil {
		return nil, closeErr
	}

	// Simple Field (elementNb)
	elementNb, _elementNbErr := io.ReadUint16("elementNb", 16)
	if _elementNbErr != nil {
		return nil, errors.Wrap(_elementNbErr, "Error parsing 'elementNb' field")
	}

	// Array field (data)
	if pullErr := io.PullContext("data", utils.WithRenderAsList(true)); pullErr != nil {
		return nil, pullErr
	}
	// Length array
	data := make([]int8, 0)
	_dataLength := uint16(dataType.Size()) * uint16(elementNb)
	_dataEndPos := io.GetPos() + uint16(_dataLength)
	for io.GetPos() < _dataEndPos {
		_item, _err := io.ReadInt8("", 8)
		if _err != nil {
			return nil, errors.Wrap(_err, "Error parsing 'data' field")
		}
		data = append(data, _item)
	}
	if closeErr := io.CloseContext("data", utils.WithRenderAsList(true)); closeErr != nil {
		return nil, closeErr
	}

	if closeErr := io.CloseContext("CipWriteRequest"); closeErr != nil {
		return nil, closeErr
	}

	// Create a partially initialized instance
	_child := &CipWriteRequest{
		RequestPathSize: RequestPathSize,
		Tag:             tag,
		DataType:        dataType,
		ElementNb:       elementNb,
		Data:            data,
		Parent:          &CipService{},
	}
	_child.Parent.Child = _child
	return _child.Parent, nil
}

func (m *CipWriteRequest) Serialize(io utils.WriteBuffer) error {
	ser := func() error {
		if pushErr := io.PushContext("CipWriteRequest"); pushErr != nil {
			return pushErr
		}

		// Simple Field (RequestPathSize)
		RequestPathSize := int8(m.RequestPathSize)
		_RequestPathSizeErr := io.WriteInt8("RequestPathSize", 8, (RequestPathSize))
		if _RequestPathSizeErr != nil {
			return errors.Wrap(_RequestPathSizeErr, "Error serializing 'RequestPathSize' field")
		}

		// Array Field (tag)
		if m.Tag != nil {
			if pushErr := io.PushContext("tag", utils.WithRenderAsList(true)); pushErr != nil {
				return pushErr
			}
			for _, _element := range m.Tag {
				_elementErr := io.WriteInt8("", 8, _element)
				if _elementErr != nil {
					return errors.Wrap(_elementErr, "Error serializing 'tag' field")
				}
			}
			if popErr := io.PopContext("tag", utils.WithRenderAsList(true)); popErr != nil {
				return popErr
			}
		}

		if pushErr := io.PushContext("dataType"); pushErr != nil {
			return pushErr
		}
		// Enum field (dataType)
		dataType := CastCIPDataTypeCode(m.DataType)
		_dataTypeErr := dataType.Serialize(io)
		if _dataTypeErr != nil {
			return errors.Wrap(_dataTypeErr, "Error serializing 'dataType' field")
		}
		if popErr := io.PopContext("dataType"); popErr != nil {
			return popErr
		}

		// Simple Field (elementNb)
		elementNb := uint16(m.ElementNb)
		_elementNbErr := io.WriteUint16("elementNb", 16, (elementNb))
		if _elementNbErr != nil {
			return errors.Wrap(_elementNbErr, "Error serializing 'elementNb' field")
		}

		// Array Field (data)
		if m.Data != nil {
			if pushErr := io.PushContext("data", utils.WithRenderAsList(true)); pushErr != nil {
				return pushErr
			}
			for _, _element := range m.Data {
				_elementErr := io.WriteInt8("", 8, _element)
				if _elementErr != nil {
					return errors.Wrap(_elementErr, "Error serializing 'data' field")
				}
			}
			if popErr := io.PopContext("data", utils.WithRenderAsList(true)); popErr != nil {
				return popErr
			}
		}

		if popErr := io.PopContext("CipWriteRequest"); popErr != nil {
			return popErr
		}
		return nil
	}
	return m.Parent.SerializeParent(io, m, ser)
}

// Deprecated: the utils.ReadBufferWriteBased should be used instead
func (m *CipWriteRequest) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var token xml.Token
	var err error
	foundContent := false
	token = start
	for {
		switch token.(type) {
		case xml.StartElement:
			foundContent = true
			tok := token.(xml.StartElement)
			switch tok.Name.Local {
			case "RequestPathSize":
				var data int8
				if err := d.DecodeElement(&data, &tok); err != nil {
					return err
				}
				m.RequestPathSize = data
			case "tag":
				var _encoded string
				if err := d.DecodeElement(&_encoded, &tok); err != nil {
					return err
				}
				_decoded, err := hex.DecodeString(_encoded)
				_len := len(_decoded)
				if err != nil {
					return err
				}
				m.Tag = utils.ByteArrayToInt8Array(_decoded[0:_len])
			case "dataType":
				var data CIPDataTypeCode
				if err := d.DecodeElement(&data, &tok); err != nil {
					return err
				}
				m.DataType = data
			case "elementNb":
				var data uint16
				if err := d.DecodeElement(&data, &tok); err != nil {
					return err
				}
				m.ElementNb = data
			case "data":
				var _encoded string
				if err := d.DecodeElement(&_encoded, &tok); err != nil {
					return err
				}
				_decoded, err := hex.DecodeString(_encoded)
				_len := len(_decoded)
				if err != nil {
					return err
				}
				m.Data = utils.ByteArrayToInt8Array(_decoded[0:_len])
			}
		}
		token, err = d.Token()
		if err != nil {
			if err == io.EOF && foundContent {
				return nil
			}
			return err
		}
	}
}

// Deprecated: the utils.WriteBufferReadBased should be used instead
func (m *CipWriteRequest) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	if err := e.EncodeElement(m.RequestPathSize, xml.StartElement{Name: xml.Name{Local: "RequestPathSize"}}); err != nil {
		return err
	}
	_encodedTag := hex.EncodeToString(utils.Int8ArrayToByteArray(m.Tag))
	_encodedTag = strings.ToUpper(_encodedTag)
	if err := e.EncodeElement(_encodedTag, xml.StartElement{Name: xml.Name{Local: "tag"}}); err != nil {
		return err
	}
	if err := e.EncodeElement(m.DataType, xml.StartElement{Name: xml.Name{Local: "dataType"}}); err != nil {
		return err
	}
	if err := e.EncodeElement(m.ElementNb, xml.StartElement{Name: xml.Name{Local: "elementNb"}}); err != nil {
		return err
	}
	_encodedData := hex.EncodeToString(utils.Int8ArrayToByteArray(m.Data))
	_encodedData = strings.ToUpper(_encodedData)
	if err := e.EncodeElement(_encodedData, xml.StartElement{Name: xml.Name{Local: "data"}}); err != nil {
		return err
	}
	return nil
}

func (m CipWriteRequest) String() string {
	return string(m.Box("", 120))
}

// Deprecated: the utils.WriteBufferBoxBased should be used instead
func (m CipWriteRequest) Box(name string, width int) utils.AsciiBox {
	boxName := "CipWriteRequest"
	if name != "" {
		boxName += "/" + name
	}
	childBoxer := func() []utils.AsciiBox {
		boxes := make([]utils.AsciiBox, 0)
		// Simple field (case simple)
		// int8 can be boxed as anything with the least amount of space
		boxes = append(boxes, utils.BoxAnything("RequestPathSize", m.RequestPathSize, -1))
		// Array Field (tag)
		if m.Tag != nil {
			// Simple array base type int8 will be rendered one by one
			arrayBoxes := make([]utils.AsciiBox, 0)
			for _, _element := range m.Tag {
				arrayBoxes = append(arrayBoxes, utils.BoxAnything("", _element, width-2))
			}
			boxes = append(boxes, utils.BoxBox("Tag", utils.AlignBoxes(arrayBoxes, width-4), 0))
		}
		// Enum field (dataType)
		dataType := CastCIPDataTypeCode(m.DataType)
		boxes = append(boxes, dataType.Box("dataType", -1))
		// Simple field (case simple)
		// uint16 can be boxed as anything with the least amount of space
		boxes = append(boxes, utils.BoxAnything("ElementNb", m.ElementNb, -1))
		// Array Field (data)
		if m.Data != nil {
			// Simple array base type int8 will be rendered one by one
			arrayBoxes := make([]utils.AsciiBox, 0)
			for _, _element := range m.Data {
				arrayBoxes = append(arrayBoxes, utils.BoxAnything("", _element, width-2))
			}
			boxes = append(boxes, utils.BoxBox("Data", utils.AlignBoxes(arrayBoxes, width-4), 0))
		}
		return boxes
	}
	return m.Parent.BoxParent(boxName, width, childBoxer)
}