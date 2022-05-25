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

//////////////////////////////////////////////////////////////////
///EthernetIP Header of size 24
/////////////////////////////////////////////////////////////////

[discriminatedType EipPacket byteOrder='LITTLE_ENDIAN'
    [discriminator uint 16 command]
    [implicit      uint 16 len 'lengthInBytes - 24']
    [simple        uint 32 sessionHandle]
    [simple        uint 32 status]
    [array         uint 8  senderContext count '8']
    [simple        uint 32 options]
    [typeSwitch command
            ['0x0065' EipConnectionRequest
                [const      uint    16   protocolVersion   0x01]
                [const      uint    16   flags             0x00]
            ]
            ['0x0066' EipDisconnectRequest
            ]
            ['0x006F' CipRRData(uint 16 len)
                [reserved   uint    32    '0x00000000']
                [simple     uint    16    timeout]
                [simple     uint    16    itemCount]
                [simple    CipExchange('len - 6')   exchange]
            ]
        ]
]

[type  CipExchange (uint 16 exchangeLen)  //We pass then length down to evey sub-type to be able to provide the remaining data size
    [const          uint 32                         nullPtr             0x0                   ]  //NullPointerAddress
    [const          uint 16                         unconnectedData     0x00B2                ]  //Connection Manager
    [implicit       uint 16                         size                'lengthInBytes - 8 - 2' ]  //remove fields above and routing
    [simple         CipService('exchangeLen - 10')  service                                     ]
]

[discriminatedType  CipService(uint 16 serviceLen)
    [discriminator  bit     response]
    [discriminator  uint    7   service]
    [typeSwitch service,response
        ['0x4C','false' CipReadRequest
            [simple     int     8   requestPathSize]
            [array      byte   tag   length  '(requestPathSize * 2)']
            [simple     uint    16  elementNb]
        ]
        ['0x4C','true' CipReadResponse
              [reserved   uint            8   '0x00']
              [simple     uint            8   status]
              [simple     uint            8   extStatus]
              [simple     CIPDataTypeCode     dataType]
              [array      byte   data  count  'serviceLen - 6']
        ]
        ['0x4D','false' CipWriteRequest
            [simple     int     8           requestPathSize]
            [array      byte           tag   length  'requestPathSize * 2']
            [simple     CIPDataTypeCode     dataType]
            [simple     uint    16          elementNb]
            [array      byte            data  length  'dataType.size * elementNb']
        ]
        ['0x4D','true' CipWriteResponse
            [reserved   uint        8   '0x00']
            [simple     uint        8   status]
            [simple     uint        8   extStatus]
        ]
        ['0x0A','false' MultipleServiceRequest
               [const  int     8   requestPathSize   0x02]
               [const  uint    32  requestPath       0x01240220]   //Logical Segment: Class(0x20) 0x02, Instance(0x24) 01 (Message Router)
               [simple Services('serviceLen - 6 ')  data ]
        ]
        ['0x0A','true' MultipleServiceResponse
               [reserved   uint    8   '0x0']
               [simple     uint    8   status]
               [simple     uint    8   extStatus]
               [simple     uint    16  serviceNb]
               [array      uint    16  offsets       count  'serviceNb']
               [array      byte   servicesData count 'serviceLen - 6 - (2 * serviceNb)']
        ]
        ['0x52','false'   CipUnconnectedRequest
               [simple     uint    8    requestPathSize ]
               [simple     PathSegment  pathSegment0]
        ]
        ['0x5B','false'     CipConnectionManagerRequest
               [simple      int     8           requestPathSize]
               [simple      ClassSegment        classSegment]
               [simple      InstanceSegment     instanceSegment]
               [simple      uint    4           priority]
               [simple      uint    4           tickTime]
               [simple      uint    8           timeoutTicks]
               [simple      uint    16          actualTimeout]
               [simple      uint    32          otConnectionId]
               [simple      uint    32          toConnectionId]
               [simple      uint    16          connectionSerialNumber]
               [simple      uint    16          originatorVendorId]
               [simple      uint    32          originatorSerialNumber]
               [simple      uint    8           timeoutMultiplier]
               [reserved    uint    24          '0x000000']
               [simple      uint    32          otRpi]
               [simple      NetworkConnectionParameters otConnectionParameters]
               [simple      uint    32          toRpi]
               [simple      NetworkConnectionParameters toConnectionParameters]
               [simple      TransportType       transportType]
               [simple      uint    8           connectionPathSize]
               [simple      PortSegment         portSegment]

        ]
        ['0x5B','true'     CipConnectionManagerResponse
               [simple      uint    32          otConnectionId]
               [simple      uint    32          toConnectionId]
               [simple      uint    16          connectionSerialNumber]
               [simple      uint    16          originatorVendorId]
               [simple      uint    32          originatorSerialNumber]
               [simple      uint    32          otApi]
               [simple      uint    32          toApi]
               [implicit    uint    8           replySize   'serviceLen - 46']
               [reserved    uint    8           '0x00']
        ]
    ]
]

[discriminatedType PathSegment
    [discriminator  uint    3   pathSegment]
    [discriminator  uint    5   dataSegment]
    [typeSwitch pathSegment,dataSegment
        ['0x04','0x11'      AnsiExtendedSymbolSegment
            [implicit   uint    8   dataSize    'symbol.length']
            [simple     vstring 'dataSize'  symbol]
        ]
    ]
]

[type   InstanceSegment
    [simple     uint    3   pathSegmentType]
    [simple     uint    3   logicalSegmentType]
    [simple     uint    2   logicalSegmentFormat]
    [simple     uint    8   instance]
]

[type   ClassSegment
    [simple     uint    3   pathSegmentType]
    [simple     uint    3   logicalSegmentType]
    [simple     uint    2   logicalSegmentFormat]
    [simple     uint    8   classSegment]
]

[type   PortSegment
    [simple     uint    3   portSegmentType]
    [simple     bit         extendedLinkAddress]
    [simple     uint    4   port]
    [simple     uint    8   linkAddress]
]

[type   NetworkConnectionParameters
   [simple      bit         owner]
   [simple      uint    2   connectionType]
   [simple      uint    2   priority]
   [simple      bit         connectionSizeType]
   [simple      uint    16  connectionSize]
]

[type   TransportType
   [simple      bit         direction]
   [simple      uint    3   trigger]
   [simple      uint    4   classTransport]
]

[type   Services  (uint   16   servicesLen)
    [simple uint        16  serviceNb]
    [array  uint        16  offsets       count  'serviceNb']
    [array  CipService('servicesLen / serviceNb')   services    count  'serviceNb' ]
]

[enum uint   16   CIPDataTypeCode(uint 8  size)
    ['0X00C1'   BOOL            ['1']]
    ['0X00C2'   SINT            ['1']]
    ['0X00C3'   INT             ['2']]
    ['0X00C4'   DINT            ['4']]
    ['0X00C5'   LINT            ['8']]
    ['0X00CA'   REAL            ['4']]
    ['0X00D3'   DWORD           ['4']]
    ['0X02A0'   STRUCTURED      ['88']]
    ['0X02A0'   STRING          ['88']]
    ['0X02A0'   STRING36        ['40']]
    //TODO: -1 is not a valid value for uint
    //['-1'       UNKNOWN         ['-1']]
]

[enum   uint    16  EiPCommand
    ['0x0065'   RegisterSession ]
    ['0x0066'   UnregisterSession ]
    ['0x006F'   SendRRData ]
]