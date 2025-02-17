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

#ifndef _PLC_PROPRIETARY_REQUEST
#define _PLC_PROPRIETARY_REQUEST

#include <org/apache/plc4x/cpp/api/messages/REQUEST.h>
#include <org/apache/plc4x/cpp/api/messages/PlcRequest.h>
#include <org/apache/plc4x/cpp/api//messages/RequestTemplate.h>

using namespace org::apache::plc4x::cpp::api::messages;

namespace org
{
	namespace apache
	{
		namespace plc4x
		{
			namespace cpp
			{
				namespace base
				{
					namespace messages
					{
						
						class PlcProprietaryRequest : public PlcRequest, public RequestTemplate<REQUEST>
						{
						public:
							virtual REQUEST getProprietaryRequest() = 0;
						};
					}
				}
			}
		}
	}
}

#endif