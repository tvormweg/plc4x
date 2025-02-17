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

#ifndef _PLC_FIELD_RESPONSE
#define _PLC_FIELD_RESPONSE

#include "PlcResponse.h"
#include "../types/PlcResponseCode.h"
#include "../model/PlcField.h"

#include <string>
#include <vector>

using namespace org::apache::plc4x::cpp::api::model;
using namespace org::apache::plc4x::cpp::api::types;

namespace org
{
	namespace apache
	{
		namespace plc4x
		{
			namespace cpp
			{
				namespace api
				{
					namespace messages
					{
						/**
						 * Base type for all response messages sent as response for a prior request
						 * from a plc to the plc4x system.
						 */
						class PlcFieldResponse : public PlcResponse
						{
							public:	
								virtual std::vector<std::string>* getFieldNames() = 0;
								virtual PlcField* getField(std::string& strName) = 0;
								virtual PlcResponseCode* getresponseCode(std::string& strName) = 0;
								virtual PlcRequest* getRequest() = 0;

							private:
						};
					}
				}
			}
		}
	}
}

#endif

