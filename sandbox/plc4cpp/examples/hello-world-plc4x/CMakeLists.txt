#[[
  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

      https://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing,
  software distributed under the License is distributed on an
  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  KIND, either express or implied.  See the License for the
  specific language governing permissions and limitations
  under the License.
]]

add_executable(helloplc4x
                src/main/cpp/org/apache/plc4x/cpp/examples/helloplc4x/helloplc4x.cpp)

target_include_directories (helloplc4x PUBLIC ${Boost_INCLUDE_DIRS})
target_include_directories (helloplc4x PUBLIC ../../api/src/main/cpp)
target_include_directories (helloplc4x PUBLIC ../../utils/logger/src/main/cpp)

target_link_libraries (helloplc4x ${Boost_LIBRARIES} plc4cpp-driver-s7 plc4cpp-utils-logger plc4cpp-api)
