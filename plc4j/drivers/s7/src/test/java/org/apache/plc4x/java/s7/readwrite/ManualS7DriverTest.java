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
package org.apache.plc4x.java.s7.readwrite;

import org.apache.plc4x.test.manual.ManualTest;

import java.util.Arrays;

public class ManualS7DriverTest extends ManualTest {

    /*
     * Test program code on the PLC with the test-data.
     *
     * Located in "main"
     *

    hurz_BOOL  := TRUE;
	hurz_BYTE  := 42;
	hurz_WORD  := 42424;
	hurz_DWORD := 4242442424;
	hurz_LWORD := 4242442424242424242;
	hurz_SINT  := -42;
	hurz_USINT := 42;
	hurz_INT   := -2424;
	hurz_UINT  := 42424;
	hurz_DINT  := -242442424;
	hurz_UDINT := 4242442424;
	hurz_LINT  := -4242442424242424242;
	hurz_ULINT := 4242442424242424242;
	hurz_REAL  := 3.14159265359;
	hurz_LREAL := 2.71828182846;
	hurz_TIME  := T#1S234MS;
	hurz_LTIME := LTIME#1000D15H23M12S34MS2US44NS;
	hurz_DATE  := D#1998-03-28;
	//hurz_LDATE:LDATE;
	hurz_TIME_OF_DAY 	:= TIME_OF_DAY#15:36:30.123;
	hurz_TOD         	:= TOD#16:17:18.123;
	//hurz_LTIME_OF_DAY:LTIME_OF_DAY;
	//hurz_LTOD:LTOD;
	hurz_DATE_AND_TIME 	:= DATE_AND_TIME#1996-05-06-15:36:30;
	hurz_DT				:= DT#1972-03-29-00:00:00;
	//hurz_LDATE_AND_TIME:LDATE_AND_TIME;
	//hurz_LDT:LDT;
	hurz_STRING			:= 'hurz';
	hurz_WSTRING		:= "wolf";

     *
     */

    public ManualS7DriverTest(String connectionString) {
        super(connectionString);
    }

    public static void main(String[] args) throws Exception {
        ManualS7DriverTest test = new ManualS7DriverTest("s7://192.168.23.30");
        test.addTestCase("%DB4:0.0:BOOL", true);
        test.addTestCase("%DB4:1:BYTE", Arrays.asList(false, false, true, false, true, false, true, false));
        test.addTestCase("%DB4:2:WORD", Arrays.asList(true, false, true, false, false, true, false, true, true, false, true, true, true, false, false, false));
        test.addTestCase("%DB4:4:DWORD", Arrays.asList(true, true, true, true, true, true, false, false, true, true, false, true, true, true, true, false, true, false, false, false, true, false, false, false, true, false, true, true, true, false, false, false));
        test.addTestCase("%DB4:16:SINT", -42);
        test.addTestCase("%DB4:17:USINT", 42);
        test.addTestCase("%DB4:18:INT", -2424);
        test.addTestCase("%DB4:20:UINT", 42424);
        test.addTestCase("%DB4:22:DINT", -242442424);
        test.addTestCase("%DB4:26:UDINT", 4242442424L);
        // Not supported in S7 1200
        //test.addTestCase("%DB4:30:LINT", -4242442424242424242L);
        // Not supported in S7 1200
        //test.addTestCase("%DB4:38:ULINT", 4242442424242424242L);
        test.addTestCase("%DB4:46:REAL", 3.141593F);
        // Not supported in S7 1200
        //test.addTestCase("%DB4:50:LREAL", 2.71828182846D);
        test.addTestCase("%DB4:58:TIME", "PT1.234S");
        // Not supported in S7 1200
        //test.addTestCase("%DB4:62:LTIME", "PT24015H23M12.034002044S");
        test.addTestCase("%DB4:70:DATE", "1998-03-28");
        test.addTestCase("%DB4:72:TIME_OF_DAY", "15:36:30.123");
        test.addTestCase("%DB4:76:TOD", "16:17:18.123");
        // Not supported in S7 1200
        //test.addTestCase("%DB4:96:DATE_AND_TIME", "1996-05-06T15:36:30");
        // Not supported in S7 1200
        //test.addTestCase("%DB4:104:DT", "1992-03-29T00:00");
        // Not supported in S7 1200
        //test.addTestCase("%DB4:112:LDATE_AND_TIME", "1978-03-28T15:36:30");
        // Not supported in S7 1200
        //test.addTestCase("%DB4:124:LDT", "1978-03-28T15:36:30");
        test.addTestCase("%DB4:136:CHAR", "H");
        test.addTestCase("%DB4:138:WCHAR", "w");
        test.addTestCase("%DB4:140:STRING(10)", "hurz");
        test.addTestCase("%DB4:396:WSTRING(10)", "wolf");
        test.run();
    }

}
