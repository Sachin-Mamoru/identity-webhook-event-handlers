/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.identity.webhook.common.event.handler;

import org.mockito.Mockito;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.identity.webhook.common.event.handler.builder.LoginEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.internal.EventHookHandlerDataHolder;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertThrows;

/**
 * Test class for PayloadBuilderFactory.
 */
public class PayloadBuilderFactoryTest {

    @BeforeClass
    public void setup() {

        LoginEventPayloadBuilder mockBuilder = Mockito.mock(LoginEventPayloadBuilder.class);
        Mockito.when(mockBuilder.getEventSchemaType()).thenReturn("WSO2");

        EventHookHandlerDataHolder.getInstance().addLoginEventPayloadBuilder(mockBuilder);
    }

    @Test
    public void testGetLoginEventPayloadBuilder() {

        LoginEventPayloadBuilder builder = PayloadBuilderFactory.getLoginEventPayloadBuilder("WSO2");
        assertEquals(builder.getEventSchemaType(), "WSO2", "The schema type should match 'WSO2'.");
    }

    @Test
    public void testGetLoginEventPayloadBuilderUnknownSchema() {

        assertThrows(IllegalArgumentException.class,
                () -> PayloadBuilderFactory.getLoginEventPayloadBuilder("UnknownSchema"));
    }
}
