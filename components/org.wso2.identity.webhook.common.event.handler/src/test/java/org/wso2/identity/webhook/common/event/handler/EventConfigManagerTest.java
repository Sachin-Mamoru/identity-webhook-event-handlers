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

import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.configuration.mgt.core.model.Attribute;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resource;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resources;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.IdentityEventServerException;
import org.wso2.identity.webhook.common.event.handler.constant.Constants;
import org.wso2.identity.webhook.common.event.handler.model.EventPublisherConfig;
import org.wso2.identity.webhook.common.event.handler.util.TestUtils;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;
import static org.wso2.identity.webhook.common.event.handler.util.TestUtils.closeMockedFiles;
import static org.wso2.identity.webhook.common.event.handler.util.TestUtils.closeMockedIdentityTenantUtil;
import static org.wso2.identity.webhook.common.event.handler.util.TestUtils.closeMockedServiceURLBuilder;

/**
 * Test class for EventConfigManager.
 */
public class EventConfigManagerTest {

    private EventConfigManager eventConfigManager;

    @BeforeClass
    public void setup() throws IdentityEventServerException {

        TestUtils.mockServiceURLBuilder();
        TestUtils.mockIdentityTenantUtil();

        String fakeJsonContent = "{ \"events\": { \"validEvent\": { \"eventSchema\": " +
                "\"https://schemas.example.com/event\" } } }";
        TestUtils.mockFilesNewInputStream(fakeJsonContent);
        eventConfigManager = EventConfigManager.getInstance();
    }

    @AfterClass
    public void tearDown() {

        closeMockedServiceURLBuilder();
        closeMockedIdentityTenantUtil();
        closeMockedFiles();
    }

    @Test
    public void testGetEventUriWithValidEvent() throws IdentityEventServerException {

        String eventUri = eventConfigManager.getEventUri("validEvent");
        assertEquals(eventUri, "https://schemas.example.com/event",
                "The event URI should match the expected URI.");
    }

    @Test(dependsOnMethods = "testGetEventUriWithValidEvent", expectedExceptions = IdentityEventServerException.class)
    public void testGetEventUriWithMissingSchemaKey() throws IdentityEventServerException, NoSuchFieldException,
            IllegalAccessException {

        resetEventConfigManagerInstance();
        String invalidJsonContent = "{ \"events\": { \"validEvent\": {} } }";
        closeMockedFiles();
        TestUtils.mockFilesNewInputStream(invalidJsonContent);
        eventConfigManager = EventConfigManager.getInstance();
        eventConfigManager.getEventUri("validEvent");
    }

    @Test(expectedExceptions = IdentityEventServerException.class)
    public void testGetEventUriWithInvalidEvent() throws IdentityEventServerException {

        eventConfigManager.getEventUri("invalidEvent");
    }

    @Test
    public void testExtractEventPublisherConfig() throws IdentityEventException {

        Resources resources = createResourcesWithAttributes(Constants.EventHandlerKey.LOGIN_SUCCESS_EVENT,
                "{\"publishEnabled\":true}");
        EventPublisherConfig config = eventConfigManager.extractEventPublisherConfig(resources,
                IdentityEventConstants.EventName.AUTHENTICATION_SUCCESS.name());
        assertTrue(config.isPublishEnabled(), "Publish should be enabled.");
    }

    @Test
    public void testExtractEventPublisherConfigWithEmptyResources() throws IdentityEventException {

        Resources resources = new Resources();
        resources.setResources(new ArrayList<>());
        EventPublisherConfig config = eventConfigManager.extractEventPublisherConfig(resources,
                Constants.EventHandlerKey.LOGIN_SUCCESS_EVENT);
        assertFalse(config.isPublishEnabled(), "Publish should be disabled for empty resources.");
    }

    @Test
    public void testExtractEventPublisherConfigWithNoAttributes() throws IdentityEventException {

        Resources resources = createResourcesWithNoAttributes();
        EventPublisherConfig config = eventConfigManager.extractEventPublisherConfig(resources,
                Constants.EventHandlerKey.LOGIN_SUCCESS_EVENT);
        assertFalse(config.isPublishEnabled(), "Publish should be disabled when there are no attributes.");
    }

    /**
     * Helper method to reset the singleton instance of EventConfigManager.
     */
    private void resetEventConfigManagerInstance() throws NoSuchFieldException, IllegalAccessException {

        Field instance = EventConfigManager.class.getDeclaredField("instance");
        instance.setAccessible(true);
        instance.set(null, null);
    }

    /**
     * Helper method to create resources with attributes.
     *
     * @param eventKey       The event key for the attribute.
     * @param attributeValue The attribute value in JSON string format.
     * @return Resources object populated with attributes.
     */
    private Resources createResourcesWithAttributes(String eventKey, String attributeValue) {

        Resources resources = new Resources();
        List<Resource> resourceList = new ArrayList<>();
        Resource resource = new Resource();

        List<Attribute> attributeList = new ArrayList<>();
        Attribute attribute = new Attribute(eventKey, attributeValue);
        attributeList.add(attribute);
        resource.setAttributes(attributeList);
        resourceList.add(resource);
        resources.setResources(resourceList);
        return resources;
    }

    /**
     * Helper method to create resources without attributes.
     *
     * @return Resources object with an empty attributes list.
     */
    private Resources createResourcesWithNoAttributes() {
        Resources resources = new Resources();
        List<Resource> resourceList = new ArrayList<>();
        Resource resource = new Resource();
        resource.setAttributes(new ArrayList<>());
        resourceList.add(resource);
        resources.setResources(resourceList);
        return resources;
    }
}
