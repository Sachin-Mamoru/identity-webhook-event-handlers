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

package org.wso2.identity.webhook.wso2.event.handler.internal;

/**
 * A data holder class to keep the data of the event handler component.
 */
public class WSO2EventHookHandlerDataHolder {

    private static final WSO2EventHookHandlerDataHolder instance = new WSO2EventHookHandlerDataHolder();

    private WSO2EventHookHandlerDataHolder() {
    }

    public static WSO2EventHookHandlerDataHolder getInstance() {

        return instance;
    }
}
