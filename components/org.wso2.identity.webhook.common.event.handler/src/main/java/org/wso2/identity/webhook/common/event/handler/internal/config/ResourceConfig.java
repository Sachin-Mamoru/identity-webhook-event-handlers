/*
 * Copyright (c) 2024-2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.identity.webhook.common.event.handler.internal.config;

import org.json.simple.JSONObject;

/**
 * A wrapper class for JSONObject to hold resource configuration properties.
 */
public class ResourceConfig {

    private JSONObject configs;

    /**
     * Constructor for Resource config .
     *
     * @param configs JSON object.
     */
    public ResourceConfig(JSONObject configs) {

        this.configs = configs;
    }

    public JSONObject getConfigs() {

        return configs;
    }

    public void setConfigs(JSONObject configs) {

        this.configs = configs;
    }
}
