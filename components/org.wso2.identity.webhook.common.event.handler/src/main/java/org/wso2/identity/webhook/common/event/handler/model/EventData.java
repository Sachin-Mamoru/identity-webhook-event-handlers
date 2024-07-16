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

package org.wso2.identity.webhook.common.event.handler.model;

import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorStatus;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.User;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

/**
 * Event data model.
 */
public class EventData {

    private final String eventName;
    private final HttpServletRequest request;
    private final Map<String, Object> eventParams;
    private final AuthenticationContext authenticationContext;
    private final AuthenticatorStatus authenticatorStatus;
    private final AuthenticatedUser authenticatedUser;
    private final User loginIdentifier;

    private EventData(Builder builder) {
        this.eventName = builder.eventName;
        this.request = builder.request;
        this.eventParams = builder.eventParams;
        this.authenticationContext = builder.authenticationContext;
        this.authenticatorStatus = builder.authenticatorStatus;
        this.authenticatedUser = builder.authenticatedUser;
        this.loginIdentifier = builder.loginIdentifier;
    }

    public String getEventName() {
        return eventName;
    }
    public HttpServletRequest getRequest() {
        return request;
    }

    public Map<String, Object> getEventParams() {
        return eventParams;
    }

    public AuthenticationContext getAuthenticationContext() {
        return authenticationContext;
    }

    public AuthenticatorStatus getAuthenticatorStatus() {
        return authenticatorStatus;
    }

    public AuthenticatedUser getAuthenticatedUser() {
        return authenticatedUser;
    }

    public User getLoginIdentifier() {
        return loginIdentifier;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String eventName;
        private HttpServletRequest request;
        private Map<String, Object> eventParams;
        private AuthenticationContext authenticationContext;
        private AuthenticatorStatus authenticatorStatus;
        private AuthenticatedUser authenticatedUser;
        private User loginIdentifier;
        public Builder eventName(String eventName) {
            this.eventName = eventName;
            return this;
        }

        public Builder request(HttpServletRequest request) {
            this.request = request;
            return this;
        }

        public Builder eventParams(Map<String, Object> eventParams) {
            this.eventParams = eventParams;
            return this;
        }

        public Builder authenticationContext(AuthenticationContext authenticationContext) {
            this.authenticationContext = authenticationContext;
            return this;
        }

        public Builder authenticatorStatus(AuthenticatorStatus authenticatorStatus) {
            this.authenticatorStatus = authenticatorStatus;
            return this;
        }

        public Builder authenticatedUser(AuthenticatedUser authenticatedUser) {
            this.authenticatedUser = authenticatedUser;
            return this;
        }

        public Builder loginIdentifier(User loginIdentifier) {
            this.loginIdentifier = loginIdentifier;
            return this;
        }

        public EventData build() {
            return new EventData(this);
        }
    }
}

