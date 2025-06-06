/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.identity.webhook.caep.event.handler.internal.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Map;

/**
 * This class represents the payload for session presented events in CAEP.
 */

public class CAEPSessionPresentedEventPayload extends CAEPBaseEventPayload {

    private CAEPSessionPresentedEventPayload(Builder builder) {

        this.initiatingEntity = builder.initiatingEntity;
        this.eventTimeStamp = builder.eventTimeStamp;
        this.reasonAdmin = builder.reasonAdmin;
        this.reasonUser = builder.reasonUser;
        this.ips = builder.ips;
        this.fpUa = builder.fpUa;
        this.extId = builder.extId;
    }

    private final List<String> ips;

    @JsonProperty("fp_ua")
    private final String fpUa;
    @JsonProperty("ext_id")
    private final String extId;

    public String getExtId() {

        return extId;
    }

    public String getFpUa() {

        return fpUa;
    }

    public List<String> getIps() {

        return ips;
    }

    /*
     * Builder class to create CAEPSessionEstablishedAndPresentedEventPayload instances.
     */
    public static class Builder {

        private long eventTimeStamp;
        private String initiatingEntity;
        private Map<String, String> reasonAdmin;
        private Map<String, String> reasonUser;
        private List<String> ips;
        private String fpUa;
        private String extId;

        public Builder eventTimeStamp(long eventTimeStamp) {

            this.eventTimeStamp = eventTimeStamp;
            return this;
        }

        public Builder initiatingEntity(String initiatingEntity) {

            this.initiatingEntity = initiatingEntity;
            return this;
        }

        public Builder reasonAdmin(Map<String, String> reasonAdmin) {

            this.reasonAdmin = reasonAdmin;
            return this;
        }

        public Builder reasonUser(Map<String, String> reasonUser) {

            this.reasonUser = reasonUser;
            return this;
        }

        public Builder ips(List<String> ips) {

            this.ips = ips;
            return this;
        }

        public Builder fpUa(String fpUa) {

            this.fpUa = fpUa;
            return this;
        }

        public Builder extId(String extId) {

            this.extId = extId;
            return this;
        }

        public CAEPSessionPresentedEventPayload build() {

            return new CAEPSessionPresentedEventPayload(this);
        }
    }
}
