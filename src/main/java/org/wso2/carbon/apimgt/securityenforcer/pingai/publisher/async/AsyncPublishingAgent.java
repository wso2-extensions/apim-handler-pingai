/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
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
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.apimgt.securityenforcer.pingai.publisher.async;

import org.json.simple.JSONObject;
import org.wso2.carbon.apimgt.securityenforcer.pingai.internal.ServiceReferenceHolder;
import org.wso2.carbon.apimgt.securityenforcer.pingai.publisher.HttpDataPublisher;

/**
 * This class is responsible for executing data publishing logic. This class implements runnable interface and
 * need to execute using thread pool executor. Primary task of this class it is accept message context as parameter
 * and perform time consuming data extraction and verifyRequest event to data publisher. Having data extraction and
 * transformation logic in this class will help to reduce overhead added to main message flow.
 */
public class AsyncPublishingAgent implements Runnable {

    private HttpDataPublisher httpDataPublisher;
    private JSONObject requestBody;
    private String correlationID;
    private String resource;

    AsyncPublishingAgent() {

        httpDataPublisher = getHttpDataPublisher();
    }

    /**
     * This method will clean data references. This method should call whenever we return data process and verifyRequest
     * agent back to pool. Every time when we add new property we need to implement cleaning logic as well.
     */
    void clearDataReference() {

        this.requestBody = null;
        this.correlationID = null;
        this.resource = null;
    }

    /**
     * This method will use to set message context.
     */
    void setDataReference(JSONObject requestBody, String correlationID, String resource) {

        this.requestBody = requestBody;
        this.correlationID = correlationID;
        this.resource = resource;

    }

    public void run() {

        httpDataPublisher.publish(this.requestBody, this.correlationID, this.resource);
    }

    private HttpDataPublisher getHttpDataPublisher() {

        return ServiceReferenceHolder.getInstance().getHttpDataPublisher();
    }
}

