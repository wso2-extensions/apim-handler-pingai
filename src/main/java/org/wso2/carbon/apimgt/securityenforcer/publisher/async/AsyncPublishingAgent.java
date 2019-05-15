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

package org.wso2.carbon.apimgt.securityenforcer.publisher.async;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.simple.JSONObject;
import org.wso2.carbon.apimgt.securityenforcer.ASEResponseStore;
import org.wso2.carbon.apimgt.securityenforcer.dto.AseResponseDTO;
import org.wso2.carbon.apimgt.securityenforcer.internal.ServiceReferenceHolder;
import org.wso2.carbon.apimgt.securityenforcer.publisher.HttpDataPublisher;
import org.wso2.carbon.apimgt.securityenforcer.utils.AISecurityHandlerConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

/**
 * This class is responsible for executing data publishing logic. This class implements runnable interface and
 * need to execute using thread pool executor. Primary task of this class it is accept message context as parameter
 * and perform time consuming data extraction and verifyRequest event to data publisher. Having data extraction and
 * transformation logic in this class will help to reduce overhead added to main message flow.
 */
public class AsyncPublishingAgent implements Runnable {

    private static final Log log = LogFactory.getLog(AsyncPublishingAgent.class);

    private HttpDataPublisher httpDataPublisher;
    private JSONObject requestBody;
    private String correlationID;
    private String resource;
    private boolean tenantFlowStarted = false;

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
        AseResponseDTO aseResponseDTO = httpDataPublisher.publish(this.requestBody, this.correlationID, this.resource);
        String hashKey = DigestUtils.md5Hex(requestBody.toString());
        if (aseResponseDTO != null) {
            if (AISecurityHandlerConstants.ASE_RESOURCE_REQUEST.equals(this.resource)) {
                try {
                    startTenantFlow();
                    ASEResponseStore.writeToASEResponseCache(hashKey, aseResponseDTO);
                    if (log.isDebugEnabled()) {
                        log.debug("Cache updated for " + this.correlationID + " as  " + aseResponseDTO
                                .getResponseMessage() + " with the response code " + aseResponseDTO.getResponseCode());
                    }
                } finally {
                    if (tenantFlowStarted) {
                        endTenantFlow();
                    }
                }
            }
        } else {
            log.error("ASE response is null for the async request " + this.correlationID);
        }
    }

    private HttpDataPublisher getHttpDataPublisher() {

        return ServiceReferenceHolder.getInstance().getHttpDataPublisher();
    }

    private void endTenantFlow() {
        PrivilegedCarbonContext.endTenantFlow();
    }

    private void startTenantFlow() {
        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().
                setTenantDomain(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME, true);
        tenantFlowStarted = true;
    }

}

