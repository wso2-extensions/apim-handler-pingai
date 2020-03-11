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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.simple.JSONObject;
import org.wso2.carbon.apimgt.securityenforcer.ASEResponseStore;
import org.wso2.carbon.apimgt.securityenforcer.dto.AseResponseDTO;
import org.wso2.carbon.apimgt.securityenforcer.internal.ServiceReferenceHolder;
import org.wso2.carbon.apimgt.securityenforcer.publisher.HttpDataPublisher;
import org.wso2.carbon.apimgt.securityenforcer.utils.AISecurityException;
import org.wso2.carbon.apimgt.securityenforcer.utils.AISecurityHandlerConstants;
import org.wso2.carbon.apimgt.securityenforcer.utils.SecurityUtils;
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
    private String tenantDomain;

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
        this.tenantDomain = null;
    }

    /**
     * This method will use to set message context.
     */
    void setDataReference(JSONObject requestBody, String correlationID, String resource, String tenantDomain) {

        this.requestBody = requestBody;
        this.correlationID = correlationID;
        this.resource = resource;
        this.tenantDomain = tenantDomain;

    }

    public void run() {

        JSONObject asePayload = (JSONObject) this.requestBody.get(AISecurityHandlerConstants.ASE_PAYLOAD_KEY_NAME);
        AseResponseDTO aseResponseDTO = httpDataPublisher.publish(asePayload, this.correlationID, this.resource);
        if (aseResponseDTO != null) {
            if (AISecurityHandlerConstants.ASE_RESOURCE_REQUEST.equals(this.resource)) {
                String operationMode = ServiceReferenceHolder.getInstance().getSecurityHandlerConfig().getMode();
                startTenantFlow();
                if (AISecurityHandlerConstants.ASYNC_MODE_STRING.equals(operationMode)){
                    try {
                        SecurityUtils.verifyASEResponse(aseResponseDTO, correlationID);
                        SecurityUtils.verifyPropertiesWithCache(requestBody, correlationID);
                    } catch (AISecurityException e) {
                        //In Async mode, only a blacklist will be maintained.
                        ASEResponseStore.updateCache(requestBody, aseResponseDTO, correlationID);
                    }
                } else {
                    //In Hybrid mode, both black and white lists will be maintained
                    ASEResponseStore.updateCache(requestBody, aseResponseDTO, correlationID);
                }
                if (tenantFlowStarted) {
                    endTenantFlow();
                }
            }
        } else {
            log.error("ASE response is null for the handle " + this.resource + " async request " + this.correlationID);
        }
    }

    private HttpDataPublisher getHttpDataPublisher() {

        return ServiceReferenceHolder.getInstance().getHttpDataPublisher();
    }

    private void endTenantFlow() {
        PrivilegedCarbonContext.endTenantFlow();
    }

    private void startTenantFlow() {
        if (this.tenantDomain == null){
            this.tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }
        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(tenantDomain, true);
        tenantFlowStarted = true;
    }
}

