/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wso2.carbon.apimgt.securityenforcer.publisher.hybrid;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.simple.JSONObject;
import org.wso2.carbon.apimgt.securityenforcer.ASEResponseStore;
import org.wso2.carbon.apimgt.securityenforcer.dto.AseResponseDTO;
import org.wso2.carbon.apimgt.securityenforcer.publisher.Publisher;
import org.wso2.carbon.apimgt.securityenforcer.publisher.async.AsyncPublisher;
import org.wso2.carbon.apimgt.securityenforcer.publisher.sync.SyncPublisher;
import org.wso2.carbon.apimgt.securityenforcer.utils.AISecurityException;
import org.wso2.carbon.apimgt.securityenforcer.utils.AISecurityHandlerConstants;
import org.wso2.carbon.apimgt.securityenforcer.utils.SecurityUtils;

public class HybridPublisher implements Publisher {

    private static final Log log = LogFactory.getLog(HybridPublisher.class);
    private AsyncPublisher asyncPublisher;
    private SyncPublisher syncPublisher;

    public HybridPublisher() {
        syncPublisher = new SyncPublisher();
        asyncPublisher = new AsyncPublisher();
        log.info("Hybrid publisher instance created for Ping AI Security Handler");
    }

    @Override
    public boolean verifyRequest(JSONObject requestMetaData, String requestCorrelationID) throws AISecurityException {

        try {
            boolean cachedASEResponseAvailable = SecurityUtils.verifyPropertiesWithCache(requestMetaData,
                    requestCorrelationID);
            if (!cachedASEResponseAvailable) {
                //A Cached response is not available for token, ip or cookie. Therefore sync mode is used
                AseResponseDTO aseResponseDTO = syncPublisher.publishSyncEvent(requestMetaData, requestCorrelationID,
                        AISecurityHandlerConstants.ASE_RESOURCE_REQUEST);
                if (aseResponseDTO != null) {
                    ASEResponseStore.updateCache(requestMetaData, aseResponseDTO, requestCorrelationID);
                    SecurityUtils.verifyASEResponse(aseResponseDTO, requestCorrelationID);
                    return true;
                } else {
                    log.error("Null response from the ASE for the request " + requestCorrelationID);
                    throw new AISecurityException(AISecurityException.HANDLER_ERROR,
                            AISecurityException.HANDLER_ERROR_MESSAGE);
                }
            } else {
                //A Cached response is available for a one of all of the properties and non of them is to block the
                // request. Async mode is used.
                asyncPublisher.publishAsyncEvent(requestMetaData, requestCorrelationID,
                        AISecurityHandlerConstants.ASE_RESOURCE_REQUEST);
            }
        } catch (AISecurityException e){
            // if cached response is to block the request, there will be an exception and cache will be updated
            // with a new async sideband call
            asyncPublisher.publishAsyncEvent(requestMetaData, requestCorrelationID,
                    AISecurityHandlerConstants.ASE_RESOURCE_REQUEST);
            throw e;
        }
        return true;
    }

    @Override
    public boolean publishResponse(JSONObject requestMetaData, String requestCorrelationID) throws AISecurityException {
        asyncPublisher.publishAsyncEvent(requestMetaData, requestCorrelationID,
                AISecurityHandlerConstants.ASE_RESOURCE_RESPONSE);
        return true;
    }

    public void setAsyncPublisher(AsyncPublisher asyncPublisher) {
        this.asyncPublisher = asyncPublisher;
    }

    public void setSyncPublisher(SyncPublisher syncPublisher) {
        this.syncPublisher = syncPublisher;
    }
}
