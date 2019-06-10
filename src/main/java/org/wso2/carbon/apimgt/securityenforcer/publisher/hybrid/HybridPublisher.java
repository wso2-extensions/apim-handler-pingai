/*
 *  Copyright WSO2 Inc.
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

import org.apache.commons.codec.digest.DigestUtils;
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
        String hashKey = DigestUtils.md5Hex(requestMetaData.toString());
        AseResponseDTO aseResponseDTO = ASEResponseStore.getFromASEResponseCache(hashKey);
        if (aseResponseDTO == null) { // sync mode
            aseResponseDTO = syncPublisher.publishSyncEvent(requestMetaData, requestCorrelationID,
                    AISecurityHandlerConstants.ASE_RESOURCE_REQUEST);
            if (aseResponseDTO != null) {
                ASEResponseStore.writeToASEResponseCache(hashKey, aseResponseDTO);
                if (log.isDebugEnabled()) {
                    log.debug(
                            "Cache updated for " + requestCorrelationID + " as  " + aseResponseDTO.getResponseMessage()
                                    + " with the response code " + aseResponseDTO.getResponseCode());
                }
                if (AISecurityHandlerConstants.ASE_RESPONSE_CODE_SUCCESS == aseResponseDTO.getResponseCode()) {
                    if (log.isDebugEnabled()) {
                        log.debug("Access granted by the Ping AI handler for the request id " + requestCorrelationID);
                    }
                    return true;
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Access revoked by the Ping AI handler for the request id " + requestCorrelationID);
                    }
                    throw new AISecurityException(AISecurityException.ACCESS_REVOKED,
                            AISecurityException.ACCESS_REVOKED_MESSAGE);
                }
            } else {
                log.error("Null response from the ASE for the request " + requestCorrelationID);
                throw new AISecurityException(AISecurityException.HANDLER_ERROR,
                        AISecurityException.HANDLER_ERROR_MESSAGE);
            }
        } else { //async mode
            if (log.isDebugEnabled()) {
                log.debug("ASE Response found for the request " + requestCorrelationID + " as " + aseResponseDTO
                        .getResponseMessage() + " with the response code " + aseResponseDTO.getResponseCode());
            }
            asyncPublisher.publishAsyncEvent(requestMetaData, requestCorrelationID,
                    AISecurityHandlerConstants.ASE_RESOURCE_REQUEST);
            if (AISecurityHandlerConstants.ASE_RESPONSE_CODE_SUCCESS == aseResponseDTO.getResponseCode()) {
                if (log.isDebugEnabled()) {
                    log.debug("Access granted by the Ping AI handler for the request id " + requestCorrelationID);
                }
                return true;
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Access revoked by the Ping AI handler for the request id " + requestCorrelationID);
                }
                throw new AISecurityException(AISecurityException.ACCESS_REVOKED,
                        AISecurityException.ACCESS_REVOKED_MESSAGE);
            }
        }
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
