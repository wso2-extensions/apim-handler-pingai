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

package org.wso2.carbon.apimgt.securityenforcer.publisher.async;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.simple.JSONObject;
import org.wso2.carbon.apimgt.securityenforcer.ASEResponseStore;
import org.wso2.carbon.apimgt.securityenforcer.dto.AISecurityHandlerConfig;
import org.wso2.carbon.apimgt.securityenforcer.dto.AseResponseDTO;
import org.wso2.carbon.apimgt.securityenforcer.internal.ServiceReferenceHolder;
import org.wso2.carbon.apimgt.securityenforcer.publisher.Publisher;
import org.wso2.carbon.apimgt.securityenforcer.utils.AISecurityException;
import org.wso2.carbon.apimgt.securityenforcer.utils.AISecurityHandlerConstants;

import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

public class AsyncPublisher implements Publisher {

    private static final Log log = LogFactory.getLog(AsyncPublisher.class);

    private static AsyncPublisherThreadPool asyncPublisherThreadPool;
    private ThreadPoolExecutor asyncExecutor;

    /**
     * This method will initialize DataPublisher. Inside this we will start executor and initialize
     * httpDataPublisher which we use to connect and verifyRequest data for analyse.
     */
    public AsyncPublisher() {
        AISecurityHandlerConfig.ThreadPoolExecutorConfig threadPoolExecutorConfig = ServiceReferenceHolder.getInstance()
                .getSecurityHandlerConfig().getThreadPoolExecutorConfig();
        asyncPublisherThreadPool = AsyncPublisherThreadPool.getInstance();
        asyncExecutor = new AsyncPublisherThreadPoolExecutor(threadPoolExecutorConfig.getCorePoolSize(),
                threadPoolExecutorConfig.getMaximumPoolSize(), threadPoolExecutorConfig.getKeepAliveTime(),
                TimeUnit.SECONDS, new LinkedBlockingDeque<Runnable>() {

        });
        log.info("Async publisher instance created for Ping AI Security Handler");
    }

    /**
     * This method used to pass requestBody and let it run within separate asynchronous thread.
     *
     * @param requestBody    is the json with the extracted details of the original request.
     * @param correlationID is the String with the xCorrelation ID.
     * @param resource       is the targeted resource of the ASE Instance. It can be either request or response
     */
    public void publishAsyncEvent(JSONObject requestBody, String correlationID, String resource)
            throws AISecurityException {
        if (asyncPublisherThreadPool != null) {
            AsyncPublishingAgent agent;
            try {
                agent = asyncPublisherThreadPool.get();
            } catch (Exception e) {
                log.error("Error when borrowing an agent from asyncPublisherThreadPool", e);
                throw new AISecurityException(AISecurityException.HANDLER_ERROR,
                        AISecurityException.HANDLER_ERROR_MESSAGE, e);
            }
            agent.setDataReference(requestBody, correlationID, resource);
            if (log.isDebugEnabled()) {
                log.debug("Async call executed for the " + resource + " id " + correlationID);
            }
            asyncExecutor.execute(agent);
        } else {
            log.error("AsyncPublisherThreadPool not initialized");
            throw new AISecurityException(AISecurityException.HANDLER_ERROR, AISecurityException.HANDLER_ERROR_MESSAGE);
        }
    }

    @Override
    public boolean verifyRequest(JSONObject requestMetaData, String requestCorrelationID) throws AISecurityException {
        publishAsyncEvent(requestMetaData, requestCorrelationID, AISecurityHandlerConstants.ASE_RESOURCE_REQUEST);
        String hashKey = DigestUtils.md5Hex(requestMetaData.toString());
        AseResponseDTO aseResponseDTO = ASEResponseStore.getFromASEResponseCache(hashKey);

        if (aseResponseDTO == null) {
            if (log.isDebugEnabled()) {
                log.debug("Cached ASE response is not found for the request " + requestCorrelationID);
            }
            return true;
        } else {
            if (log.isDebugEnabled()) {
                log.debug("ASE Response found for the request " + requestCorrelationID + " with metadata "
                        + requestMetaData.toString() + " as " + aseResponseDTO.getResponseMessage()
                        + " with the response code " + aseResponseDTO.getResponseCode());
            }

            if (AISecurityHandlerConstants.ASE_RESPONSE_CODE_FORBIDDEN == aseResponseDTO.getResponseCode()) {
                if (log.isDebugEnabled()) {
                    log.debug("Access revoked by the Ping AI handler for the request id " + requestCorrelationID);
                }
                throw new AISecurityException(AISecurityException.ACCESS_REVOKED,
                        AISecurityException.ACCESS_REVOKED_MESSAGE);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Access granted by the Ping AI handler for the request id " + requestCorrelationID);
                }
                return true;
            }
        }
    }

    @Override
    public boolean publishResponse(JSONObject requestMetaData, String requestCorrelationID) throws AISecurityException {
        publishAsyncEvent(requestMetaData, requestCorrelationID, AISecurityHandlerConstants.ASE_RESOURCE_RESPONSE);
        return true;
    }

    /**
     * This class will act as thread pool executor and after executing each thread it will return runnable
     * object back to pool. This implementation specifically used to minimize number of objects created during
     * runtime. In this queuing strategy the submitted task will wait in the queue if the core Pool size threads are
     * busy and the task will be allocated if any of the threads become idle.Thus ThreadPool will always have number
     * of threads running  as mentioned in the corePoolSize.
     * LinkedBlockingQueue without the capacity can be used for this queuing strategy.If the corePoolsize of the
     * thread pool is less and there are more number of time consuming task were submitted,there is more possibility
     * that the task has to wait in the queue for more time before it is run by any of the ideal thread.
     * So tuning core pool size is something we need to tune properly.
     * Also no task will be rejected in Thread pool until the thread pool was shutdown.
     */

    private class AsyncPublisherThreadPoolExecutor extends ThreadPoolExecutor {

        AsyncPublisherThreadPoolExecutor(int corePoolSize, int maximumPoolSize, long keepAliveTime, TimeUnit unit,
                LinkedBlockingDeque<Runnable> workQueue) {
            super(corePoolSize, maximumPoolSize, keepAliveTime, unit, workQueue);
        }

        protected void afterExecute(java.lang.Runnable r, java.lang.Throwable t) {
            try {
                AsyncPublishingAgent agent = (AsyncPublishingAgent) r;
                asyncPublisherThreadPool.release(agent);
            } catch (Exception e) {
                log.error("Error while returning Ping AI data publishing agent back to pool", e);
            }
        }
    }
}
