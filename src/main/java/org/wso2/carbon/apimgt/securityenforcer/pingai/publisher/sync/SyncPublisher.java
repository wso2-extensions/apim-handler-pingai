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

package org.wso2.carbon.apimgt.securityenforcer.pingai.publisher.sync;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.simple.JSONObject;
import org.wso2.carbon.apimgt.securityenforcer.pingai.dto.AISecurityHandlerConfig;
import org.wso2.carbon.apimgt.securityenforcer.pingai.internal.ServiceReferenceHolder;
import org.wso2.carbon.apimgt.securityenforcer.pingai.utils.AISecurityException;
import org.wso2.carbon.apimgt.securityenforcer.pingai.utils.AISecurityHandlerConstants;
import org.wso2.carbon.apimgt.securityenforcer.pingai.utils.SecurityUtils;
import org.wso2.carbon.apimgt.securityenforcer.pingai.publisher.Publisher;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

public class SyncPublisher implements Publisher {

    private static final Log log = LogFactory.getLog(SyncPublisher.class);

    private static SyncPublisherThreadPool syncPublisherThreadPool;
    private ThreadPoolExecutor syncExecutor;

    /**
     * This method will initialize DataPublisher. Inside this we will start executor and initialize
     * httpDataPublisher which we use to connect and verifyRequest data for analyse.
     */
    public SyncPublisher() {

        AISecurityHandlerConfig.ThreadPoolExecutorConfig threadPoolExecutorConfig = ServiceReferenceHolder.getInstance()
                .getSecurityHandlerConfig().getThreadPoolExecutorConfig();
        syncPublisherThreadPool = SyncPublisherThreadPool.getInstance();
        syncExecutor = new SyncPublisherThreadPoolExecutor(threadPoolExecutorConfig.getCorePoolSize(),
                threadPoolExecutorConfig.getMaximumPoolSize(), threadPoolExecutorConfig.getKeepAliveTime(),
                TimeUnit.SECONDS, new LinkedBlockingDeque<Runnable>() {

        });
        log.info("Sync publisher instance created for Ping AI Security Handler");
    }

    /**
     * This method used to pass requestBody and let it run within separate synchronous thread.
     *
     * @param requestBody   is the json with the extracted details of the original request.
     * @param correlationID is the String with the xCorrelation ID.
     * @param resource      is the targeted resource of the ASE Instance. It can be either request or response
     */
    public int publishSyncEvent(JSONObject requestBody, String correlationID, String resource)
            throws AISecurityException {

        int response = 0;
        if (syncPublisherThreadPool != null) {
            SyncPublishingAgent agent;
            try {
                agent = syncPublisherThreadPool.get();
            } catch (Exception e) {
                log.error("Error borrowing an agent from client pool for the request id " + correlationID, e);
                throw new AISecurityException(AISecurityException.HANDLER_ERROR,
                        AISecurityException.HANDLER_ERROR_MESSAGE, e);
            }
            agent.setDataReference(requestBody, correlationID, resource);
            Future<Integer> result = syncExecutor.submit(agent);
            if (log.isDebugEnabled()) {
                log.debug("Sync call executed for the " + resource + " id " + correlationID);
            }
            try {
                response = result.get();
            } catch (InterruptedException | ExecutionException e) {
                log.error("Error getting result from the callable response for the request id " + correlationID, e);
                throw new AISecurityException(AISecurityException.HANDLER_ERROR,
                        AISecurityException.HANDLER_ERROR_MESSAGE, e);
            }
            syncPublisherThreadPool.release(agent);

        } else {
            log.error("No instance found for SyncPublisherThreadPool for the request " + correlationID);
            throw new AISecurityException(AISecurityException.HANDLER_ERROR, AISecurityException.HANDLER_ERROR_MESSAGE);
        }
        return response;
    }

    @Override
    public boolean verifyRequest(JSONObject requestMetaData, String correlationID) throws AISecurityException {

        int aseResponseCode = publishSyncEvent(requestMetaData, correlationID,
                AISecurityHandlerConstants.ASE_RESOURCE_REQUEST);
        SecurityUtils.verifyASEResponse(aseResponseCode, correlationID);
        return true;
    }

    @Override
    public boolean publishResponse(JSONObject requestMetaData, String correlationID) {

        return false;
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

    private class SyncPublisherThreadPoolExecutor extends ThreadPoolExecutor {

        SyncPublisherThreadPoolExecutor(int corePoolSize, int maximumPoolSize, long keepAliveTime, TimeUnit unit,
                                        LinkedBlockingDeque<Runnable> workQueue) {

            super(corePoolSize, maximumPoolSize, keepAliveTime, unit, workQueue);
        }
    }

}
