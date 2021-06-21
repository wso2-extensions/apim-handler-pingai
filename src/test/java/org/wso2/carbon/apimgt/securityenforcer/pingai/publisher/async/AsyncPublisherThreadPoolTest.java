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

import org.junit.Assert;
import org.junit.Test;
import org.wso2.carbon.apimgt.securityenforcer.pingai.dto.AISecurityHandlerConfig;
import org.wso2.carbon.apimgt.securityenforcer.pingai.internal.ServiceReferenceHolder;

public class AsyncPublisherThreadPoolTest {

    @Test
    public void getAsyncPublisherThreadPoolInstance() throws Exception {
        AISecurityHandlerConfig aiSecurityHandlerConfig = new AISecurityHandlerConfig();
        AISecurityHandlerConfig.StackObjectPoolConfig stackObjectPoolConfig = new AISecurityHandlerConfig.StackObjectPoolConfig();
        stackObjectPoolConfig.setMaxIdle(10);
        stackObjectPoolConfig.setInitIdleCapacity(10);
        aiSecurityHandlerConfig.setStackObjectPoolConfig(stackObjectPoolConfig);
        ServiceReferenceHolder.getInstance().setSecurityHandlerConfig(aiSecurityHandlerConfig);
        AsyncPublisherThreadPool dataPublisherPoolInstance = AsyncPublisherThreadPool.getInstance();
        AsyncPublishingAgent runnableAgent = dataPublisherPoolInstance.get();
        dataPublisherPoolInstance.release(runnableAgent);
        dataPublisherPoolInstance.cleanup();
        Assert.assertTrue(dataPublisherPoolInstance.clientPool.getNumActive() == 0);
    }
}