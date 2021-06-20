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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.commons.pool.BasePoolableObjectFactory;
import org.apache.commons.pool.ObjectPool;
import org.apache.commons.pool.impl.StackObjectPool;
import org.wso2.carbon.apimgt.securityenforcer.pingai.dto.AISecurityHandlerConfig;
import org.wso2.carbon.apimgt.securityenforcer.pingai.internal.ServiceReferenceHolder;

/**
 * This class implemented to hold runnable publishing agent pool. Reason for implement this is to
 * reduce unwanted object creation. This is using stack object pool as we may need to handle some scenarios
 * where unexpected load comes. In such cases we cannot have fixed size pool.
 */

public class AsyncPublisherThreadPool {

    private static final Log log = LogFactory.getLog(AsyncPublisherThreadPool.class);

    ObjectPool clientPool;

    private AsyncPublisherThreadPool() {
        /*
        Using stack object pool to handle high concurrency scenarios without dropping any messages.
        Tuning this pool is mandatory according to use cases.
        A finite number of "sleeping" or idle instances is enforced, but when the pool is empty, new instances
        are created to support the new load. Hence this following data stricture places no limit on the number of
        "active" instance created by the pool, but is quite useful for re-using Objects without introducing
        artificial limits.
        Proper tuning is mandatory for good performance according to system load.
        */
        AISecurityHandlerConfig.StackObjectPoolConfig stackObjectPoolConfigurations = ServiceReferenceHolder
                .getInstance().getSecurityHandlerConfig().getStackObjectPoolConfig();
        clientPool = new StackObjectPool(new BasePoolableObjectFactory() {

            @Override
            public Object makeObject() {
                if (log.isDebugEnabled()) {
                    log.debug("Initializing new AsyncPublisherThreadPool instance");
                }
                return new AsyncPublishingAgent();
            }
        }, stackObjectPoolConfigurations.getMaxIdle(), stackObjectPoolConfigurations.getInitIdleCapacity());
    }

    public static AsyncPublisherThreadPool getInstance() {
        return AsyncPublisherThreadPool.AsyncPublisherPoolHolder.INSTANCE;
    }

    AsyncPublishingAgent get() throws Exception {
        return (AsyncPublishingAgent) clientPool.borrowObject();
    }

    void release(AsyncPublishingAgent client) throws Exception {
        //We must clean data references as it can caused to pass old data to global policy server.
        client.clearDataReference();
        clientPool.returnObject(client);
    }

    public void cleanup() {
        try {
            clientPool.close();
        } catch (Exception e) {
            log.warn("Error while cleaning up the object pool", e);
        }
    }

    private static class AsyncPublisherPoolHolder {

        private static final AsyncPublisherThreadPool INSTANCE = new AsyncPublisherThreadPool();

        private AsyncPublisherPoolHolder() {
        }
    }

}
