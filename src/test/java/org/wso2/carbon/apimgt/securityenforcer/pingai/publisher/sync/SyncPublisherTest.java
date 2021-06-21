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

package org.wso2.carbon.apimgt.securityenforcer.pingai.publisher.sync;

import org.json.simple.JSONObject;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.wso2.carbon.apimgt.securityenforcer.pingai.dto.AISecurityHandlerConfig;
import org.wso2.carbon.apimgt.securityenforcer.pingai.internal.ServiceReferenceHolder;
import org.wso2.carbon.apimgt.securityenforcer.pingai.publisher.HttpDataPublisher;
import org.wso2.carbon.apimgt.securityenforcer.pingai.utils.AISecurityException;
import org.wso2.carbon.apimgt.securityenforcer.pingai.utils.AISecurityHandlerConstants;

@RunWith(PowerMockRunner.class)
@PrepareForTest({ SyncPublisherThreadPool.class })
public class SyncPublisherTest {

    private SyncPublisher syncPublisher;
    private SyncPublisher syncPublisherSpy;
    private HttpDataPublisher httpDataPublisher;
    private JSONObject requestMetaData;
    private String correlationID;

    @Before
    public void setup() throws AISecurityException {
        AISecurityHandlerConfig aiSecurityHandlerConfig = new AISecurityHandlerConfig();
        aiSecurityHandlerConfig.setStackObjectPoolConfig(new AISecurityHandlerConfig.StackObjectPoolConfig());
        aiSecurityHandlerConfig.setThreadPoolExecutorConfig(new AISecurityHandlerConfig.ThreadPoolExecutorConfig());
        ServiceReferenceHolder.getInstance().setSecurityHandlerConfig(aiSecurityHandlerConfig);

        httpDataPublisher = Mockito.mock(HttpDataPublisher.class);
        Mockito.when(httpDataPublisher.publish(requestMetaData, correlationID, "request")).thenReturn(0);
        ServiceReferenceHolder.getInstance().setHttpDataPublisher(httpDataPublisher);

        syncPublisher = new SyncPublisher();
        syncPublisherSpy = Mockito.spy(syncPublisher);

        requestMetaData = new JSONObject();
        JSONObject asePayload = new JSONObject();
        asePayload.put("A", 1);
        asePayload.put("B", 2);
        requestMetaData.put(AISecurityHandlerConstants.ASE_PAYLOAD_KEY_NAME,asePayload);
        correlationID = "2344214";
    }

    @Test
    public void verifyRequestForSuccessResponseTest() throws AISecurityException {
        int aseResponseCode = 200;
        Mockito.when(syncPublisherSpy.publishSyncEvent(requestMetaData, correlationID, "request"))
                .thenReturn(aseResponseCode);
        Assert.assertTrue(syncPublisherSpy.verifyRequest(requestMetaData, correlationID));
    }

    @Test
    public void verifyRequestForAccessRevokeResponseTest() throws AISecurityException {
        int aseResponseCode = 403;
        Mockito.when(syncPublisherSpy.publishSyncEvent(requestMetaData, correlationID, "request"))
                .thenReturn(aseResponseCode);
        try {
            syncPublisherSpy.verifyRequest(requestMetaData, correlationID);
        } catch (AISecurityException e) {
            Assert.assertTrue(e.getErrorCode() == AISecurityException.ACCESS_REVOKED);
        }
    }

}