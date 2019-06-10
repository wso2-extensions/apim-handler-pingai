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

package org.wso2.carbon.apimgt.securityenforcer.publisher.hybrid;

import org.apache.commons.codec.digest.DigestUtils;
import org.json.simple.JSONObject;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.wso2.carbon.apimgt.securityenforcer.ASEResponseStore;
import org.wso2.carbon.apimgt.securityenforcer.dto.AISecurityHandlerConfig;
import org.wso2.carbon.apimgt.securityenforcer.dto.AseResponseDTO;
import org.wso2.carbon.apimgt.securityenforcer.internal.ServiceReferenceHolder;
import org.wso2.carbon.apimgt.securityenforcer.publisher.HttpDataPublisher;
import org.wso2.carbon.apimgt.securityenforcer.publisher.async.AsyncPublisher;
import org.wso2.carbon.apimgt.securityenforcer.publisher.sync.SyncPublisher;
import org.wso2.carbon.apimgt.securityenforcer.utils.AISecurityException;

@RunWith(PowerMockRunner.class)
@PrepareForTest({ ASEResponseStore.class })
public class HybridPublisherTest {

    private AsyncPublisher asyncPublisherSpy;
    private SyncPublisher syncPublisherSpy;

    private HybridPublisher hybridPublisher;
    private HttpDataPublisher httpDataPublisher;
    private JSONObject requestMetaData;
    private String requestCorrelationID;

    @Before
    public void setup() throws AISecurityException {
        AISecurityHandlerConfig aiSecurityHandlerConfig = new AISecurityHandlerConfig();
        aiSecurityHandlerConfig.setStackObjectPoolConfig(new AISecurityHandlerConfig.StackObjectPoolConfig());
        aiSecurityHandlerConfig.setThreadPoolExecutorConfig(new AISecurityHandlerConfig.ThreadPoolExecutorConfig());
        ServiceReferenceHolder.getInstance().setSecurityHandlerConfig(aiSecurityHandlerConfig);

        httpDataPublisher = Mockito.mock(HttpDataPublisher.class);
        Mockito.when(httpDataPublisher.publish(requestMetaData, requestCorrelationID, "request")).thenReturn(null);
        ServiceReferenceHolder.getInstance().setHttpDataPublisher(httpDataPublisher);

        hybridPublisher = new HybridPublisher();

        AsyncPublisher asyncPublisher = new AsyncPublisher();
        asyncPublisherSpy = Mockito.spy(asyncPublisher);

        SyncPublisher syncPublisher = new SyncPublisher();
        syncPublisherSpy = Mockito.spy(syncPublisher);

        hybridPublisher.setAsyncPublisher(asyncPublisherSpy);
        hybridPublisher.setSyncPublisher(syncPublisherSpy);

        asyncPublisher = new AsyncPublisher();
        asyncPublisherSpy = Mockito.spy(asyncPublisher);

        requestMetaData = new JSONObject();
        requestMetaData.put("A", 1);
        requestMetaData.put("B", 2);
        requestCorrelationID = "2344214";

        PowerMockito.mockStatic(ASEResponseStore.class);
    }

    @Test
    public void verifyRequestWithoutCacheInstanceLaterWithResponseSuccessTest() throws AISecurityException {

        AseResponseDTO aseResponseDTO = new AseResponseDTO();
        aseResponseDTO.setResponseCode(200);
        aseResponseDTO.setResponseMessage("OK");
        Mockito.when(syncPublisherSpy.publishSyncEvent(requestMetaData, requestCorrelationID, "request"))
                .thenReturn(aseResponseDTO);
        hybridPublisher.setSyncPublisher(syncPublisherSpy);

        String hashKey = DigestUtils.md5Hex(requestMetaData.toString());
        AseResponseDTO aseResponseDTOFromCache = null;
        Mockito.when(ASEResponseStore.getFromASEResponseCache(hashKey)).thenReturn(aseResponseDTOFromCache);
        Assert.assertTrue(hybridPublisher.verifyRequest(requestMetaData, requestCorrelationID));
    }

    @Test
    public void verifyRequestWithoutCacheInstanceLaterWithResponseRevokedTest() throws AISecurityException {

        AseResponseDTO aseResponseDTO = new AseResponseDTO();
        aseResponseDTO.setResponseCode(403);
        aseResponseDTO.setResponseMessage("Forbidden");
        Mockito.when(syncPublisherSpy.publishSyncEvent(requestMetaData, requestCorrelationID, "request"))
                .thenReturn(aseResponseDTO);
        hybridPublisher.setSyncPublisher(syncPublisherSpy);

        String hashKey = DigestUtils.md5Hex(requestMetaData.toString());
        AseResponseDTO aseResponseDTOFromCache = null;
        Mockito.when(ASEResponseStore.getFromASEResponseCache(hashKey)).thenReturn(aseResponseDTOFromCache);

        try {
            hybridPublisher.verifyRequest(requestMetaData, requestCorrelationID);
        } catch (AISecurityException e) {
            Assert.assertTrue(e.getErrorCode() == AISecurityException.ACCESS_REVOKED);
        }
    }

    @Test
    public void verifyRequestWithCacheInstanceSuccessLaterWithResponseSuccessTest() throws AISecurityException {
        Mockito.doNothing().when(asyncPublisherSpy).publishAsyncEvent(requestMetaData, requestCorrelationID, "request");
        hybridPublisher.setAsyncPublisher(asyncPublisherSpy);

        String hashKey = DigestUtils.md5Hex(requestMetaData.toString());
        AseResponseDTO aseResponseDTO = new AseResponseDTO();
        aseResponseDTO.setResponseCode(200);
        aseResponseDTO.setResponseMessage("OK");
        Mockito.when(ASEResponseStore.getFromASEResponseCache(hashKey)).thenReturn(aseResponseDTO);
        Assert.assertTrue(hybridPublisher.verifyRequest(requestMetaData, requestCorrelationID));
    }

    @Test
    public void verifyRequestWithCacheInstanceSuccessLaterWithResponseRevokedTest() throws AISecurityException {
        Mockito.doNothing().when(asyncPublisherSpy).publishAsyncEvent(requestMetaData, requestCorrelationID, "request");
        hybridPublisher.setAsyncPublisher(asyncPublisherSpy);

        AseResponseDTO aseResponseDTO = new AseResponseDTO();
        aseResponseDTO.setResponseCode(403);
        aseResponseDTO.setResponseMessage("Forbidden");
        String hashKey = DigestUtils.md5Hex(requestMetaData.toString());
        Mockito.when(ASEResponseStore.getFromASEResponseCache(hashKey)).thenReturn(aseResponseDTO);

        try {
            hybridPublisher.verifyRequest(requestMetaData, requestCorrelationID);
        } catch (AISecurityException e) {
            Assert.assertTrue(e.getErrorCode() == AISecurityException.ACCESS_REVOKED);
        }
    }

    @Test
    public void verifySuccessSecondRequestAfterSuccessCacheUpdateTest() throws AISecurityException {

        AseResponseDTO aseResponseDTOFirstCacheResponse = null;
        String hashKey = DigestUtils.md5Hex(requestMetaData.toString());
        Mockito.when(ASEResponseStore.getFromASEResponseCache(hashKey)).thenReturn(aseResponseDTOFirstCacheResponse);

        AseResponseDTO aseResponseDTO = new AseResponseDTO();
        aseResponseDTO.setResponseCode(200);
        aseResponseDTO.setResponseMessage("OK");
        Mockito.when(syncPublisherSpy.publishSyncEvent(requestMetaData, requestCorrelationID, "request"))
                .thenReturn(aseResponseDTO);
        hybridPublisher.setSyncPublisher(syncPublisherSpy);

        hybridPublisher.verifyRequest(requestMetaData, requestCorrelationID);

        Mockito.doNothing().when(asyncPublisherSpy).publishAsyncEvent(requestMetaData, requestCorrelationID, "request");
        hybridPublisher.setAsyncPublisher(asyncPublisherSpy);

        AseResponseDTO aseResponseDTOSecondCacheResponse = new AseResponseDTO();
        aseResponseDTOSecondCacheResponse.setResponseCode(200);
        aseResponseDTOSecondCacheResponse.setResponseMessage("OK");
        Mockito.when(ASEResponseStore.getFromASEResponseCache(hashKey)).thenReturn(aseResponseDTOSecondCacheResponse);

        Assert.assertTrue(hybridPublisher.verifyRequest(requestMetaData, requestCorrelationID));
    }

    @Test
    public void verifyRevokeSecondRequestAfterSuccessCacheUpdateTest() throws AISecurityException {

        AseResponseDTO aseResponseDTOFirstCacheResponse = null;
        String hashKey = DigestUtils.md5Hex(requestMetaData.toString());
        Mockito.when(ASEResponseStore.getFromASEResponseCache(hashKey)).thenReturn(aseResponseDTOFirstCacheResponse);

        AseResponseDTO aseResponseDTO = new AseResponseDTO();
        aseResponseDTO.setResponseCode(200);
        aseResponseDTO.setResponseMessage("OK");
        Mockito.when(syncPublisherSpy.publishSyncEvent(requestMetaData, requestCorrelationID, "request"))
                .thenReturn(aseResponseDTO);
        hybridPublisher.setSyncPublisher(syncPublisherSpy);

        hybridPublisher.verifyRequest(requestMetaData, requestCorrelationID);

        Mockito.doNothing().when(asyncPublisherSpy).publishAsyncEvent(requestMetaData, requestCorrelationID, "request");
        hybridPublisher.setAsyncPublisher(asyncPublisherSpy);

        AseResponseDTO aseResponseDTOSecondCacheResponse = new AseResponseDTO();
        aseResponseDTOSecondCacheResponse.setResponseCode(403);
        aseResponseDTOSecondCacheResponse.setResponseMessage("Forbidden");
        Mockito.when(ASEResponseStore.getFromASEResponseCache(hashKey)).thenReturn(aseResponseDTOSecondCacheResponse);

        try {
            hybridPublisher.verifyRequest(requestMetaData, requestCorrelationID);
        } catch (AISecurityException e) {
            Assert.assertTrue(e.getErrorCode() == AISecurityException.ACCESS_REVOKED);
        }
    }
}