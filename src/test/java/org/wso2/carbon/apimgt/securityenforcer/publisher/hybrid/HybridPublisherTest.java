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
import org.wso2.carbon.apimgt.securityenforcer.internal.ServiceReferenceHolder;
import org.wso2.carbon.apimgt.securityenforcer.publisher.HttpDataPublisher;
import org.wso2.carbon.apimgt.securityenforcer.publisher.async.AsyncPublisher;
import org.wso2.carbon.apimgt.securityenforcer.publisher.sync.SyncPublisher;
import org.wso2.carbon.apimgt.securityenforcer.utils.AISecurityException;
import org.wso2.carbon.apimgt.securityenforcer.utils.AISecurityHandlerConstants;

@RunWith(PowerMockRunner.class)
@PrepareForTest({ ASEResponseStore.class })
public class HybridPublisherTest {

    private AsyncPublisher asyncPublisherSpy;
    private SyncPublisher syncPublisherSpy;

    private HybridPublisher hybridPublisher;
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
        JSONObject asePayload = new JSONObject();
        asePayload.put("A", 1);
        asePayload.put("B", 2);
        requestMetaData.put(AISecurityHandlerConstants.ASE_PAYLOAD_KEY_NAME, asePayload);
        requestMetaData.put(AISecurityHandlerConstants.COOKIE_KEY_NAME, "Cookie");
        requestMetaData.put(AISecurityHandlerConstants.TOKEN_KEY_NAME, "Token");
        requestMetaData.put(AISecurityHandlerConstants.IP_KEY_NAME, "IP");
        correlationID = "2344214";

        PowerMockito.mockStatic(ASEResponseStore.class);
    }

    @Test
    public void verifyRequestWithoutCacheInstanceLaterWithResponseSuccessTest() throws AISecurityException {

        int aseResponseCode = 200;
        Mockito.when(syncPublisherSpy.publishSyncEvent(requestMetaData, correlationID, "request"))
                .thenReturn(aseResponseCode);
        hybridPublisher.setSyncPublisher(syncPublisherSpy);

        int aseResponseCodeFromCache = 0;
        Mockito.when(ASEResponseStore.getFromASEResponseCache(AISecurityHandlerConstants.IP_CACHE_NAME,"IP"))
                .thenReturn(aseResponseCodeFromCache);
        Mockito.when(ASEResponseStore.getFromASEResponseCache(AISecurityHandlerConstants.TOKEN_CACHE_NAME,"Token"))
                .thenReturn(aseResponseCodeFromCache);
        Mockito.when(ASEResponseStore.getFromASEResponseCache(AISecurityHandlerConstants.COOKIE_CACHE_NAME,"Cookie"))
                .thenReturn(aseResponseCodeFromCache);
        Assert.assertTrue(hybridPublisher.verifyRequest(requestMetaData, correlationID));
    }

    @Test
    public void verifyRequestWithoutCacheInstanceLaterWithResponseRevokedTest() throws AISecurityException {

        int aseResponseCode = 403;
        Mockito.when(syncPublisherSpy.publishSyncEvent(requestMetaData, correlationID, "request"))
                .thenReturn(aseResponseCode);
        hybridPublisher.setSyncPublisher(syncPublisherSpy);

        int aseResponseCodeFromCache = 0;
        Mockito.when(ASEResponseStore.getFromASEResponseCache(AISecurityHandlerConstants.IP_CACHE_NAME,"IP"))
                .thenReturn(aseResponseCodeFromCache);
        Mockito.when(ASEResponseStore.getFromASEResponseCache(AISecurityHandlerConstants.TOKEN_CACHE_NAME,"Token"))
                .thenReturn(aseResponseCodeFromCache);
        Mockito.when(ASEResponseStore.getFromASEResponseCache(AISecurityHandlerConstants.COOKIE_CACHE_NAME,"Cookie"))
                .thenReturn(aseResponseCodeFromCache);


        try {
            hybridPublisher.verifyRequest(requestMetaData, correlationID);
        } catch (AISecurityException e) {
            Assert.assertTrue(e.getErrorCode() == AISecurityException.ACCESS_REVOKED);
        }
    }

    @Test
    public void verifyRequestWithCacheInstanceSuccessLaterWithResponseSuccessTest() throws AISecurityException {
        Mockito.doNothing().when(asyncPublisherSpy).publishAsyncEvent(requestMetaData, correlationID, "request");
        hybridPublisher.setAsyncPublisher(asyncPublisherSpy);

        int aseResponseCode = 200;
        Mockito.when(ASEResponseStore.getFromASEResponseCache(AISecurityHandlerConstants.IP_CACHE_NAME,"IP"))
                .thenReturn(aseResponseCode);
        Mockito.when(ASEResponseStore.getFromASEResponseCache(AISecurityHandlerConstants.TOKEN_CACHE_NAME,"Token"))
                .thenReturn(aseResponseCode);
        Mockito.when(ASEResponseStore.getFromASEResponseCache(AISecurityHandlerConstants.COOKIE_CACHE_NAME,"Cookie"))
                .thenReturn(aseResponseCode);

        Assert.assertTrue(hybridPublisher.verifyRequest(requestMetaData, correlationID));
    }

    @Test
    public void verifyRequestWithCacheInstanceSuccessLaterWithResponseRevokedTest() throws AISecurityException {
        Mockito.doNothing().when(asyncPublisherSpy).publishAsyncEvent(requestMetaData, correlationID, "request");
        hybridPublisher.setAsyncPublisher(asyncPublisherSpy);

        int aseResponseCode = 403;
        Mockito.when(ASEResponseStore.getFromASEResponseCache(AISecurityHandlerConstants.IP_CACHE_NAME,"IP"))
                .thenReturn(aseResponseCode);
        Mockito.when(ASEResponseStore.getFromASEResponseCache(AISecurityHandlerConstants.TOKEN_CACHE_NAME,"Token"))
                .thenReturn(aseResponseCode);
        Mockito.when(ASEResponseStore.getFromASEResponseCache(AISecurityHandlerConstants.COOKIE_CACHE_NAME,"Cookie"))
                .thenReturn(aseResponseCode);


        try {
            hybridPublisher.verifyRequest(requestMetaData, correlationID);
        } catch (AISecurityException e) {
            Assert.assertTrue(e.getErrorCode() == AISecurityException.ACCESS_REVOKED);
        }
    }

    @Test
    public void verifySuccessSecondRequestAfterSuccessCacheUpdateTest() throws AISecurityException {

        int aseResponseCodeFirstCacheResponse = 0;
        Mockito.when(ASEResponseStore.getFromASEResponseCache(AISecurityHandlerConstants.IP_CACHE_NAME,"IP"))
                .thenReturn(aseResponseCodeFirstCacheResponse);
        Mockito.when(ASEResponseStore.getFromASEResponseCache(AISecurityHandlerConstants.TOKEN_CACHE_NAME,"Token"))
                .thenReturn(aseResponseCodeFirstCacheResponse);
        Mockito.when(ASEResponseStore.getFromASEResponseCache(AISecurityHandlerConstants.COOKIE_CACHE_NAME,"Cookie"))
                .thenReturn(aseResponseCodeFirstCacheResponse);


        int aseResponseCode = 200;
        Mockito.when(syncPublisherSpy.publishSyncEvent(requestMetaData, correlationID, "request"))
                .thenReturn(aseResponseCode);
        hybridPublisher.setSyncPublisher(syncPublisherSpy);

        hybridPublisher.verifyRequest(requestMetaData, correlationID);

        Mockito.doNothing().when(asyncPublisherSpy).publishAsyncEvent(requestMetaData, correlationID, "request");
        hybridPublisher.setAsyncPublisher(asyncPublisherSpy);

        int aseResponseCodeSecondCacheResponse = 200;
        Mockito.when(ASEResponseStore.getFromASEResponseCache(AISecurityHandlerConstants.IP_CACHE_NAME,"IP"))
                .thenReturn(aseResponseCodeSecondCacheResponse);
        Mockito.when(ASEResponseStore.getFromASEResponseCache(AISecurityHandlerConstants.TOKEN_CACHE_NAME,"Token"))
                .thenReturn(aseResponseCodeSecondCacheResponse);
        Mockito.when(ASEResponseStore.getFromASEResponseCache(AISecurityHandlerConstants.COOKIE_CACHE_NAME,"Cookie"))
                .thenReturn(aseResponseCodeSecondCacheResponse);


        Assert.assertTrue(hybridPublisher.verifyRequest(requestMetaData, correlationID));
    }

    @Test
    public void verifyRevokeSecondRequestAfterSuccessCacheUpdateTest() throws AISecurityException {

        int aseResponseCodeFirstCacheResponse = 0;
        Mockito.when(ASEResponseStore.getFromASEResponseCache(AISecurityHandlerConstants.IP_CACHE_NAME,"IP")).thenReturn(aseResponseCodeFirstCacheResponse);
        Mockito.when(ASEResponseStore.getFromASEResponseCache(AISecurityHandlerConstants.TOKEN_CACHE_NAME,"Token")).thenReturn(aseResponseCodeFirstCacheResponse);
        Mockito.when(ASEResponseStore.getFromASEResponseCache(AISecurityHandlerConstants.COOKIE_CACHE_NAME,"Cookie")).thenReturn(aseResponseCodeFirstCacheResponse);


        int aseResponseCode =  200;
        Mockito.when(syncPublisherSpy.publishSyncEvent(requestMetaData, correlationID, "request"))
                .thenReturn(aseResponseCode);
        hybridPublisher.setSyncPublisher(syncPublisherSpy);

        hybridPublisher.verifyRequest(requestMetaData, correlationID);

        Mockito.doNothing().when(asyncPublisherSpy).publishAsyncEvent(requestMetaData, correlationID, "request");
        hybridPublisher.setAsyncPublisher(asyncPublisherSpy);

        int aseResponseCodeSecondCacheResponse = 403;
        Mockito.when(ASEResponseStore.getFromASEResponseCache(AISecurityHandlerConstants.IP_CACHE_NAME,"IP")).thenReturn(aseResponseCodeSecondCacheResponse);
        Mockito.when(ASEResponseStore.getFromASEResponseCache(AISecurityHandlerConstants.TOKEN_CACHE_NAME,"Token")).thenReturn(aseResponseCodeSecondCacheResponse);
        Mockito.when(ASEResponseStore.getFromASEResponseCache(AISecurityHandlerConstants.COOKIE_CACHE_NAME,"Cookie")).thenReturn(aseResponseCodeSecondCacheResponse);

        try {
            hybridPublisher.verifyRequest(requestMetaData, correlationID);
        } catch (AISecurityException e) {
            Assert.assertTrue(e.getErrorCode() == AISecurityException.ACCESS_REVOKED);
        }
    }
}