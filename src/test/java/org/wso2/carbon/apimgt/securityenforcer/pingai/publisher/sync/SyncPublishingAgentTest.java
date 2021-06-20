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
import org.mockito.Mockito;
import org.wso2.carbon.apimgt.securityenforcer.pingai.internal.ServiceReferenceHolder;
import org.wso2.carbon.apimgt.securityenforcer.pingai.publisher.HttpDataPublisher;
import org.wso2.carbon.apimgt.securityenforcer.pingai.utils.AISecurityException;

public class SyncPublishingAgentTest {

    HttpDataPublisher httpDataPublisher;
    JSONObject requestMetaData;
    String correlationID;
    SyncPublishingAgent syncPublishingAgent;

    @Before
    public void setup() throws AISecurityException {
        httpDataPublisher = Mockito.mock(HttpDataPublisher.class);
        requestMetaData = new JSONObject();
        requestMetaData.put("A", 1);
        requestMetaData.put("B", 2);
        correlationID = "2344214";
    }

    @Test
    public void verifyPublishMethodWith200ResponseFromASETest() throws AISecurityException {
        Mockito.when(httpDataPublisher.publish(requestMetaData, correlationID, "request")).thenReturn(200);
        ServiceReferenceHolder.getInstance().setHttpDataPublisher(httpDataPublisher);

        syncPublishingAgent = new SyncPublishingAgent();
        syncPublishingAgent.setDataReference(requestMetaData, correlationID, "request");
        int aseResponseCode = syncPublishingAgent.call();
        syncPublishingAgent.clearDataReference();
        Assert.assertTrue(aseResponseCode == 200);
    }

}