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

package org.wso2.carbon.apimgt.securityenforcer;

import org.apache.axis2.Constants;
import org.apache.http.ProtocolVersion;
import org.apache.synapse.MessageContext;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.transport.passthru.ServerWorker;
import org.apache.synapse.transport.passthru.SourceRequest;
import org.json.simple.JSONObject;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.wso2.carbon.apimgt.gateway.handlers.security.AuthenticationContext;
import org.wso2.carbon.apimgt.securityenforcer.dto.AISecurityHandlerConfig;
import org.wso2.carbon.apimgt.securityenforcer.internal.ServiceReferenceHolder;
import org.wso2.carbon.apimgt.securityenforcer.utils.AISecurityException;
import org.wso2.carbon.apimgt.securityenforcer.utils.AISecurityHandlerConstants;

import java.util.TreeMap;

public class PingAISecurityHandlerTest {

    private AISecurityHandlerConfig securityHandlerConfig;
    private MessageContext messageContext;
    private org.apache.axis2.context.MessageContext axis2MsgCntxt;
    private PingAISecurityHandler pingAiSecurityHandler;
    private ServerWorker worker;
    private SourceRequest sourceRequest;
    private ProtocolVersion httpProtocolVersion;
    private TreeMap<String, String> transportHeadersMap;

    public static JSONObject addObj(String key, Object value) {
        JSONObject obj = new JSONObject();
        obj.put(key, value);
        return obj;
    }

    @Before
    public void setup() throws AISecurityException {

        messageContext = Mockito.mock(Axis2MessageContext.class);
        axis2MsgCntxt = Mockito.mock(org.apache.axis2.context.MessageContext.class);

        Mockito.when(((Axis2MessageContext) messageContext).getAxis2MessageContext()).thenReturn(axis2MsgCntxt);

        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setApiKey("1234");
        authenticationContext.setApiTier("secured");
        authenticationContext.setUsername("John");
        Mockito.when((AuthenticationContext) messageContext.getProperty("__API_AUTH_CONTEXT"))
                .thenReturn(authenticationContext);

        transportHeadersMap = new TreeMap<>();
        transportHeadersMap.put(AISecurityHandlerConstants.TRANSPORT_HEADER_HOST_NAME, "xbank.com");
        transportHeadersMap.put("content-type", "application/xml");

        Mockito.when((TreeMap<String, String>) axis2MsgCntxt
                .getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS))
                .thenReturn(transportHeadersMap);

        worker = Mockito.mock(ServerWorker.class);
        sourceRequest = Mockito.mock(SourceRequest.class);

        httpProtocolVersion = new ProtocolVersion("http", 1, 1);

        Mockito.when(sourceRequest.getVersion()).thenReturn(httpProtocolVersion);
        Mockito.when(worker.getSourceRequest()).thenReturn(sourceRequest);
        Mockito.when((ServerWorker) axis2MsgCntxt.getProperty(Constants.OUT_TRANSPORT_INFO)).thenReturn(worker);

        pingAiSecurityHandler = new PingAISecurityHandler();
        securityHandlerConfig = new AISecurityHandlerConfig();
        securityHandlerConfig.setMode("hybrid");
        AISecurityHandlerConfig.LimitTransportHeaders limitTransportHeaders = new AISecurityHandlerConfig.LimitTransportHeaders();
        securityHandlerConfig.setLimitTransportHeaders(limitTransportHeaders);
        ServiceReferenceHolder.getInstance().setSecurityHandlerConfig(securityHandlerConfig);

    }

    @Test
    public void extractRequestMetadataTest() throws AISecurityException {

        Mockito.when((String) axis2MsgCntxt.getProperty(org.apache.axis2.context.MessageContext.REMOTE_ADDR))
                .thenReturn("1.1.1.1");
        Mockito.when((String) axis2MsgCntxt.getProperty(AISecurityHandlerConstants.HTTP_METHOD_STRING))
                .thenReturn("POST");
        Mockito.when((String) axis2MsgCntxt.getProperty(AISecurityHandlerConstants.API_BASEPATH_STRING))
                .thenReturn("/shop/get");

        JSONObject metaData = pingAiSecurityHandler.extractRequestMetadata(messageContext);
        Assert.assertTrue(metaData.size() == 4);
    }

    @Test
    public void extractResponseMetadataTest() throws AISecurityException {

        Mockito.when((Integer) axis2MsgCntxt.getProperty(AISecurityHandlerConstants.BACKEND_RESPONSE_STATUS_CODE))
                .thenReturn(200);
        Mockito.when((String) axis2MsgCntxt.getProperty(AISecurityHandlerConstants.BACKEND_RESPONSE_STATUS_MESSAGE))
                .thenReturn("OK");
        JSONObject responseJSON = pingAiSecurityHandler.extractResponseMetadata(messageContext);
        JSONObject asePayload = (JSONObject) responseJSON.get(AISecurityHandlerConstants.ASE_PAYLOAD_KEY_NAME);
        Assert.assertTrue(asePayload.get("response_code").equals("200"));
    }

}
