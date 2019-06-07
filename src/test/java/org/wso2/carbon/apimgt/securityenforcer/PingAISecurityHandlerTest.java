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

import org.apache.synapse.MessageContext;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.wso2.carbon.apimgt.securityenforcer.dto.AISecurityHandlerConfig;
import org.wso2.carbon.apimgt.securityenforcer.internal.ServiceReferenceHolder;
import org.wso2.carbon.apimgt.securityenforcer.utils.AISecurityException;
import org.wso2.carbon.apimgt.securityenforcer.utils.AISecurityHandlerConstants;
import org.wso2.carbon.apimgt.securityenforcer.utils.SecurityUtils;

@RunWith(PowerMockRunner.class)
@PrepareForTest({ SecurityUtils.class })
public class PingAISecurityHandlerTest {

    private AISecurityHandlerConfig securityHandlerConfig;
    private MessageContext messageContext;
    private org.apache.axis2.context.MessageContext axis2MsgCntxt;
    private PingAISecurityHandler pingAiSecurityHandler;

    private SecurityUtils securityUtils;
    private JSONArray transportHeaderArray;

    public static JSONObject addObj(String key, Object value) {
        JSONObject obj = new JSONObject();
        obj.put(key, value);
        return obj;
    }

    @Before
    public void setup() throws AISecurityException {

        messageContext = Mockito.mock(Axis2MessageContext.class);
        axis2MsgCntxt = new org.apache.axis2.context.MessageContext();
        Mockito.when(((Axis2MessageContext) messageContext).getAxis2MessageContext()).thenReturn(axis2MsgCntxt);

        securityHandlerConfig = new AISecurityHandlerConfig();
        securityHandlerConfig.setMode("hybrid");
        ServiceReferenceHolder.getInstance().setSecurityHandlerConfig(securityHandlerConfig);

        pingAiSecurityHandler = new PingAISecurityHandler();

        PowerMockito.mockStatic(SecurityUtils.class);
        securityUtils = Mockito.mock(SecurityUtils.class);

        transportHeaderArray = new JSONArray();
        transportHeaderArray.add(addObj(AISecurityHandlerConstants.TRANSPORT_HEADER_HOST_NAME, "xbank.com"));
        transportHeaderArray.add(addObj("content-type", "application/xml"));
        Mockito.when(SecurityUtils.getTransportHeaders(axis2MsgCntxt, "request", "1234"))
                .thenReturn(transportHeaderArray);
        Mockito.when(SecurityUtils.getTransportHeaders(axis2MsgCntxt, "response", "1234"))
                .thenReturn(transportHeaderArray);

    }

    @Test
    public void extractRequestMetadataTest() throws AISecurityException {
/*
        Mockito.when(SecurityUtils.getIp(axis2MsgCntxt)).thenReturn("55.56.38.20");
        Mockito.when(SecurityUtils.getHttpVersion(axis2MsgCntxt)).thenReturn("1.1");
        axis2MsgCntxt.setProperty(AISecurityHandlerConstants.HTTP_METHOD_STRING, "POST");
        axis2MsgCntxt.setProperty(AISecurityHandlerConstants.API_BASEPATH_STRING, "/shop/get");
        JSONObject metaData = pingAiSecurityHandler.extractRequestMetadata(messageContext);
*/
    }

    @Test
    public void extractResponseMetadataTest() throws AISecurityException {

        Object code = 200;
        Mockito.when(SecurityUtils.getHttpVersion(axis2MsgCntxt)).thenReturn("1.1");
        axis2MsgCntxt.setProperty(AISecurityHandlerConstants.BACKEND_RESPONSE_STATUS_CODE, code);
        axis2MsgCntxt.setProperty(AISecurityHandlerConstants.BACKEND_RESPONSE_STATUS_MESSAGE, "OK");
        JSONObject responseJSON = pingAiSecurityHandler.extractResponseMetadata(messageContext);
        Assert.assertTrue(((String) responseJSON.get("response_code")).equals("200"));
    }

}
