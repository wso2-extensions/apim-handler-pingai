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

package org.wso2.carbon.apimgt.securityenforcer.utils;

import org.json.simple.JSONArray;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.wso2.carbon.apimgt.securityenforcer.dto.AISecurityHandlerConfig;
import org.wso2.carbon.apimgt.securityenforcer.internal.ServiceReferenceHolder;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;
import java.util.TreeMap;

public class SecurityUtilsTest {

    org.apache.axis2.context.MessageContext axis2MessageContext;
    String headerOne = "headerOne";
    String headerTwo = "headerTwo";
    String headerThree = "headerThree";
    String headerFour = "headerFour";
    String headerFive = "headerFive";
    String hostHeader = "Host";
    String sideBandCallType = "request";
    String correlationID = "12345";

    @Before
    public void setup() throws AISecurityException {
        axis2MessageContext = Mockito.mock(org.apache.axis2.context.MessageContext.class);
    }

    @Test
    public void limitTrasportHeadersMentionedInTheConfigTest() throws AISecurityException, IOException {
        TreeMap<String, String> transportHeaderMap = new TreeMap<>();
        transportHeaderMap.put(headerOne, "one");
        transportHeaderMap.put(headerTwo, "two");
        transportHeaderMap.put(headerThree, "three");
        transportHeaderMap.put(headerFour, "four");
        transportHeaderMap.put(hostHeader, "Host");
        Mockito.when(axis2MessageContext.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS))
                .thenReturn(transportHeaderMap);

        AISecurityHandlerConfig securityHandlerConfig = new AISecurityHandlerConfig();
        AISecurityHandlerConfig.LimitTransportHeaders limitTransportHeadersConfig = new AISecurityHandlerConfig.LimitTransportHeaders();
        Set limitTransportHeaderSet = new HashSet();
        limitTransportHeaderSet.add(headerOne.toLowerCase());
        limitTransportHeaderSet.add(headerTwo.toLowerCase());
        limitTransportHeadersConfig.setEnable(true);
        limitTransportHeadersConfig.setHeaderSet(limitTransportHeaderSet);
        securityHandlerConfig.setLimitTransportHeaders(limitTransportHeadersConfig);
        ServiceReferenceHolder.getInstance().setSecurityHandlerConfig(securityHandlerConfig);

        JSONArray transportHeaderJson = SecurityUtils
                .getTransportHeaders(axis2MessageContext, sideBandCallType, correlationID);
        Assert.assertFalse(transportHeaderJson.toString().contains(headerThree));

    }

    @Test
    public void hostHeaderIncludedWithoutMentionedInConfig() throws AISecurityException, IOException {
        TreeMap<String, String> transportHeaderMap = new TreeMap<>();
        transportHeaderMap.put(headerOne, "one");
        transportHeaderMap.put(headerTwo, "two");
        transportHeaderMap.put(headerThree, "three");
        transportHeaderMap.put(headerFour, "four");
        transportHeaderMap.put(hostHeader, "Host");
        Mockito.when(axis2MessageContext.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS))
                .thenReturn(transportHeaderMap);

        AISecurityHandlerConfig securityHandlerConfig = new AISecurityHandlerConfig();
        AISecurityHandlerConfig.LimitTransportHeaders limitTransportHeadersConfig = new AISecurityHandlerConfig.LimitTransportHeaders();
        Set limitTransportHeaderSet = new HashSet();
        limitTransportHeaderSet.add(headerOne.toLowerCase());
        limitTransportHeaderSet.add(headerTwo.toLowerCase());
        limitTransportHeadersConfig.setEnable(true);
        limitTransportHeadersConfig.setHeaderSet(limitTransportHeaderSet);
        securityHandlerConfig.setLimitTransportHeaders(limitTransportHeadersConfig);
        ServiceReferenceHolder.getInstance().setSecurityHandlerConfig(securityHandlerConfig);

        JSONArray transportHeaderJson = SecurityUtils
                .getTransportHeaders(axis2MessageContext, sideBandCallType, correlationID);
        Assert.assertFalse(!transportHeaderJson.toString().contains(hostHeader));

    }

    @Test
    public void configMentionedHeaderNotInTransportHeaderList() throws AISecurityException, IOException {
        TreeMap<String, String> transportHeaderMap = new TreeMap<>();
        transportHeaderMap.put(headerOne, "one");
        transportHeaderMap.put(headerTwo, "two");
        transportHeaderMap.put(headerThree, "three");
        transportHeaderMap.put(headerFour, "four");
        transportHeaderMap.put(hostHeader, "Host");
        Mockito.when(axis2MessageContext.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS))
                .thenReturn(transportHeaderMap);

        AISecurityHandlerConfig securityHandlerConfig = new AISecurityHandlerConfig();
        AISecurityHandlerConfig.LimitTransportHeaders limitTransportHeadersConfig = new AISecurityHandlerConfig.LimitTransportHeaders();
        Set limitTransportHeaderSet = new HashSet();
        limitTransportHeaderSet.add(headerOne.toLowerCase());
        limitTransportHeaderSet.add(headerTwo.toLowerCase());
        limitTransportHeaderSet.add(headerFive.toLowerCase());
        limitTransportHeadersConfig.setEnable(true);
        limitTransportHeadersConfig.setHeaderSet(limitTransportHeaderSet);
        securityHandlerConfig.setLimitTransportHeaders(limitTransportHeadersConfig);
        ServiceReferenceHolder.getInstance().setSecurityHandlerConfig(securityHandlerConfig);

        JSONArray transportHeaderJson = SecurityUtils
                .getTransportHeaders(axis2MessageContext, sideBandCallType, correlationID);
        Assert.assertFalse(transportHeaderJson.toString().contains(headerFive));

    }

    @Test(expected = AISecurityException.class)
    public void ifHostNotFoundInTransportHeaders() throws AISecurityException, IOException {
        TreeMap<String, String> transportHeaderMap = new TreeMap<>();
        transportHeaderMap.put(headerOne, "one");
        transportHeaderMap.put(headerTwo, "two");
        transportHeaderMap.put(headerThree, "three");
        transportHeaderMap.put(headerFour, "four");
        Mockito.when(axis2MessageContext.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS))
                .thenReturn(transportHeaderMap);

        AISecurityHandlerConfig securityHandlerConfig = new AISecurityHandlerConfig();
        AISecurityHandlerConfig.LimitTransportHeaders limitTransportHeadersConfig = new AISecurityHandlerConfig.LimitTransportHeaders();
        Set limitTransportHeaderSet = new HashSet();
        limitTransportHeaderSet.add(headerOne.toLowerCase());
        limitTransportHeaderSet.add(headerTwo.toLowerCase());
        limitTransportHeaderSet.add(headerFive.toLowerCase());
        limitTransportHeadersConfig.setEnable(true);
        limitTransportHeadersConfig.setHeaderSet(limitTransportHeaderSet);
        securityHandlerConfig.setLimitTransportHeaders(limitTransportHeadersConfig);
        ServiceReferenceHolder.getInstance().setSecurityHandlerConfig(securityHandlerConfig);
        JSONArray transportHeaderJson = SecurityUtils
                .getTransportHeaders(axis2MessageContext, sideBandCallType, correlationID);
    }

    @Test
    public void hostMentionedConfigTest() throws AISecurityException, IOException {
        TreeMap<String, String> transportHeaderMap = new TreeMap<>();
        transportHeaderMap.put(headerOne, "one");
        transportHeaderMap.put(headerTwo, "two");
        transportHeaderMap.put(headerThree, "three");
        transportHeaderMap.put(headerFour, "four");
        transportHeaderMap.put(hostHeader, "Host");
        Mockito.when(axis2MessageContext.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS))
                .thenReturn(transportHeaderMap);

        AISecurityHandlerConfig securityHandlerConfig = new AISecurityHandlerConfig();
        AISecurityHandlerConfig.LimitTransportHeaders limitTransportHeadersConfig = new AISecurityHandlerConfig.LimitTransportHeaders();
        Set limitTransportHeaderSet = new HashSet();
        limitTransportHeaderSet.add(headerOne.toLowerCase());
        limitTransportHeaderSet.add(headerTwo.toLowerCase());
        limitTransportHeaderSet.add(hostHeader.toLowerCase());
        limitTransportHeadersConfig.setEnable(true);
        limitTransportHeadersConfig.setHeaderSet(limitTransportHeaderSet);
        securityHandlerConfig.setLimitTransportHeaders(limitTransportHeadersConfig);
        ServiceReferenceHolder.getInstance().setSecurityHandlerConfig(securityHandlerConfig);

        JSONArray transportHeaderJson = SecurityUtils
                .getTransportHeaders(axis2MessageContext, sideBandCallType, correlationID);
        Assert.assertFalse(transportHeaderJson.size() != 3);

    }

    @Test
    public void limitTransportHeaderDisabledTest() throws AISecurityException, IOException {
        TreeMap<String, String> transportHeaderMap = new TreeMap<>();
        transportHeaderMap.put(headerOne, "one");
        transportHeaderMap.put(headerTwo, "two");
        transportHeaderMap.put(headerThree, "three");
        transportHeaderMap.put(headerFour, "four");
        transportHeaderMap.put(hostHeader, "Host");
        Mockito.when(axis2MessageContext.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS))
                .thenReturn(transportHeaderMap);

        AISecurityHandlerConfig securityHandlerConfig = new AISecurityHandlerConfig();
        AISecurityHandlerConfig.LimitTransportHeaders limitTransportHeadersConfig = new AISecurityHandlerConfig.LimitTransportHeaders();
        Set limitTransportHeaderSet = new HashSet();
        limitTransportHeaderSet.add(headerOne.toLowerCase());
        limitTransportHeaderSet.add(headerTwo.toLowerCase());
        limitTransportHeaderSet.add(headerFive.toLowerCase());
        limitTransportHeadersConfig.setEnable(false);
        limitTransportHeadersConfig.setHeaderSet(limitTransportHeaderSet);
        securityHandlerConfig.setLimitTransportHeaders(limitTransportHeadersConfig);
        ServiceReferenceHolder.getInstance().setSecurityHandlerConfig(securityHandlerConfig);

        JSONArray transportHeaderJson = SecurityUtils
                .getTransportHeaders(axis2MessageContext, sideBandCallType, correlationID);
        Assert.assertFalse(transportHeaderJson.size() != transportHeaderMap.size() || transportHeaderJson.toString()
                .contains(headerFive));

    }

}