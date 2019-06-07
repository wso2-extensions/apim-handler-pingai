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

package org.wso2.carbon.apimgt.securityenforcer.publisher;

import org.apache.http.Header;
import org.apache.http.HeaderIterator;
import org.apache.http.HttpEntity;
import org.apache.http.ProtocolVersion;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.params.HttpParams;
import org.json.simple.JSONObject;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Matchers;
import org.mockito.Mockito;
import org.powermock.modules.junit4.PowerMockRunner;
import org.wso2.carbon.apimgt.securityenforcer.dto.AseResponseDTO;
import org.wso2.carbon.apimgt.securityenforcer.utils.AISecurityException;

import java.io.IOException;
import java.util.Locale;

@RunWith(PowerMockRunner.class)
public class HttpDataPublisherTest {

    private HttpDataPublisher httpDataPublisher;
    private CloseableHttpClient httpClient;
    private JSONObject requestMetaData;
    private String requestCorrelationID;

    @Before
    public void setup() throws AISecurityException {
        requestMetaData = new JSONObject();
        requestMetaData.put("A", 1);
        requestMetaData.put("B", 2);
        requestCorrelationID = "2344214";
        String endPoint = "http://10.100.10.11:2222/ase/";
        String aseToken = "asdf";
        httpClient = Mockito.mock(CloseableHttpClient.class);
        httpDataPublisher = new HttpDataPublisher(endPoint, aseToken);

    }

    @Test
    public void verifyPublishMethodWithSuccessResponseFromASETest() throws AISecurityException, IOException {

        CloseableHttpResponse response = generateResponse(200, "OK");
        Mockito.when(httpClient.execute(Matchers.<HttpPost>any())).thenReturn(response);
        httpDataPublisher.setHttpClient(httpClient);
        AseResponseDTO aseResponseDTO = httpDataPublisher.publish(requestMetaData, requestCorrelationID, "request");
        Assert.assertTrue(aseResponseDTO.getResponseCode() == 200);

    }

    public CloseableHttpResponse generateResponse(final int code, final String message) {
        final StatusLine statusLine = new StatusLine() {

            @Override
            public ProtocolVersion getProtocolVersion() {
                return null;
            }

            @Override
            public int getStatusCode() {
                return code;
            }

            @Override
            public String getReasonPhrase() {
                return message;
            }
        };
        CloseableHttpResponse response = new CloseableHttpResponse() {

            @Override
            public void close() throws IOException {

            }

            @Override
            public StatusLine getStatusLine() {
                return statusLine;
            }

            @Override
            public void setStatusLine(StatusLine statusLine) {

            }

            @Override
            public void setStatusLine(ProtocolVersion protocolVersion, int i) {

            }

            @Override
            public void setStatusLine(ProtocolVersion protocolVersion, int i, String s) {

            }

            @Override
            public HttpEntity getEntity() {
                return null;
            }

            @Override
            public void setEntity(HttpEntity httpEntity) {

            }

            @Override
            public Locale getLocale() {
                return null;
            }            @Override
            public void setStatusCode(int i) throws IllegalStateException {

            }

            @Override
            public void setLocale(Locale locale) {

            }

            @Override
            public ProtocolVersion getProtocolVersion() {
                return null;
            }

            @Override
            public boolean containsHeader(String s) {
                return false;
            }            @Override
            public void setReasonPhrase(String s) throws IllegalStateException {

            }

            @Override
            public Header[] getHeaders(String s) {
                return new Header[0];
            }

            @Override
            public Header getFirstHeader(String s) {
                return null;
            }

            @Override
            public Header getLastHeader(String s) {
                return null;
            }

            @Override
            public Header[] getAllHeaders() {
                return new Header[0];
            }

            @Override
            public void addHeader(Header header) {

            }

            @Override
            public void addHeader(String s, String s1) {

            }

            @Override
            public void setHeader(Header header) {

            }

            @Override
            public void setHeader(String s, String s1) {

            }

            @Override
            public void setHeaders(Header[] headers) {

            }

            @Override
            public void removeHeader(Header header) {

            }

            @Override
            public void removeHeaders(String s) {

            }

            @Override
            public HeaderIterator headerIterator() {
                return null;
            }

            @Override
            public HeaderIterator headerIterator(String s) {
                return null;
            }

            @Override
            public HttpParams getParams() {
                return null;
            }

            @Override
            public void setParams(HttpParams httpParams) {

            }





        };
        return response;
    }

}