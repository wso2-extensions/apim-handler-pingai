/*
 *  Copyright WSO2 Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wso2.carbon.apimgt.securityenforcer.publisher;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.json.simple.JSONObject;
import org.wso2.carbon.apimgt.securityenforcer.dto.AISecurityHandlerConfig;
import org.wso2.carbon.apimgt.securityenforcer.dto.AseResponseDTO;
import org.wso2.carbon.apimgt.securityenforcer.utils.AISecurityException;
import org.wso2.carbon.apimgt.securityenforcer.utils.AISecurityHandlerConstants;
import org.wso2.carbon.apimgt.securityenforcer.utils.SecurityUtils;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.SocketTimeoutException;
import java.net.URL;
import javax.net.ssl.SSLHandshakeException;

/**
 * HttpDataPublisher class is here to verifyRequest PingAI data to Ping Intelligence ASE via http requests.
 * This will create a http client and a pool. If proxy is enabled for the endpoint, client is changed accordingly.
 */
public class HttpDataPublisher {

    private static final Log log = LogFactory.getLog(HttpDataPublisher.class);

    private CloseableHttpClient httpClient;
    private String authToken;
    private String endPoint;

    public HttpDataPublisher(AISecurityHandlerConfig.AseConfig aseConfiguration,
            AISecurityHandlerConfig.DataPublisherConfig dataPublisherConfiguration,
            AISecurityHandlerConfig.ProxyConfig proxyConfiguration) throws AISecurityException {

        String protocol;
        try {
            protocol = new URL(aseConfiguration.getEndPoint()).getProtocol();
        } catch (MalformedURLException e) {
            log.error("Error when getting the ASE request protocol", e);
            throw new AISecurityException(AISecurityException.HANDLER_ERROR, AISecurityException.HANDLER_ERROR_MESSAGE,
                    e);
        }
        httpClient = SecurityUtils.getHttpClient(protocol, dataPublisherConfiguration, proxyConfiguration);
        setAuthToken(aseConfiguration.getAseToken());
        setEndPoint(aseConfiguration.getEndPoint());
    }

    public HttpDataPublisher(String endPoint, String authToken) {
        setAuthToken(authToken);
        setEndPoint(endPoint);
    }

    public AseResponseDTO publish(JSONObject data, String correlationID, String resource) {
        HttpPost postRequest = new HttpPost(this.getEndPoint() + resource);
        postRequest.addHeader(AISecurityHandlerConstants.ASE_TOKEN_HEADER, this.getAuthToken());
        postRequest.addHeader(AISecurityHandlerConstants.X_CORRELATION_ID_HEADER, correlationID);

        CloseableHttpResponse response = null;
        AseResponseDTO aseResponseDTO = null;

        try {
            postRequest.setEntity(new StringEntity(data.toString()));
            long publishingStartTime = System.nanoTime();
            response = httpClient.execute(postRequest);
            long publishingEndTime = System.nanoTime();

            if (response != null) {
                aseResponseDTO = new AseResponseDTO();
                aseResponseDTO.setResponseMessage(response.getStatusLine().getReasonPhrase());
                aseResponseDTO.setResponseCode(response.getStatusLine().getStatusCode());

                switch (response.getStatusLine().getStatusCode()) {
                case AISecurityHandlerConstants.ASE_RESPONSE_CODE_INCORRECT_JSON:
                    log.error("Incorrect JSON format sent for the ASE from the request " + correlationID);
                    break;
                case AISecurityHandlerConstants.ASE_RESPONSE_CODE_UNKNOWN_API:
                    log.error("Unknown API for the request " + correlationID);
                    break;
                case AISecurityHandlerConstants.ASE_RESPONSE_CODE_UNAUTHORIZED:
                    log.error("Authentication failure (ASE-Token) for the request " + correlationID);
                    break;
                }

                if (log.isDebugEnabled()) {
                    log.debug("PING ASE Response for method: " + resource + ", correlation ID " + correlationID
                            + " , response: " + response.toString()
                            + ", connection time for the request in nano seconds is " + (publishingEndTime
                            - publishingStartTime));
                }
            } else {
                log.error("Null response returned from ASE for the request " + correlationID);
            }
        } catch (SocketTimeoutException e) {
            log.error(
                    "Socket timeout exception when sending the HTTP Request with id " + correlationID + " ,Error : " + e
                            .getMessage());
            aseResponseDTO = getDefaultAcceptResponse();
        } catch (SSLHandshakeException e) {
            log.error("SSLHandshakeException exception when sending the HTTP Request with id " + correlationID
                    + " ,Error : " + e.getMessage());
            aseResponseDTO = getDefaultAcceptResponse();
        } catch (IOException e) {
            log.error("IO exception when sending the HTTP Request with id " + correlationID + " ,Error : " + e
                    .getMessage());
            aseResponseDTO = getDefaultAcceptResponse();
        } finally {
            if (response != null) {
                try {
                    response.close();
                } catch (IOException e) {
                    log.error("Error when closing the response of the request id " + correlationID, e);
                }
            }
        }
        return aseResponseDTO;
    }

    private String getAuthToken() {

        return authToken;
    }

    private void setAuthToken(String authToken) {

        this.authToken = authToken;
    }

    private String getEndPoint() {

        return endPoint;
    }

    private void setEndPoint(String endPoint) {

        this.endPoint = endPoint;
    }

    private AseResponseDTO getDefaultAcceptResponse() {
        AseResponseDTO aseResponseDTO = new AseResponseDTO();
        aseResponseDTO.setResponseCode(AISecurityHandlerConstants.ASE_RESPONSE_CODE_SUCCESS);
        aseResponseDTO.setResponseMessage(AISecurityHandlerConstants.ASE_RESPONSE_CODE_SUCCESS_MESSAGE);
        return aseResponseDTO;
    }

    public CloseableHttpClient getHttpClient() {
        return httpClient;
    }

    public void setHttpClient(CloseableHttpClient httpClient) {
        this.httpClient = httpClient;
    }
}

