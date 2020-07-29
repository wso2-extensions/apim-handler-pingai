/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpResponse;
import org.apache.http.StatusLine;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.json.simple.JSONObject;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;
import org.wso2.carbon.apimgt.securityenforcer.dto.AISecurityHandlerConfig;
import org.wso2.carbon.apimgt.securityenforcer.utils.AISecurityException;
import org.wso2.carbon.apimgt.securityenforcer.utils.AISecurityHandlerConstants;
import org.wso2.carbon.apimgt.securityenforcer.utils.SecurityUtils;

/**
 * HttpDataPublisher class is here to verifyRequest PingAI data to Ping
 * Intelligence ASE via http requests. This will create a http client and a
 * pool. If proxy is enabled for the endpoint, client is changed accordingly.
 */
public class HttpDataPublisher {

    private static final Log log = LogFactory.getLog(HttpDataPublisher.class);

    private CloseableHttpClient httpClient;
    private String authToken;
    private String endPoint;
    private AISecurityHandlerConfig.AseConfig aseConfig;

    public HttpDataPublisher(AISecurityHandlerConfig.AseConfig aseConfiguration,
            AISecurityHandlerConfig.DataPublisherConfig dataPublisherConfiguration,
            AISecurityHandlerConfig.ModelCreationEndpoint modelCreationConfiguration) throws AISecurityException {

        String protocol;
        try {
            protocol = new URL(aseConfiguration.getEndPoint()).getProtocol();
        } catch (MalformedURLException e) {
            log.error("Error when getting the ASE request protocol", e);
            throw new AISecurityException(AISecurityException.HANDLER_ERROR, AISecurityException.HANDLER_ERROR_MESSAGE,
                    e);
        }
        httpClient = SecurityUtils.getHttpClient(protocol, dataPublisherConfiguration);
        setAuthToken(aseConfiguration.getAseToken());
        setEndPoint(aseConfiguration.getEndPoint());
        aseConfig = aseConfiguration;
    }

    public HttpDataPublisher(String endPoint, String authToken) {
        setAuthToken(authToken);
        setEndPoint(endPoint);
    }

    public int publish(JSONObject data, String correlationID, String resource) {
        HttpPost postRequest = new HttpPost(endPoint + "/ase/" + resource);
        postRequest.addHeader(AISecurityHandlerConstants.ASE_TOKEN_HEADER, authToken);
        postRequest.addHeader(AISecurityHandlerConstants.X_CORRELATION_ID_HEADER, correlationID);

        CloseableHttpResponse response = null;
        int aseResponseCode = 200;

        try {
            postRequest.setEntity(new StringEntity(data.toString()));
            long publishingStartTime = System.nanoTime();
            response = httpClient.execute(postRequest);
            long publishingEndTime = System.nanoTime();

            if (response != null) {
                aseResponseCode = response.getStatusLine().getStatusCode();

                switch (aseResponseCode) {
                    case AISecurityHandlerConstants.ASE_RESPONSE_CODE_INCORRECT_JSON:
                        log.error("Incorrect JSON format sent for the ASE from the request " + correlationID);
                        break;
                    case AISecurityHandlerConstants.ASE_RESPONSE_CODE_UNKNOWN_API:
                        log.error("Unknown API for the request " + correlationID);
                        break;
                    case AISecurityHandlerConstants.ASE_RESPONSE_CODE_UNAUTHORIZED:
                        log.error("Authentication failure (ASE-Token) for the request " + correlationID);
                        break;
                    case AISecurityHandlerConstants.ASE_RESPONSE_CODE_FORBIDDEN:
                        if (log.isDebugEnabled()) {
                            log.debug("Forbidden code sent from the ASE for the " + resource + " " + correlationID);
                        }
                        break;
                    case AISecurityHandlerConstants.ASE_RESPONSE_CODE_SUCCESS:
                        if (log.isDebugEnabled()) {
                            log.debug("Success code sent from the ASE for the " + resource + " " + correlationID);
                        }
                        break;
                    default:
                        log.error("ASE responded with " + aseResponseCode + " for the request " + correlationID);
                        break;
                }

                if (log.isDebugEnabled()) {
                    log.debug("PING ASE Response for method: " + resource + ", correlation ID " + correlationID
                            + " , response: " + response.toString()
                            + ", connection time for the request in nano seconds is "
                            + (publishingEndTime - publishingStartTime));
                }
            } else {
                log.error("Null response returned from ASE for the request " + correlationID);
            }
        } catch (Exception ex) {
            aseConfig.shiftEndpoint();
            endPoint = aseConfig.getEndPoint();
            setEndPoint(aseConfig.getEndPoint());
            log.error("Error sending the HTTP Request with id " + correlationID, ex);
        } finally {
            if (response != null) {
                try {
                    response.close();
                } catch (IOException e) {
                    log.error("Error when closing the response of the request id " + correlationID, e);
                }
            }
        }
        return aseResponseCode;
    }

    public StatusLine publishToASEManagementAPI(String modelCreationEndpoint, String type, Object request) {

        HttpResponse response = null;
        int aseManagementEndpointPort;
        String aseManagementEndpointProtocol;

        try {
            aseManagementEndpointPort = new URL(modelCreationEndpoint).getPort();
            aseManagementEndpointProtocol = new URL(modelCreationEndpoint).getProtocol();
            HttpClient aseManagementEndpointHttpClient = APIUtil.getHttpClient(aseManagementEndpointPort,
                    aseManagementEndpointProtocol);

            if (AISecurityHandlerConstants.CREATE.equals(type)) {
                HttpPost postRequest = (HttpPost) request;
                response = aseManagementEndpointHttpClient.execute(postRequest);
                log.debug("ASE Management API create request sent");
            } else if (AISecurityHandlerConstants.UPDATE.equals(type)) {
                HttpPut putRequest = (HttpPut) request;
                response = aseManagementEndpointHttpClient.execute(putRequest);
                log.debug("ASE Management API update request sent");
            } else if (AISecurityHandlerConstants.LIST.equals(type)) {
                HttpGet getRequest = (HttpGet) request;
                response = aseManagementEndpointHttpClient.execute(getRequest);
                log.debug("ASE Management API list request sent");
            } else if (AISecurityHandlerConstants.DELETE.equals(type)) {
                HttpDelete deleteRequest = (HttpDelete) request;
                response = aseManagementEndpointHttpClient.execute(deleteRequest);
                log.debug("ASE Management API delete request sent");
            }
            if (response != null) {
                if (log.isDebugEnabled()) {
                    log.debug("ASE responded with " + response.getStatusLine().getReasonPhrase() + " with code "
                            + response.getStatusLine().getStatusCode());
                }
                return response.getStatusLine();
            }
        } catch (MalformedURLException e) {
            log.error("Error occurred while retrieving ASE management endpoint configuration", e);
        } catch (Exception e) {
            log.error("Error occurred while publishing " + type + " request to ASE Management API", e);
        }
        return null;
    }

    private void setAuthToken(String authToken) {
        this.authToken = authToken;
    }

    private void setEndPoint(String endPoint) {
        this.endPoint = endPoint;
    }

    public CloseableHttpClient getHttpClient() {
        return httpClient;
    }

    public void setHttpClient(CloseableHttpClient httpClient) {
        this.httpClient = httpClient;
    }

}
