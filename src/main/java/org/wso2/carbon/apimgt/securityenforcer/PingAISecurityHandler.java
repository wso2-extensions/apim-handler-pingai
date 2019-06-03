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

package org.wso2.carbon.apimgt.securityenforcer;

import org.apache.axis2.AxisFault;
import org.apache.axis2.Constants;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpStatus;
import org.apache.synapse.Mediator;
import org.apache.synapse.MessageContext;
import org.apache.synapse.SynapseConstants;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.rest.AbstractHandler;
import org.apache.synapse.rest.RESTConstants;
import org.apache.synapse.transport.passthru.PassThroughConstants;
import org.apache.synapse.transport.passthru.util.RelayUtils;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.wso2.carbon.apimgt.gateway.handlers.Utils;
import org.wso2.carbon.apimgt.gateway.handlers.security.AuthenticationContext;
import org.wso2.carbon.apimgt.securityenforcer.internal.ServiceReferenceHolder;
import org.wso2.carbon.apimgt.securityenforcer.utils.AISecurityException;
import org.wso2.carbon.apimgt.securityenforcer.utils.AISecurityHandlerConstants;
import org.wso2.carbon.apimgt.securityenforcer.utils.SecurityUtils;

import java.util.Date;
import java.util.TreeMap;

/**
 * This class is Handling the Ping Identity analysis. This class will use inside each API as securityenforcer.
 * It will fetch some of meta data from incoming message and send them to PING API Security Enforcer.
 */
public class PingAISecurityHandler extends AbstractHandler {

    private static final Log log = LogFactory.getLog(PingAISecurityHandler.class);

    public PingAISecurityHandler() {
        log.debug("Ping AI Security Handler initialized");
    }

    /**
     * This method will handle the request. For every request gateway receives, this is method will invoke first for this handler
     */
    @Override
    public boolean handleRequest(MessageContext messageContext) {

        long handleRequestStartTime = System.nanoTime();
        String requestCorrelationID = SecurityUtils.getAndSetCorrelationID(messageContext);
        try {
            if (authenticate(messageContext, requestCorrelationID)) {
                if (log.isDebugEnabled()) {
                    log.debug(
                            "Handle Request Time for the request " + requestCorrelationID + " is " + (System.nanoTime()
                                    - handleRequestStartTime) + " Nano seconds");
                }
                SecurityUtils.updateLatency(System.nanoTime() - handleRequestStartTime, messageContext);
                return true;
            }
        } catch (AISecurityException e) {
            if (log.isDebugEnabled()) {
                long difference = System.nanoTime() - handleRequestStartTime;
                String messageDetails = logMessageDetails(messageContext);
                log.debug("Request " + requestCorrelationID + " failed. " + messageDetails + ", elapsedTimeInNano"
                        + difference);
            }
            handleAuthFailure(messageContext, e);
        } finally {
            SecurityUtils.updateLatency(System.nanoTime() - handleRequestStartTime, messageContext);
        }
        return false;
    }

    /**
     * This method will handle the response.
     */
    @Override
    public boolean handleResponse(MessageContext messageContext) {
        long handleResponseStartTime = System.nanoTime();
        try {
            sendResponseDetailsToASE(messageContext);
            if (log.isDebugEnabled()) {
                log.debug("Handle Response Time " + (System.nanoTime() - handleResponseStartTime));
            }
            SecurityUtils.updateLatency(System.nanoTime() - handleResponseStartTime, messageContext);
            return true;

        } catch (AISecurityException e) {
            if (log.isDebugEnabled()) {
                long difference = (System.nanoTime() - handleResponseStartTime);
                String messageDetails = logMessageDetails(messageContext);
                log.debug("Call to Ping ASE : " + messageDetails + ", elapsedTimeInNanoseconds=" + difference);
            }
            handleAuthFailure(messageContext, e);
        }
        return false;
    }

    /**
     * This method will return true if the request is authorized.
     */
    private boolean authenticate(MessageContext messageContext, String requestCorrelationID)
            throws AISecurityException {

        JSONObject requestMetaData = extractRequestMetadata(messageContext);

        if (log.isDebugEnabled()) {
            log.debug(
                    "Metadata extracted for the request " + requestCorrelationID + " is " + requestMetaData.toString());
        }

        return ServiceReferenceHolder.getInstance().getRequestPublisher()
                .verifyRequest(requestMetaData, requestCorrelationID);
    }

    private void sendResponseDetailsToASE(MessageContext messageContext) throws AISecurityException {
        //getAndSetCorrelationID() method cannot be used here. if the correlation ID is not present in the messageContext,
        //method will add a new id and send. but when sending the backend response to ASE, this id should correlate to the
        //handleRequest id. therefore property is read and if not found, an error is thrown.
        Object responseCorrelationID = messageContext.getProperty("am.correlationID");
        JSONObject responseMetaData = extractResponseMetadata(messageContext);
        if (responseCorrelationID != null) {
            if (log.isDebugEnabled()) {
                log.debug("Metadata extracted for the response " + responseCorrelationID + " is " + responseMetaData
                        .toString());
            }
            ServiceReferenceHolder.getInstance().getResponsePublisher()
                    .publishResponse(responseMetaData, (String) responseCorrelationID);
        } else {
            log.error("Correlation ID not found for the request with responseMetadata " + responseMetaData.toString());
            throw new AISecurityException(AISecurityException.CLIENT_REQUEST_ERROR,
                    AISecurityException.CLIENT_REQUEST_ERROR_MESSAGE);
        }
    }

    /**
     * This method will extract the required meta data from the synapse context.
     */
    JSONObject extractRequestMetadata(MessageContext messageContext) throws AISecurityException {

        String requestCorrelationID = SecurityUtils.getAndSetCorrelationID(messageContext);

        org.apache.axis2.context.MessageContext axis2MessageContext = ((Axis2MessageContext) messageContext)
                .getAxis2MessageContext();

        JSONArray transportHeaders = SecurityUtils
                .getTransportHeaders(axis2MessageContext, AISecurityHandlerConstants.ASE_RESOURCE_REQUEST,
                        requestCorrelationID);

        AuthenticationContext authContext = (AuthenticationContext) messageContext.getProperty("__API_AUTH_CONTEXT");

        //OAuth header may not be included in the transport headers. Therefore API key is used.
        String apiKey = authContext.getApiKey();
        String tier = authContext.getTier();
        if (apiKey != null && !AISecurityHandlerConstants.UNAUTHENTICATED_TIER.equals(tier)) {
            transportHeaders.add(SecurityUtils.addObj(AISecurityHandlerConstants.API_KEY_HEADER_NAME, apiKey));
        }

        String requestOriginIP = SecurityUtils.getIp(axis2MessageContext);
        int requestOriginPort = AISecurityHandlerConstants.DUMMY_REQUEST_PORT;
        String requestMethod = (String) axis2MessageContext.getProperty(AISecurityHandlerConstants.HTTP_METHOD_STRING);
        String requestPath = (String) axis2MessageContext.getProperty(AISecurityHandlerConstants.API_BASEPATH_STRING);
        String requestHttpVersion = SecurityUtils.getHttpVersion(axis2MessageContext);

        return createRequestJson(requestMethod, requestPath, requestHttpVersion, requestOriginIP, requestOriginPort,
                transportHeaders);
    }

    JSONObject extractResponseMetadata(MessageContext messageContext) throws AISecurityException {

        String requestCorrelationID = SecurityUtils.getAndSetCorrelationID(messageContext);

        org.apache.axis2.context.MessageContext axis2MessageContext = ((Axis2MessageContext) messageContext)
                .getAxis2MessageContext();

        JSONArray transportHeaders = SecurityUtils
                .getTransportHeaders(axis2MessageContext, AISecurityHandlerConstants.ASE_RESOURCE_RESPONSE,
                        requestCorrelationID);

        String requestHttpVersion = SecurityUtils.getHttpVersion(axis2MessageContext);
        String responseCode = Integer.toString(
                (Integer) axis2MessageContext.getProperty(AISecurityHandlerConstants.BACKEND_RESPONSE_STATUS_CODE));
        String responseMessage = (String) axis2MessageContext
                .getProperty(AISecurityHandlerConstants.BACKEND_RESPONSE_STATUS_MESSAGE);

        return createResponseJson(responseCode, responseMessage, requestHttpVersion, transportHeaders);
    }

    /**
     * This method will format the extracted details to a given json format
     */
    private JSONObject createRequestJson(String requestMethod, String requestPath, String requestHttpVersion,
            String requestOriginIP, int requestOriginPort, JSONArray transportHeaders) {

        JSONObject aseRequestBodyJson = new JSONObject();
        aseRequestBodyJson.put(AISecurityHandlerConstants.JSON_KEY_SOURCE_IP, requestOriginIP);
        aseRequestBodyJson.put(AISecurityHandlerConstants.JSON_KEY_SOURCE_PORT, requestOriginPort);
        aseRequestBodyJson.put(AISecurityHandlerConstants.JSON_KEY_METHOD, requestMethod);
        aseRequestBodyJson.put(AISecurityHandlerConstants.JSON_KEY_API_BASEPATH, requestPath);
        aseRequestBodyJson.put(AISecurityHandlerConstants.JSON_KEY_HTTP_VERSION, requestHttpVersion);
        aseRequestBodyJson.put(AISecurityHandlerConstants.JSON_KEY_HEADERS, transportHeaders);
        return aseRequestBodyJson;
    }

    private JSONObject createResponseJson(String responseCode, String responseMessage, String requestHttpVersion,
            JSONArray transportHeaders) {

        JSONObject aseResponseBodyJson = new JSONObject();
        aseResponseBodyJson.put(AISecurityHandlerConstants.JSON_KEY_RESPONSE_CODE, responseCode);
        aseResponseBodyJson.put(AISecurityHandlerConstants.JSON_KEY_RESPONSE_STATUS, responseMessage);
        aseResponseBodyJson.put(AISecurityHandlerConstants.JSON_KEY_HTTP_VERSION, requestHttpVersion);
        aseResponseBodyJson.put(AISecurityHandlerConstants.JSON_KEY_HEADERS, transportHeaders);
        return aseResponseBodyJson;
    }

    protected void handleAuthFailure(MessageContext messageContext, AISecurityException e) {

        Mediator sequence = messageContext.getSequence("_auth_failure_handler_");
        // Invoke the custom error handler specified by the user
        if (sequence != null && !sequence.mediate(messageContext)) {
            // If needed user should be able to prevent the rest of the fault handling
            // logic from getting executed
            return;
        }

        org.apache.axis2.context.MessageContext axis2MC = ((Axis2MessageContext) messageContext).
                getAxis2MessageContext();
        // This property need to be set to avoid sending the content in pass-through pipe (request message)
        // as the response.
        axis2MC.setProperty(PassThroughConstants.MESSAGE_BUILDER_INVOKED, Boolean.TRUE);
        try {
            RelayUtils.consumeAndDiscardMessage(axis2MC);
        } catch (AxisFault axisFault) {
            //In case of an error it is logged and the process is continued because we're setting a fault message in the payload.
            log.error("Error occurred while consuming and discarding the message", axisFault);
        }
        axis2MC.setProperty(Constants.Configuration.MESSAGE_TYPE, "application/soap+xml");
        int status;
        String errorMessage;
        if (e.getErrorCode() == AISecurityException.HANDLER_ERROR) {
            status = HttpStatus.SC_INTERNAL_SERVER_ERROR;
            errorMessage = "Internal Sever Error";
        } else if (e.getErrorCode() == AISecurityException.ACCESS_REVOKED) {
            status = HttpStatus.SC_FORBIDDEN;
            errorMessage = "Forbidden";
        } else if (e.getErrorCode() == AISecurityException.CLIENT_REQUEST_ERROR) {
            status = HttpStatus.SC_BAD_REQUEST;
            errorMessage = "Bad Request";
        } else {
            status = HttpStatus.SC_UNAUTHORIZED;
            errorMessage = "Unauthorized";
        }

        messageContext.setProperty(SynapseConstants.ERROR_CODE, status);
        messageContext.setProperty(SynapseConstants.ERROR_MESSAGE, errorMessage);
        messageContext.setProperty(SynapseConstants.ERROR_EXCEPTION, e);

        if (messageContext.isDoingPOX() || messageContext.isDoingGET()) {
            Utils.setFaultPayload(messageContext, SecurityUtils.getFaultPayload(e));
        } else {
            Utils.setSOAPFault(messageContext, "Client", "Authentication Failure from AI Security Handler",
                    e.getMessage());
        }
        Utils.sendFault(messageContext, status);
    }

    private String logMessageDetails(MessageContext messageContext) {

        String applicationName = (String) messageContext.getProperty(AISecurityHandlerConstants.APPLICATION_NAME);
        String endUserName = (String) messageContext.getProperty(AISecurityHandlerConstants.END_USER_NAME);
        Date incomingReqTime = null;
        org.apache.axis2.context.MessageContext axisMC = ((Axis2MessageContext) messageContext)
                .getAxis2MessageContext();
        String logMessage = "API call failed reason=Ping_AI_authentication_failure";
        String logID = axisMC.getOptions().getMessageId();
        if (applicationName != null) {
            logMessage = logMessage + " belonging to appName=" + applicationName;
        }
        if (endUserName != null) {
            logMessage = logMessage + " userName=" + endUserName;
        }
        if (logID != null) {
            logMessage = logMessage + " transactionId=" + logID;
        }
        String userAgent = (String) ((TreeMap) axisMC
                .getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS)).get("User-Agent");
        if (userAgent != null) {
            logMessage = logMessage + " with userAgent=" + userAgent;
        }
        String accessToken = (String) ((TreeMap) axisMC
                .getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS))
                .get(AISecurityHandlerConstants.AUTHORIZATION);
        if (accessToken != null) {
            logMessage = logMessage + " with accessToken=" + accessToken;
        }
        String requestURI = (String) messageContext.getProperty(RESTConstants.REST_FULL_REQUEST_PATH);
        if (requestURI != null) {
            logMessage = logMessage + " for requestURI=" + requestURI;
        }
        String requestReceivedTime = (String) ((Axis2MessageContext) messageContext).getAxis2MessageContext()
                .getProperty(AISecurityHandlerConstants.REQUEST_RECEIVED_TIME);
        if (requestReceivedTime != null) {
            long reqIncomingTimestamp = Long.parseLong(requestReceivedTime);
            incomingReqTime = new Date(reqIncomingTimestamp);
            logMessage = logMessage + " at time=" + incomingReqTime;
        }

        String remoteIP = (String) axisMC.getProperty(org.apache.axis2.context.MessageContext.REMOTE_ADDR);
        if (remoteIP != null) {
            logMessage = logMessage + " from clientIP=" + remoteIP;
        }
        return logMessage;
    }

}

