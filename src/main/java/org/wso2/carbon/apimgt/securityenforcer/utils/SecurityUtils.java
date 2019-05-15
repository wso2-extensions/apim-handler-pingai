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

import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMDocument;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMFactory;
import org.apache.axiom.om.OMNamespace;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axiom.soap.SOAPFactory;
import org.apache.axiom.soap.SOAPFault;
import org.apache.axiom.soap.SOAPFaultCode;
import org.apache.axiom.soap.SOAPFaultDetail;
import org.apache.axiom.soap.SOAPFaultReason;
import org.apache.axiom.soap.SOAPFaultText;
import org.apache.axiom.soap.SOAPFaultValue;
import org.apache.axiom.soap.SOAPHeader;
import org.apache.axiom.soap.SOAPHeaderBlock;
import org.apache.axis2.AxisFault;
import org.apache.axis2.Constants;
import org.apache.axis2.addressing.RelatesTo;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpHost;
import org.apache.http.ProtocolVersion;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.AuthCache;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLContexts;
import org.apache.http.conn.ssl.X509HostnameVerifier;
import org.apache.http.impl.client.BasicAuthCache;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.DefaultProxyRoutePlanner;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.synapse.MessageContext;
import org.apache.synapse.commons.json.JsonUtil;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.core.axis2.Axis2Sender;
import org.apache.synapse.transport.nhttp.NhttpConstants;
import org.apache.synapse.transport.passthru.ServerWorker;
import org.apache.synapse.transport.passthru.SourceRequest;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.wso2.carbon.apimgt.securityenforcer.dto.AISecurityHandlerConfig;
import org.wso2.carbon.apimgt.securityenforcer.internal.ServiceReferenceHolder;
import org.wso2.carbon.utils.CarbonUtils;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import javax.xml.namespace.QName;

public class SecurityUtils {

    private static final Log log = LogFactory.getLog(SecurityUtils.class);

    private static final String STRICT = "Strict";
    private static final String ALLOW_ALL = "AllowAll";
    private static final String HOST_NAME_VERIFIER = "httpclient.hostnameVerifier";

    /**
     * Return a json array with with transport headers
     *
     * @param axis2MessageContext- synapse variables
     * @param sideBandCallType - request or response message
     * @return transportHeaderArray - JSON array with all the transport headers
     */
    public static JSONArray getTransportHeaders(org.apache.axis2.context.MessageContext axis2MessageContext,
            String sideBandCallType, String correlationID) throws AISecurityException {

        TreeMap<String, String> transportHeaderMap = (TreeMap<String, String>) axis2MessageContext
                .getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);

        if (transportHeaderMap != null) {
            JSONArray transportHeaderArray = new JSONArray();
            Set<String> headerKeysSet = new HashSet<String>(transportHeaderMap.keySet());

            if (log.isDebugEnabled()) {
                log.debug("Transport headers found for the request " + correlationID + " are " + headerKeysSet);
            }
            if (ServiceReferenceHolder.getInstance().getSecurityHandlerConfig().getLimitTransportHeaders().isEnable()) {
                headerKeysSet.retainAll(
                        ServiceReferenceHolder.getInstance().getSecurityHandlerConfig().getLimitTransportHeaders()
                                .getHeaderSet());
            }

            if (AISecurityHandlerConstants.ASE_RESOURCE_REQUEST.equals(sideBandCallType)) {
                String hostValue = transportHeaderMap.get(AISecurityHandlerConstants.TRANSPORT_HEADER_HOST_NAME);
                if (hostValue != null) {
                    transportHeaderArray.add(addObj(AISecurityHandlerConstants.TRANSPORT_HEADER_HOST_NAME, hostValue));
                    headerKeysSet.remove(AISecurityHandlerConstants.TRANSPORT_HEADER_HOST_NAME);
                } else {
                    log.error("Host not found in the transport headers for the request " + correlationID);
                    throw new AISecurityException(AISecurityException.CLIENT_REQUEST_ERROR,
                            AISecurityException.CLIENT_REQUEST_ERROR_MESSAGE);
                }
            }

            for (String headerKey : headerKeysSet) {
                String headerValue = transportHeaderMap.get(headerKey);
                transportHeaderArray.add(addObj(headerKey, headerValue));
            }
            return transportHeaderArray;
        } else {
            log.error("No Transport headers found for the request " + correlationID);
            throw new AISecurityException(AISecurityException.CLIENT_REQUEST_ERROR,
                    AISecurityException.CLIENT_REQUEST_ERROR_MESSAGE);
        }
    }

    private static JSONObject addObj(String key, Object value) {
        JSONObject obj = new JSONObject();
        obj.put(key, value);
        return obj;
    }

    /**
     * Return a CloseableHttpClient instance
     *
     * @param protocol- service endpoint protocol. It can be http/https
     * @param dataPublisherConfiguration - DataPublisher Configurations
     *          maxPerRoute- maximum number of HTTP connections allowed across all routes.
     *          maxOpenConnections- maximum number of HTTP connections allowed for a route.
     *          connectionTimeout- the time to establish the connection with the remote host
     * @param proxyConfiguration- proxy configurations
     * @return CloseableHttpClient
     */
    public static CloseableHttpClient getHttpClient(String protocol,
            AISecurityHandlerConfig.DataPublisherConfig dataPublisherConfiguration,
            AISecurityHandlerConfig.ProxyConfig proxyConfiguration) throws AISecurityException {

        PoolingHttpClientConnectionManager pool;
        try {
            pool = SecurityUtils.getPoolingHttpClientConnectionManager(protocol);

        } catch (Exception e) {
            throw new AISecurityException(e);
        }

        pool.setMaxTotal(dataPublisherConfiguration.getMaxOpenConnections());
        pool.setDefaultMaxPerRoute(dataPublisherConfiguration.getMaxPerRoute());

        RequestConfig params = RequestConfig.custom()
                .setConnectTimeout(dataPublisherConfiguration.getConnectionTimeout() * 1000)
                .setSocketTimeout((dataPublisherConfiguration.getConnectionTimeout() + 10) * 10000).build();

        if (proxyConfiguration.isProxyEnabled()) {
            HttpHost proxy = new HttpHost(proxyConfiguration.getHostname(), proxyConfiguration.getPort());
            DefaultProxyRoutePlanner routePlanner = new DefaultProxyRoutePlanner(proxy);
            AuthCache authCache = new BasicAuthCache();
            CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
            credentialsProvider.setCredentials(
                    new AuthScope(proxyConfiguration.getHostname(), proxyConfiguration.getPort(), AuthScope.ANY_HOST,
                            null), new UsernamePasswordCredentials(proxyConfiguration.getUserName(),
                            proxyConfiguration.getPassword()));
            HttpClientContext context = HttpClientContext.create();
            context.setCredentialsProvider(credentialsProvider);
            context.setAuthCache(authCache);

            return HttpClients.custom().setConnectionManager(pool).setDefaultCredentialsProvider(credentialsProvider)
                    .setRoutePlanner(routePlanner).setDefaultRequestConfig(params).build();
        } else {
            return HttpClients.custom().setConnectionManager(pool).setDefaultRequestConfig(params).build();
        }
    }

    /**
     * Return a PoolingHttpClientConnectionManager instance
     *
     * @param protocol- service endpoint protocol. It can be http/https
     * @return
     */
    private static PoolingHttpClientConnectionManager getPoolingHttpClientConnectionManager(String protocol)
            throws KeyStoreException, NoSuchAlgorithmException, KeyManagementException, IOException,
            CertificateException {

        PoolingHttpClientConnectionManager poolManager;
        if ("https".equals(protocol)) {

            String keyStorePath = CarbonUtils.getServerConfiguration().getFirstProperty("Security.TrustStore.Location");
            String keyStorePassword = CarbonUtils.getServerConfiguration()
                    .getFirstProperty("Security.TrustStore.Password");
            KeyStore trustStore = KeyStore.getInstance("JKS");
            trustStore.load(new FileInputStream(keyStorePath), keyStorePassword.toCharArray());

            SSLContext sslContext = SSLContexts.custom().loadTrustMaterial(trustStore).build();

            X509HostnameVerifier hostnameVerifier;
            String hostnameVerifierOption = System.getProperty(HOST_NAME_VERIFIER);

            if (ALLOW_ALL.equalsIgnoreCase(hostnameVerifierOption)) {
                hostnameVerifier = SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER;
            } else if (STRICT.equalsIgnoreCase(hostnameVerifierOption)) {
                hostnameVerifier = SSLConnectionSocketFactory.STRICT_HOSTNAME_VERIFIER;
            } else {
                hostnameVerifier = SSLConnectionSocketFactory.BROWSER_COMPATIBLE_HOSTNAME_VERIFIER;
            }

            SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslContext, hostnameVerifier);

            Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
                    .register("https", sslsf).build();
            poolManager = new PoolingHttpClientConnectionManager(socketFactoryRegistry);

        } else {
            poolManager = new PoolingHttpClientConnectionManager();
        }

        return poolManager;

    }

    /**
     * Extracts the IP from Message Context.
     *
     * @param axis2MessageContext Axis2 Message Context.
     * @return IP as a String.
     */
    public static String getIp(org.apache.axis2.context.MessageContext axis2MessageContext) {

        //Set transport headers of the message
        TreeMap<String, String> transportHeaderMap = (TreeMap<String, String>) axis2MessageContext
                .getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);
        // Assigning an Empty String so that when doing comparisons, .equals method can be used without explicitly
        // checking for nullity.
        String remoteIP = "";
        //Check whether headers map is null and x forwarded for header is present
        if (transportHeaderMap != null) {
            remoteIP = transportHeaderMap.get("X-Forwarded-For");
        }

        //Setting IP of the client by looking at x forded for header and  if it's empty get remote address
        if (remoteIP != null && !remoteIP.isEmpty()) {
            if (remoteIP.indexOf(",") > 0) {
                remoteIP = remoteIP.substring(0, remoteIP.indexOf(","));
            }
        } else {
            remoteIP = (String) axis2MessageContext.getProperty(org.apache.axis2.context.MessageContext.REMOTE_ADDR);
        }

        return remoteIP;
    }

    /**
     * return existing correlation ID in the message context or set new correlation ID to the message context.
     *
     * @param messageContext synapse message context
     * @return correlation ID
     */
    public static String getAndSetCorrelationID(MessageContext messageContext) {
        Object correlationObj = messageContext.getProperty("am.correlationID");
        String correlationID;
        if (correlationObj != null) {
            correlationID = (String) correlationObj;
            if (log.isDebugEnabled()) {
                log.debug("Correlation ID is available in the message context.");
            }
        } else {
            correlationID = UUID.randomUUID().toString();
            messageContext.setProperty("am.correlationID", correlationID);
            if (log.isDebugEnabled()) {
                log.debug(
                        "Correlation ID is not available in the message context. Setting a new ID to message context.");
            }
        }
        return correlationID;
    }

    /**
     * Return the httpVersion of the request
     *
     * @param axis2MessageContext - synapse variables
     * @return
     */
    public static String getHttpVersion(org.apache.axis2.context.MessageContext axis2MessageContext) {

        ServerWorker worker = (ServerWorker) axis2MessageContext.getProperty(Constants.OUT_TRANSPORT_INFO);
        SourceRequest sourceRequest = worker.getSourceRequest();
        ProtocolVersion httpProtocolVersion = sourceRequest.getVersion();

        return httpProtocolVersion.getMajor() + AISecurityHandlerConstants.HTTP_VERSION_CONNECTOR + httpProtocolVersion
                .getMinor();
    }

    public static OMElement getFaultPayload(AISecurityException e) {
        OMFactory fac = OMAbstractFactory.getOMFactory();
        OMNamespace ns = fac.createOMNamespace(AISecurityHandlerConstants.API_SECURITY_NS,
                AISecurityHandlerConstants.API_SECURITY_NS_PREFIX);
        OMElement payload = fac.createOMElement("fault", ns);
        OMElement errorCode = fac.createOMElement("code", ns);
        errorCode.setText(String.valueOf(e.getErrorCode()));
        OMElement errorMessage = fac.createOMElement("message", ns);
        errorMessage.setText(AISecurityException.getAuthenticationFailureMessage(e.getErrorCode()));
        OMElement errorDetail = fac.createOMElement("description", ns);
        errorDetail.setText(e.getMessage());

        payload.addChild(errorCode);
        payload.addChild(errorMessage);
        payload.addChild(errorDetail);
        return payload;
    }

    public static void setFaultPayload(org.apache.synapse.MessageContext messageContext, OMElement payload) {
        org.apache.axis2.context.MessageContext axis2MC = ((Axis2MessageContext) messageContext).
                getAxis2MessageContext();
        JsonUtil.removeJsonPayload(axis2MC);
        messageContext.getEnvelope().getBody().addChild(payload);
        Map headers = (Map) axis2MC.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);
        String acceptType = (String) headers.get(HttpHeaders.ACCEPT);
        Set<String> supportedMimes = new HashSet<String>(
                Arrays.asList("application/x-www-form-urlencoded", "multipart/form-data", "text/html",
                        "application/xml", "text/xml", "application/soap+xml", "text/plain", "application/json",
                        "application/json/badgerfish", "text/javascript"));

        // If an Accept header has been provided and is supported by the Gateway
        if (!StringUtils.isEmpty(acceptType) && supportedMimes.contains(acceptType)) {
            axis2MC.setProperty(Constants.Configuration.MESSAGE_TYPE, acceptType);
        } else {
            // If there isn't Accept Header in the request, will use error_message_type property
            // from _auth_failure_handler_.xml file
            if (messageContext.getProperty("error_message_type") != null) {
                axis2MC.setProperty(Constants.Configuration.MESSAGE_TYPE,
                        messageContext.getProperty("error_message_type"));
            }
        }
    }

    public static void sendFault(org.apache.synapse.MessageContext messageContext, int status) {
        org.apache.axis2.context.MessageContext axis2MC = ((Axis2MessageContext) messageContext).
                getAxis2MessageContext();

        axis2MC.setProperty(NhttpConstants.HTTP_SC, status);
        messageContext.setResponse(true);
        messageContext.setProperty("RESPONSE", "true");
        messageContext.setTo(null);
        axis2MC.removeProperty("NO_ENTITY_BODY");

        // Always remove the ContentType - Let the formatter do its thing
        axis2MC.removeProperty(Constants.Configuration.CONTENT_TYPE);
        Map headers = (Map) axis2MC.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);
        if (headers != null) {
            headers.remove(HttpHeaders.AUTHORIZATION);
            headers.remove(HttpHeaders.AUTHORIZATION);

            headers.remove(HttpHeaders.HOST);
        }
        Axis2Sender.sendBack(messageContext);
    }

    public static void setSOAPFault(org.apache.synapse.MessageContext messageContext, String code, String reason,
            String detail) {
        SOAPFactory factory = (messageContext.isSOAP11() ?
                OMAbstractFactory.getSOAP11Factory() :
                OMAbstractFactory.getSOAP12Factory());

        OMDocument soapFaultDocument = factory.createOMDocument();
        SOAPEnvelope faultEnvelope = factory.getDefaultFaultEnvelope();
        soapFaultDocument.addChild(faultEnvelope);

        SOAPFault fault = faultEnvelope.getBody().getFault();
        if (fault == null) {
            fault = factory.createSOAPFault();
        }

        SOAPFaultCode faultCode = factory.createSOAPFaultCode();
        if (messageContext.isSOAP11()) {
            faultCode.setText(new QName(fault.getNamespace().getNamespaceURI(), code));
        } else {
            SOAPFaultValue value = factory.createSOAPFaultValue(faultCode);
            value.setText(new QName(fault.getNamespace().getNamespaceURI(), code));
        }
        fault.setCode(faultCode);

        SOAPFaultReason faultReason = factory.createSOAPFaultReason();
        if (messageContext.isSOAP11()) {
            faultReason.setText(reason);
        } else {
            SOAPFaultText text = factory.createSOAPFaultText();
            text.setText(reason);
            text.setLang("en");
            faultReason.addSOAPText(text);
        }
        fault.setReason(faultReason);

        SOAPFaultDetail soapFaultDetail = factory.createSOAPFaultDetail();
        soapFaultDetail.setText(detail);
        fault.setDetail(soapFaultDetail);

        // set the all headers of original SOAP Envelope to the Fault Envelope
        if (messageContext.getEnvelope() != null) {
            SOAPHeader soapHeader = messageContext.getEnvelope().getHeader();
            if (soapHeader != null) {
                for (Iterator iterator = soapHeader.examineAllHeaderBlocks(); iterator.hasNext(); ) {
                    Object o = iterator.next();
                    if (o instanceof SOAPHeaderBlock) {
                        SOAPHeaderBlock header = (SOAPHeaderBlock) o;
                        faultEnvelope.getHeader().addChild(header);
                    } else if (o instanceof OMElement) {
                        faultEnvelope.getHeader().addChild((OMElement) o);
                    }
                }
            }
        }

        try {
            messageContext.setEnvelope(faultEnvelope);
        } catch (AxisFault af) {
            log.error("Error while setting SOAP fault as payload", af);
            return;
        }

        if (messageContext.getFaultTo() != null) {
            messageContext.setTo(messageContext.getFaultTo());
        } else if (messageContext.getReplyTo() != null) {
            messageContext.setTo(messageContext.getReplyTo());
        } else {
            messageContext.setTo(null);
        }

        // set original messageID as relatesTo
        if (messageContext.getMessageID() != null) {
            RelatesTo relatesTo = new RelatesTo(messageContext.getMessageID());
            messageContext.setRelatesTo(new RelatesTo[] { relatesTo });
        }
    }

    public static void updateLatency(Long latency, MessageContext messageContext) {
        Object otherLatency = messageContext.getProperty("other_latency");
        if (otherLatency == null) {
            messageContext.setProperty("other_latency", TimeUnit.NANOSECONDS.toMillis(latency));
        } else {
            messageContext.setProperty("other_latency", TimeUnit.NANOSECONDS.toMillis((long) otherLatency + latency));
        }

    }
}
