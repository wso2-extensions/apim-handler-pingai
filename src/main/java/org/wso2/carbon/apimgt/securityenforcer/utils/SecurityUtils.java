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

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;

import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMFactory;
import org.apache.axiom.om.OMNamespace;
import org.apache.axis2.Constants;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.ProtocolVersion;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.scheme.PlainSocketFactory;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLContexts;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.conn.ssl.X509HostnameVerifier;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.impl.conn.tsccm.ThreadSafeClientConnManager;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpParams;
import org.apache.synapse.MessageContext;
import org.apache.synapse.transport.passthru.ServerWorker;
import org.apache.synapse.transport.passthru.SourceRequest;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.securityenforcer.ASEResponseStore;
import org.wso2.carbon.apimgt.securityenforcer.dto.AISecurityHandlerConfig;
import org.wso2.carbon.apimgt.securityenforcer.internal.ServiceReferenceHolder;
import org.wso2.carbon.utils.CarbonUtils;

public class SecurityUtils {

    private static final Log log = LogFactory.getLog(SecurityUtils.class);

    private static final String STRICT = "Strict";
    private static final String ALLOW_ALL = "AllowAll";
    private static final String HOST_NAME_VERIFIER = "httpclient.hostnameVerifier";

    /**
     * Return a json array with with transport headers
     *
     * @param transportHeadersMap- transport headers map
     * @param sideBandCallType - request or response message
     * @return transportHeaderArray - JSON array with all the transport headers
     */
    public static JSONArray getTransportHeaders(TreeMap<String, String> transportHeadersMap,
            String sideBandCallType, String correlationID) throws AISecurityException {

        if (transportHeadersMap != null) {
            JSONArray transportHeadersArray = new JSONArray();
            Set<String> headerKeysSet = new TreeSet<String>(String.CASE_INSENSITIVE_ORDER);
            headerKeysSet.addAll(transportHeadersMap.keySet());
            headerKeysSet.remove(AISecurityHandlerConstants.COOKIE_KEY_NAME);

            if (log.isDebugEnabled()) {
                log.debug("Transport headers found for the request " + correlationID + " are " + headerKeysSet);
            }

            if (AISecurityHandlerConstants.ASE_RESOURCE_REQUEST.equals(sideBandCallType)) {
                String hostValue = transportHeadersMap.get(AISecurityHandlerConstants.TRANSPORT_HEADER_HOST_NAME);
                if (hostValue != null) {
                    transportHeadersArray.add(addObj(AISecurityHandlerConstants.TRANSPORT_HEADER_HOST_NAME, hostValue));
                    headerKeysSet.remove(AISecurityHandlerConstants.TRANSPORT_HEADER_HOST_NAME);
                } else {
                    log.error("Host not found in the transport headers for the request " + correlationID);
                    throw new AISecurityException(AISecurityException.CLIENT_REQUEST_ERROR,
                            AISecurityException.CLIENT_REQUEST_ERROR_MESSAGE);
                }
            }

            AISecurityHandlerConfig.LimitTransportHeaders limitTransportHeadersConfig =
                    ServiceReferenceHolder.getInstance().getSecurityHandlerConfig().getLimitTransportHeaders();
            if (limitTransportHeadersConfig.isEnable()) {
                Set<String> allowedTransportHeadersKeySet = limitTransportHeadersConfig.getHeaderSet();
                for (String headerKey : headerKeysSet) {
                    if (allowedTransportHeadersKeySet.contains(headerKey)) {
                        String headerValue = transportHeadersMap.get(headerKey);
                        transportHeadersArray.add(addObj(headerKey, headerValue));
                    }
                }
            } else {
                for (String headerKey : headerKeysSet) {
                    String headerValue = transportHeadersMap.get(headerKey);
                    transportHeadersArray.add(addObj(headerKey, headerValue));
                }
            }

            return transportHeadersArray;
        } else {
            log.error("No Transport headers found for the request " + correlationID);
            throw new AISecurityException(AISecurityException.CLIENT_REQUEST_ERROR,
                    AISecurityException.CLIENT_REQUEST_ERROR_MESSAGE);
        }
    }

    public static JSONObject addObj(String key, Object value) {
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
     *
     * @return CloseableHttpClient
     */
    public static CloseableHttpClient getHttpClient(String protocol,
            AISecurityHandlerConfig.DataPublisherConfig dataPublisherConfiguration) throws AISecurityException {

        PoolingHttpClientConnectionManager pool;
        try {
            pool = SecurityUtils.getPoolingHttpClientConnectionManager(protocol);
        } catch (Exception e) {
            throw new AISecurityException(e);
        }

        pool.setMaxTotal(dataPublisherConfiguration.getMaxOpenConnections());
        pool.setDefaultMaxPerRoute(dataPublisherConfiguration.getMaxPerRoute());

        //Socket timeout is set to 10 seconds addition to connection timeout.
        RequestConfig params = RequestConfig.custom()
                .setConnectTimeout(dataPublisherConfiguration.getConnectionTimeout() * 1000)
                .setSocketTimeout((dataPublisherConfiguration.getConnectionTimeout() + 10) * 1000).build();

        return HttpClients.custom().setConnectionManager(pool).setDefaultRequestConfig(params).build();
    }

    /**
     * Return a PoolingHttpClientConnectionManager instance
     *
     * @param protocol- service endpoint protocol. It can be http/https
     * @return PoolManager
     */
    private static PoolingHttpClientConnectionManager getPoolingHttpClientConnectionManager(String protocol)
            throws KeyStoreException, NoSuchAlgorithmException, KeyManagementException, IOException,
            CertificateException {

        PoolingHttpClientConnectionManager poolManager;
        if (AISecurityHandlerConstants.HTTPS_PROTOCOL.equals(protocol)) {
            SSLConnectionSocketFactory sslsf = createSocketFactory();
            Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
                    .register(AISecurityHandlerConstants.HTTPS_PROTOCOL, sslsf).build();
            poolManager = new PoolingHttpClientConnectionManager(socketFactoryRegistry);
        } else {
            poolManager = new PoolingHttpClientConnectionManager();
        }
        return poolManager;
    }

    private static SSLConnectionSocketFactory createSocketFactory()
            throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException,
            KeyManagementException {
        SSLContext sslContext;
        if (ServiceReferenceHolder.getInstance().getSecurityHandlerConfig().isSkipCertValidation()) {
            //If skip validation is enabled, certificates will be trusted without a validation
            sslContext = SSLContexts.custom().loadTrustMaterial(null, new TrustStrategy() {
                @Override
                public boolean isTrusted(X509Certificate[] chain, String authType)
                        throws CertificateException {
                    return true;
                }
            }).build();
        } else {
            String keyStorePath = CarbonUtils.getServerConfiguration().getFirstProperty("Security.TrustStore.Location");
            String keyStorePassword = CarbonUtils.getServerConfiguration().getFirstProperty("Security.TrustStore.Password");
            KeyStore trustStore = KeyStore.getInstance("JKS");
            trustStore.load(new FileInputStream(keyStorePath), keyStorePassword.toCharArray());
            sslContext = SSLContexts.custom().loadTrustMaterial(trustStore).build();
        }

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
        return sslsf;
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
        if (remoteIP.indexOf(":") > 0) {
            remoteIP = remoteIP.substring(0, remoteIP.indexOf(":"));
        }
        return remoteIP;
    }

    /**
     * Extracts the cookie from Message Context.
     *
     * @param transportHeadersMap Transport headers map.
     * @return cookie as a String.
     */
    public static String getCookie(TreeMap<String, String> transportHeadersMap) {

        String cookie = null;
        //Check whether headers map is null and x forwarded for header is present
        if (transportHeadersMap != null) {
            cookie = transportHeadersMap.get("Cookie");
        }
        return cookie;
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
        } else {
            correlationID = UUID.randomUUID().toString();
            messageContext.setProperty("am.correlationID", correlationID);
        }
        return correlationID;
    }

    /**
     * Return the httpVersion of the request
     *
     * @param axis2MessageContext - synapse variables
     * @return payload - HTTP version of the request
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
        errorMessage.setText(e.getMessage());
        OMElement errorDetail = fac.createOMElement("description", ns);
        errorDetail.setText(AISecurityException.getAuthenticationFailureMessage(e.getErrorCode()));

        payload.addChild(errorCode);
        payload.addChild(errorMessage);
        payload.addChild(errorDetail);
        return payload;
    }

    public static void updateLatency(Long latency, MessageContext messageContext) {
        Object otherLatency = messageContext.getProperty("other_latency");
        if (otherLatency == null) {
            messageContext.setProperty("other_latency", TimeUnit.NANOSECONDS.toMillis(latency));
        } else {
            messageContext.setProperty("other_latency", TimeUnit.NANOSECONDS.toMillis((long) otherLatency + latency));
        }
    }

    /**
     * Verify whether token, cookie or IP has a cache entry
     *
     * @param requestMetaData - Request data
     * @param correlationID - Correlation ID of the request
     * @return true if token or ip or cookie has a cache entry
     * @return false if non of the properties has any cache entry
     * @throws AISecurityException if the cached response of any property is to block the request
     */
    public static boolean verifyPropertiesWithCache(JSONObject requestMetaData,
                                                    String correlationID) throws AISecurityException {

        boolean statusForToken = SecurityUtils.verifyPropertyWithCache(AISecurityHandlerConstants.TOKEN_CACHE_NAME,
                AISecurityHandlerConstants.TOKEN_KEY_NAME, requestMetaData, correlationID);
        boolean statusForIP = SecurityUtils.verifyPropertyWithCache(AISecurityHandlerConstants.IP_CACHE_NAME,
                AISecurityHandlerConstants.IP_KEY_NAME, requestMetaData, correlationID);
        boolean statusForCookie = SecurityUtils.verifyPropertyWithCache(AISecurityHandlerConstants.COOKIE_CACHE_NAME,
                AISecurityHandlerConstants.COOKIE_KEY_NAME, requestMetaData, correlationID);
        return statusForToken || statusForIP || statusForCookie;
    }

    public static boolean verifyPropertyWithCache(String cacheName, String propertyName, JSONObject requestMetaData,
                                                  String correlationID) throws AISecurityException {

        String property = (String) requestMetaData.get(propertyName);
        boolean status = true;
        int aseResponseForProperty = ASEResponseStore.getFromASEResponseCache(cacheName, property);
        if (aseResponseForProperty == 0) {
            status = false;
        } else {
            verifyASEResponse(aseResponseForProperty, correlationID, cacheName + " Cache");
        }
        if (log.isDebugEnabled()) {
            log.debug("Status of " + cacheName + " for request " + correlationID + " is " + status);
        }
        return status;
    }

    /**
     * Verify whether ASE response is to block the request of not
     *
     * @param aseResponseCode - ASE response for the request
     * @param correlationID - Correlation ID of the request
     * @throws AISecurityException if the ASE response is to block the request
     */
    public static void verifyASEResponse(int aseResponseCode, String correlationID, String instance)
            throws AISecurityException {
        //Handler will block the request only if ASE responds with forbidden code
        if (AISecurityHandlerConstants.ASE_RESPONSE_CODE_FORBIDDEN == aseResponseCode) {
            if (log.isDebugEnabled()) {
                log.debug("Access revoked by the Ping AI handler for the request id " + correlationID + " from " +
                        instance);
            }
            throw new AISecurityException(AISecurityException.ACCESS_REVOKED,
                    AISecurityException.ACCESS_REVOKED_MESSAGE);
        }
    }

    /**
     * This method will anonymize the cookie content by hashing with md5
     *
     * @param cookieString - Cookie header value
     */
    public static String anonymizeCookie(String cookieString) {

        String finalString = "";
        if (cookieString.isEmpty()) {
            return null;
        } else {
            String[] cookieVariables = cookieString.split(";");

            for (String cookieVariable : cookieVariables) {
                String[] keyValuePair = cookieVariable.split("=");
                if (keyValuePair.length > 1) {
                    finalString = finalString + keyValuePair[0] + "=" + DigestUtils.md5Hex(keyValuePair[1]) + ";";
                } else {
                    finalString = finalString + DigestUtils.md5Hex(cookieVariable) + ";";
                }
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("Cookie header values were anonymized");
        }
        
        if (finalString == null || finalString.length() == 0) {
            return finalString;
        }
        return finalString.substring(0, finalString.length() - 1);
    }

    /**
     * Return a http client instance
     *
     * @param port      - server port
     * @param protocol- service endpoint protocol http/https
     * @return
     */
    public static HttpClient getManagementHttpClient(int port, String protocol) {
        SchemeRegistry registry = new SchemeRegistry();
        SSLSocketFactory socketFactory = SSLSocketFactory.getSocketFactory();

        String hostnameVerifierOption = System.getProperty(HOST_NAME_VERIFIER);
        X509HostnameVerifier hostnameVerifier;
        if (ALLOW_ALL.equalsIgnoreCase(hostnameVerifierOption)) {
            hostnameVerifier = SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER;
        } else if (STRICT.equalsIgnoreCase(hostnameVerifierOption)) {
            hostnameVerifier = SSLSocketFactory.STRICT_HOSTNAME_VERIFIER;
        } else {
            hostnameVerifier = SSLSocketFactory.BROWSER_COMPATIBLE_HOSTNAME_VERIFIER;
        }
        socketFactory.setHostnameVerifier(hostnameVerifier);

        if (APIConstants.HTTPS_PROTOCOL.equals(protocol)) {
            try {
                socketFactory = createManagementSocketFactory();
                if (socketFactory == null) {
                    return null;
                }
                socketFactory.setHostnameVerifier(hostnameVerifier);
                if (port >= 0) {
                    registry.register(new Scheme(APIConstants.HTTPS_PROTOCOL, port, socketFactory));
                } else {
                    registry.register(new Scheme(APIConstants.HTTPS_PROTOCOL, 443, socketFactory));
                }
            } catch (APIManagementException e) {
                log.error(e);
            }
        } else if (APIConstants.HTTP_PROTOCOL.equals(protocol)) {
            if (port >= 0) {
                registry.register(new Scheme(APIConstants.HTTP_PROTOCOL, port, PlainSocketFactory.getSocketFactory()));
            } else {
                registry.register(new Scheme(APIConstants.HTTP_PROTOCOL, 80, PlainSocketFactory.getSocketFactory()));
            }
        }
        HttpParams params = new BasicHttpParams();
        ThreadSafeClientConnManager tcm = new ThreadSafeClientConnManager(registry);
        return new DefaultHttpClient(tcm, params);
    }

    private static SSLSocketFactory createManagementSocketFactory() throws APIManagementException {
        KeyStore keyStore;
        String keyStorePath = null;
        String keyStorePassword;
        try {
            SSLSocketFactory sslSocketFactory;
            if (ServiceReferenceHolder.getInstance().getSecurityHandlerConfig().isSkipCertValidation()) {
                //If skip validation is enabled, certificates will be trusted without a validation
                SSLContext sslContext = SSLContexts.custom().loadTrustMaterial(null, new TrustStrategy() {
                    @Override
                    public boolean isTrusted(X509Certificate[] chain, String authType)
                            throws CertificateException {
                        return true;
                    }
                }).build();
                sslSocketFactory = new SSLSocketFactory(sslContext);
                return sslSocketFactory;
            } else {
                keyStorePath = CarbonUtils.getServerConfiguration().getFirstProperty("Security.KeyStore.Location");
                keyStorePassword = CarbonUtils.getServerConfiguration().getFirstProperty("Security.KeyStore.Password");
                keyStore = KeyStore.getInstance("JKS");
                keyStore.load(new FileInputStream(keyStorePath), keyStorePassword.toCharArray());
                sslSocketFactory = new SSLSocketFactory(keyStore, keyStorePassword);
                return sslSocketFactory;
            }
        } catch (KeyStoreException e) {
            log.error("Failed to read from Key Store", e);
        } catch (CertificateException e) {
            log.error("Failed to read Certificate", e);
        } catch (NoSuchAlgorithmException e) {
            log.error("Failed to load Key Store from " + keyStorePath, e);
        } catch (IOException e) {
            log.error("Key Store not found in " + keyStorePath, e);
        } catch (UnrecoverableKeyException e) {
            log.error("Failed to load key from" + keyStorePath, e);
        } catch (KeyManagementException e) {
            log.error("Failed to load key from" + keyStorePath, e);
        }
        return null;
    }
}
