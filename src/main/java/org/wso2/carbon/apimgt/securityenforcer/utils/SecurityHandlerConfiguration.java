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

package org.wso2.carbon.apimgt.securityenforcer.utils;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.impl.builder.StAXOMBuilder;
import org.apache.axis2.util.JavaUtils;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.apimgt.securityenforcer.dto.AISecurityHandlerConfig;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.securevault.SecretResolver;
import org.wso2.securevault.SecretResolverFactory;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.Stack;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;

/**
 * Global API Manager configuration. This is generally populated from a special
 * XML descriptor file at system startup. Once successfully populated, this
 * class does not allow more parameters to be added to the configuration. The
 * design of this class has been greatly inspired by the ServerConfiguration
 * class in Carbon core. This class uses a similar '.' separated approach to
 * keep track of XML parameters.
 */
public class SecurityHandlerConfiguration {

    private static final String RECEIVER_URL_PORT = "receiver.url.port";
    private static final String AUTH_URL_PORT = "auth.url.port";
    private static final String JMS_PORT = "jms.port";
    private static final Log log = LogFactory.getLog(SecurityHandlerConfiguration.class);
    private SecretResolver secretResolver;

    private boolean initialized;
    private AISecurityHandlerConfig securityHandlerConfig = new AISecurityHandlerConfig();

    /**
     * Populate this configuration by reading an XML file at the given location.
     * This method can be executed only once on a given SecurityHandlerConfiguration
     * instance. Once invoked and successfully populated, it will ignore all
     * subsequent invocations.
     *
     * @param filePath Path of the XML descriptor file
     *
     */

    public void load(String filePath) throws AISecurityException {
        if (initialized) {
            return;
        }
        InputStream in = null;
        int offset = getPortOffset();
        int receiverPort = 9611 + offset;
        int authUrlPort = 9711 + offset;
        int jmsPort = 5672 + offset;
        System.setProperty(RECEIVER_URL_PORT, "" + receiverPort);
        System.setProperty(AUTH_URL_PORT, "" + authUrlPort);
        System.setProperty(JMS_PORT, "" + jmsPort);
        try {
            in = FileUtils.openInputStream(new File(filePath));
            StAXOMBuilder builder = new StAXOMBuilder(in);
            secretResolver = SecretResolverFactory.create(builder.getDocumentElement(), true);
            readChildElements(builder.getDocumentElement(), new Stack<String>());
            initialized = true;
        } catch (XMLStreamException | IOException e) {
            log.error("Error when reading the Ping AI config file ", e);
            throw new AISecurityException(AISecurityException.HANDLER_ERROR, AISecurityException.HANDLER_ERROR_MESSAGE,
                    e);
        } finally {
            if (in != null) {
                IOUtils.closeQuietly(in);
            }
        }
    }

    private void readChildElements(OMElement serverConfig, Stack<String> nameStack) throws AISecurityException {
        for (Iterator childElements = serverConfig.getChildElements(); childElements.hasNext();) {
            OMElement element = (OMElement) childElements.next();
            String localName = element.getLocalName();
            nameStack.push(localName);

            if (AISecurityHandlerConstants.PING_AI_SECURITY_HANDLER_CONFIGURATION.equals(localName)) {
                try {
                    setPingAISecurityHandlerProperties(serverConfig);
                } catch (Exception e) {
                    log.error("Ping AI config error", e);
                    throw new AISecurityException(AISecurityException.HANDLER_ERROR,
                            AISecurityException.HANDLER_ERROR_MESSAGE, e);
                }
            }
            nameStack.pop();
        }
    }

    public AISecurityHandlerConfig getPingAISecurityHandlerProperties() {
        return securityHandlerConfig;
    }

    /**
     * set the AI Security Enforcer Properties into Configuration
     *
     * @param element
     */
    private void setPingAISecurityHandlerProperties(OMElement element) throws AISecurityException {
        OMElement aiSecurityConfigurationElement = element
                .getFirstChildWithName(new QName(AISecurityHandlerConstants.PING_AI_SECURITY_HANDLER_CONFIGURATION));
        if (aiSecurityConfigurationElement != null) {

            // Get mode
            OMElement modeElement = aiSecurityConfigurationElement
                    .getFirstChildWithName(new QName(AISecurityHandlerConstants.OPERATION_MODE_CONFIGURATION));
            if (modeElement != null) {
                securityHandlerConfig.setMode(modeElement.getText());
            } else {
                log.info("Operation mode is not set. Set to default async mode");
            }

            // Get Cache expiry time
            OMElement cacheExpiryElement = aiSecurityConfigurationElement
                    .getFirstChildWithName(new QName(AISecurityHandlerConstants.CACHE_EXPIRY_TIME_CONFIG));
            if (cacheExpiryElement != null) {
                securityHandlerConfig.setCacheExpiryTime(Integer.parseInt(cacheExpiryElement.getText()));
            } else {
                log.debug("Cache expiry is not set. Set to default: " + securityHandlerConfig.getCacheExpiryTime());
            }

            // Get Apply for all APIs
            OMElement applyForAllAPIsElement = aiSecurityConfigurationElement
                    .getFirstChildWithName(new QName(AISecurityHandlerConstants.APPLY_FOR_ALL_APIS_CONFIG));
            if (applyForAllAPIsElement != null) {
                securityHandlerConfig.setApplyForAllAPIs(JavaUtils.isTrueExplicitly(applyForAllAPIsElement.getText()));
            } else {
                log.debug("Apply For All APIs Element is not set. Set to default: "
                        + securityHandlerConfig.isApplyForAllAPIs());
            }

            // Get ASE config data
            OMElement aseConfigElement = aiSecurityConfigurationElement
                    .getFirstChildWithName(new QName(AISecurityHandlerConstants.API_SECURITY_ENFORCER_CONFIGURATION));
            AISecurityHandlerConfig.AseConfig aseConfig = new AISecurityHandlerConfig.AseConfig();
            if (aseConfigElement != null) {
                OMElement aseEndPointElement = aseConfigElement
                        .getFirstChildWithName(new QName(AISecurityHandlerConstants.END_POINT_CONFIGURATION));
                if (aseEndPointElement != null) {
                    aseConfig.setEndPoint(aseEndPointElement.getText());
                } else {
                    log.error("Ping AI config error - ASE Endpoint not found");
                    throw new AISecurityException(AISecurityException.HANDLER_ERROR,
                            AISecurityException.HANDLER_ERROR_MESSAGE);
                }

                OMElement backupAseEndPointElement = aseConfigElement.getFirstChildWithName(
                        new QName(AISecurityHandlerConstants.BACKUP_ASE_END_POINT_CONFIGURATION));
                if (backupAseEndPointElement != null) {
                    aseConfig.setBackupAseEndPoint(backupAseEndPointElement.getText());
                } else {
                    log.debug("Ping AI config error - Backup ASE Endpoint not found. Set to primary ASE: "
                            + aseEndPointElement.getText());
                    aseConfig.setBackupAseEndPoint(aseEndPointElement.getText());
                }

                OMElement aseTokenElement = aseConfigElement
                        .getFirstChildWithName(new QName(AISecurityHandlerConstants.ASE_TOKEN_CONFIGURATION));
                if (aseTokenElement != null) {
                    if (secretResolver.isInitialized()
                            && secretResolver.isTokenProtected("APIManager.PingAISecurityHandler.ASE.ASEToken")) {
                        aseConfig.setAseToken(secretResolver.resolve("APIManager.PingAISecurityHandler.ASE.ASEToken"));
                    } else {
                        aseConfig.setAseToken(aseTokenElement.getText());
                    }
                } else {
                    log.error("Ping AI config error - ASE access token not found");
                    throw new AISecurityException(AISecurityException.HANDLER_ERROR,
                            AISecurityException.HANDLER_ERROR_MESSAGE);
                }

                OMElement modelCreationEndpointElement = aseConfigElement.getFirstChildWithName(
                        new QName(AISecurityHandlerConstants.MODEL_CREATION_ENDPOINT_CONFIGURATION));
                AISecurityHandlerConfig.ModelCreationEndpoint modelCreationEndpointConfig = new AISecurityHandlerConfig.ModelCreationEndpoint();
                if (modelCreationEndpointElement != null) {
                    boolean configMissing = false;
                    OMElement managementEndpointElement = modelCreationEndpointElement
                            .getFirstChildWithName(new QName(AISecurityHandlerConstants.END_POINT_CONFIGURATION));
                    if (managementEndpointElement != null) {
                        modelCreationEndpointConfig.setManagementAPIEndpoint(managementEndpointElement.getText());
                    } else
                        configMissing = true;

                    OMElement accessKeyElement = modelCreationEndpointElement
                            .getFirstChildWithName(new QName(AISecurityHandlerConstants.ACCESS_KEY_CONFIGURATION));
                    if (accessKeyElement != null) {
                        if (secretResolver.isInitialized()
                                && secretResolver.isTokenProtected("APIManager.PingAISecurityHandler.ASE.AccessKey")) {
                            modelCreationEndpointConfig.setAccessKey(
                                    secretResolver.resolve("APIManager.PingAISecurityHandler.ASE.AccessKey"));
                        } else {
                            modelCreationEndpointConfig.setAccessKey(accessKeyElement.getText());
                        }
                    } else
                        configMissing = true;

                    OMElement secretKeyElement = modelCreationEndpointElement
                            .getFirstChildWithName(new QName(AISecurityHandlerConstants.SECRET_KEY_CONFIGURATION));
                    if (secretKeyElement != null) {
                        if (secretResolver.isInitialized()
                                && secretResolver.isTokenProtected("APIManager.PingAISecurityHandler.ASE.SecretKey")) {
                            modelCreationEndpointConfig.setSecretKey(
                                    secretResolver.resolve("APIManager.PingAISecurityHandler.ASE.SecretKey"));
                        } else {
                            modelCreationEndpointConfig.setSecretKey(secretKeyElement.getText());
                        }
                    } else
                        configMissing = true;

                    if (!configMissing) {
                        modelCreationEndpointConfig.setEnable(true);
                    }
                } else {
                    log.debug("Model creation endpoint not set. Models will not be created automatically.");
                }
                securityHandlerConfig.setAseConfig(aseConfig);
                securityHandlerConfig.setModelCreationEndpointConfig(modelCreationEndpointConfig);
            } else {
                log.error("Ping AI config error - ASE config not found");
                throw new AISecurityException(AISecurityException.HANDLER_ERROR,
                        AISecurityException.HANDLER_ERROR_MESSAGE);
            }

            // Get data publisher config data
            OMElement dataPublisherConfigElement = aiSecurityConfigurationElement
                    .getFirstChildWithName(new QName(AISecurityHandlerConstants.DATA_PUBLISHER_CONFIGURATION));
            AISecurityHandlerConfig.DataPublisherConfig dataPublisherConfig = new AISecurityHandlerConfig.DataPublisherConfig();
            if (dataPublisherConfigElement != null) {
                OMElement maxPerRouteElement = dataPublisherConfigElement
                        .getFirstChildWithName(new QName(AISecurityHandlerConstants.MAX_PER_ROUTE_CONFIGURATION));
                if (maxPerRouteElement != null) {
                    dataPublisherConfig.setMaxPerRoute(Integer.parseInt(maxPerRouteElement.getText()));
                }

                OMElement maxOpenConnectionsElement = dataPublisherConfigElement.getFirstChildWithName(
                        new QName(AISecurityHandlerConstants.MAX_OPEN_CONNECTIONS_CONFIGURATION));
                if (maxOpenConnectionsElement != null) {
                    dataPublisherConfig.setMaxOpenConnections(Integer.parseInt(maxOpenConnectionsElement.getText()));
                }

                OMElement connectionTimeoutElement = dataPublisherConfigElement
                        .getFirstChildWithName(new QName(AISecurityHandlerConstants.CONNECTIONS_TIMEOUT_CONFIGURATION));
                if (connectionTimeoutElement != null) {
                    dataPublisherConfig.setConnectionTimeout(Integer.parseInt(connectionTimeoutElement.getText()));
                }
            } else {
                log.debug("Data publisher config is not set. Set to default.");
            }
            securityHandlerConfig.setDataPublisherConfig(dataPublisherConfig);

            // Get thread pool executor config data
            OMElement threadPoolExecutorConfigElement = aiSecurityConfigurationElement
                    .getFirstChildWithName(new QName(AISecurityHandlerConstants.THREAD_POOL_EXECUTOR_CONFIGURATION));
            AISecurityHandlerConfig.ThreadPoolExecutorConfig threadPoolExecutorConfig = new AISecurityHandlerConfig.ThreadPoolExecutorConfig();
            if (threadPoolExecutorConfigElement != null) {
                OMElement corePoolSizeElement = threadPoolExecutorConfigElement
                        .getFirstChildWithName(new QName(AISecurityHandlerConstants.CORE_POOL_SIZE_CONFIGURATION));
                if (corePoolSizeElement != null) {
                    threadPoolExecutorConfig.setCorePoolSize(Integer.parseInt(corePoolSizeElement.getText()));
                }

                OMElement maximumPoolSizeElement = threadPoolExecutorConfigElement
                        .getFirstChildWithName(new QName(AISecurityHandlerConstants.MAX_POOL_SIZE_CONFIGURATION));
                if (maximumPoolSizeElement != null) {
                    threadPoolExecutorConfig.setMaximumPoolSize(Integer.parseInt(maximumPoolSizeElement.getText()));
                }

                OMElement keepAliveTimeElement = threadPoolExecutorConfigElement
                        .getFirstChildWithName(new QName(AISecurityHandlerConstants.KEEP_ALIVE_TIME_CONFIGURATION));
                if (keepAliveTimeElement != null) {
                    threadPoolExecutorConfig.setKeepAliveTime(Long.parseLong(keepAliveTimeElement.getText()));
                }
            } else {
                log.debug("Thread pool config is not set. Set to default.");
            }
            securityHandlerConfig.setThreadPoolExecutorConfig(threadPoolExecutorConfig);

            // Get stack object pool config data
            OMElement stackObjectPoolConfigElement = aiSecurityConfigurationElement
                    .getFirstChildWithName(new QName(AISecurityHandlerConstants.STACK_OBJECT_POOL_CONFIGURATION));
            AISecurityHandlerConfig.StackObjectPoolConfig stackObjectPoolConfig = new AISecurityHandlerConfig.StackObjectPoolConfig();
            if (stackObjectPoolConfigElement != null) {
                OMElement maxIdleElement = stackObjectPoolConfigElement
                        .getFirstChildWithName(new QName(AISecurityHandlerConstants.MAX_IDLE_CONFIGURATION));
                if (maxIdleElement != null) {
                    stackObjectPoolConfig.setMaxIdle(Integer.parseInt(maxIdleElement.getText()));
                }

                OMElement initIdleCapacityElement = stackObjectPoolConfigElement
                        .getFirstChildWithName(new QName(AISecurityHandlerConstants.INIT_IDLE_CAPACITY_CONFIGURATION));
                if (initIdleCapacityElement != null) {
                    stackObjectPoolConfig.setInitIdleCapacity(Integer.parseInt(initIdleCapacityElement.getText()));
                }
            } else {
                log.debug("Stack object pool config is not set. Set to default.");
            }
            securityHandlerConfig.setStackObjectPoolConfig(stackObjectPoolConfig);

            // Get limit transport headers config data
            OMElement limitTransportHeadersElement = aiSecurityConfigurationElement
                    .getFirstChildWithName(new QName(AISecurityHandlerConstants.LIMIT_TRANSPORT_HEADERS_CONFIGURATION));

            AISecurityHandlerConfig.LimitTransportHeaders limitTransportHeadersConfig = new AISecurityHandlerConfig.LimitTransportHeaders();
            if (limitTransportHeadersElement != null) {
                limitTransportHeadersConfig.setEnable(true);

                Iterator headersIterator = limitTransportHeadersElement
                        .getChildrenWithLocalName(AISecurityHandlerConstants.HEADER_CONFIGURATION);
                Set<String> headerSet = new HashSet<>();
                while (headersIterator.hasNext()) {
                    OMElement headerElement = (OMElement) headersIterator.next();
                    if (headerElement != null) {
                        headerSet.add(headerElement.getText().toLowerCase());
                    }
                }
                limitTransportHeadersConfig.setHeaderSet(headerSet);
            } else {
                log.debug("Limit transport headers config is not set. Set to default.");
            }
            securityHandlerConfig.setLimitTransportHeaders(limitTransportHeadersConfig);
        }
    }

    private int getPortOffset() {
        ServerConfiguration carbonConfig = ServerConfiguration.getInstance();
        String portOffset = System.getProperty("portOffset", carbonConfig.getFirstProperty("Ports.Offset"));
        try {
            if ((portOffset != null)) {
                return Integer.parseInt(portOffset.trim());
            } else {
                return 0;
            }
        } catch (NumberFormatException e) {
            log.error("Invalid Port Offset: " + portOffset + ". Default value 0 will be used.", e);
            return 0;
        }
    }

}
