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

package org.wso2.carbon.apimgt.securityenforcer.pingai.internal;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.annotations.Component;
import org.wso2.carbon.apimgt.securityenforcer.pingai.dto.AISecurityHandlerConfig;
import org.wso2.carbon.apimgt.securityenforcer.pingai.utils.AISecurityException;
import org.wso2.carbon.apimgt.securityenforcer.pingai.utils.AISecurityHandlerConstants;
import org.wso2.carbon.apimgt.securityenforcer.pingai.publisher.HttpDataPublisher;
import org.wso2.carbon.apimgt.securityenforcer.pingai.publisher.Publisher;
import org.wso2.carbon.apimgt.securityenforcer.pingai.publisher.async.AsyncPublisher;
import org.wso2.carbon.apimgt.securityenforcer.pingai.publisher.async.AsyncPublisherThreadPool;
import org.wso2.carbon.apimgt.securityenforcer.pingai.publisher.sync.SyncPublisher;
import org.wso2.carbon.apimgt.securityenforcer.pingai.publisher.sync.SyncPublisherThreadPool;
import org.wso2.carbon.apimgt.securityenforcer.pingai.utils.SecurityHandlerConfiguration;
import org.wso2.carbon.utils.CarbonUtils;

@Component(name = "org.wso2.carbon.apimgt.securityenforcer", immediate = true)
public class PingAIHandlerComponent implements BundleActivator {

    private static final Log log = LogFactory.getLog(PingAIHandlerComponent.class);

    private String operationMode;
    private HttpDataPublisher httpDataPublisher;
    private AISecurityHandlerConfig securityHandlerConfig;

    public void start(BundleContext bundleContext) throws Exception {
        log.debug("OSGi start method for Ping AI security handler");

        securityHandlerConfig = getConfigData();
        ServiceReferenceHolder.getInstance().setSecurityHandlerConfig(securityHandlerConfig);

        if (securityHandlerConfig.isPolicyEnforcementEnabled()) {
            JSONObject managementAPIPayload = getManagementAPIPayload();
            logConfigData(securityHandlerConfig);
            operationMode = securityHandlerConfig.getMode();

            ServiceReferenceHolder.getInstance().setManagementAPIPayload(managementAPIPayload);

            Publisher requestPublisher;
            Publisher responsePublisher;

            switch (operationMode) {
                case AISecurityHandlerConstants.SYNC_MODE_STRING:
                    requestPublisher = new SyncPublisher();
                    break;
                case AISecurityHandlerConstants.ASYNC_MODE_STRING:
                    requestPublisher = new AsyncPublisher();
                    break;
                default:
                    log.info(operationMode + " is not a supported mode. Setting Ping AI Security Handler mode to sync");
                    operationMode = AISecurityHandlerConstants.SYNC_MODE_STRING;
                    securityHandlerConfig.setMode(AISecurityHandlerConstants.SYNC_MODE_STRING);
                    requestPublisher = new SyncPublisher();
            }

            ServiceReferenceHolder.getInstance().setRequestPublisher(requestPublisher);

            // response publisher is for the second sideband request with the backend
            // response metadata. This is sent asynchronously in all three operation modes
            // and for that async publisher instance is needed. As async mode
            // contains async publisher instance, only for the sync mode, there
            // will be a new additional instance created.
            if (AISecurityHandlerConstants.SYNC_MODE_STRING.equals(operationMode)) {
                responsePublisher = new AsyncPublisher();
            } else {
                responsePublisher = requestPublisher;
            }

            ServiceReferenceHolder.getInstance().setResponsePublisher(responsePublisher);

            AISecurityHandlerConfig.AseConfig aseConfiguration = securityHandlerConfig.getAseConfig();
            AISecurityHandlerConfig.DataPublisherConfig dataPublisherConfiguration = securityHandlerConfig
                    .getDataPublisherConfig();

            try {
                httpDataPublisher = new HttpDataPublisher(aseConfiguration, dataPublisherConfiguration);
            } catch (AISecurityException e) {
                log.error("Error when creating a httpDataPublisher Instance " + e.getMessage());
                throw new Exception(e);
            }

            ServiceReferenceHolder.getInstance().setHttpDataPublisher(httpDataPublisher);
        } else {
            log.info("AI security handler policy enforcement disabled");
        }
    }

    public void stop(BundleContext bundleContext) {
        if (securityHandlerConfig.isPolicyEnforcementEnabled()) {
            log.info("OSGi stop method for Ping AI Security Handler");
            if (AISecurityHandlerConstants.ASYNC_MODE_STRING.equals(operationMode)) {
                log.info("Cleaning the Async thread pool");
                AsyncPublisherThreadPool.getInstance().cleanup();
            } else {
                log.info("Cleaning both Async and sync thread pools");
                AsyncPublisherThreadPool.getInstance().cleanup();
                SyncPublisherThreadPool.getInstance().cleanup();
            }

            try {
                log.info("Closing the Http Client");
                httpDataPublisher.getHttpClient().close();
            } catch (IOException e) {
                log.error("Error when closing the HttpClient");
            }
        }
    }

    /**
     * This method will read the config file.
     */
    private AISecurityHandlerConfig getConfigData() throws AISecurityException {
        SecurityHandlerConfiguration configuration = new SecurityHandlerConfiguration();
        configuration.load(
                CarbonUtils.getCarbonConfigDirPath() + File.separator + AISecurityHandlerConstants.CONFIG_FILE_NAME);
        return configuration.getPingAISecurityHandlerProperties();
    }

    private JSONObject getManagementAPIPayload() {
        InputStream inputStreamObject;
        JSONParser jsonParser = new JSONParser();
        JSONObject managementAPIPayloadJson = null;

        try {
            inputStreamObject = PingAIHandlerComponent.class
                    .getResourceAsStream(AISecurityHandlerConstants.ASE_MANAGEMENT_API_REQUEST_PAYLOAD_FILE_NAME);
            managementAPIPayloadJson = (JSONObject) jsonParser
                    .parse(new InputStreamReader(inputStreamObject, StandardCharsets.UTF_8));
        } catch (IOException | ParseException e) {
            log.error("Error when reading the payload", e);
        }
        return managementAPIPayloadJson;
    }

    private void logConfigData(AISecurityHandlerConfig securityHandlerConfig) {

        if (log.isDebugEnabled()) {
            if (securityHandlerConfig != null) {
                String logMessage = "Ping AI configurations- ";
                logMessage = logMessage + ", Operation Mode: " + securityHandlerConfig.getMode();
                logMessage = logMessage + ", ASE Endpoint: " + securityHandlerConfig.getAseConfig().getEndPoint();
                logMessage = logMessage + ", Management Endpoint: "
                        + securityHandlerConfig.getModelCreationEndpointConfig().getManagementAPIEndpoint();
                logMessage = logMessage + ", DataPublisher- MaxPerRoute: "
                        + securityHandlerConfig.getDataPublisherConfig().getMaxPerRoute();
                logMessage = logMessage + ", DataPublisher- MaxOpenConnections: "
                        + securityHandlerConfig.getDataPublisherConfig().getMaxOpenConnections();
                logMessage = logMessage + ", DataPublisher- ConnectionTimeout: "
                        + securityHandlerConfig.getDataPublisherConfig().getConnectionTimeout();
                logMessage = logMessage + ", ThreadPoolExecutor- CorePoolSize: "
                        + securityHandlerConfig.getThreadPoolExecutorConfig().getCorePoolSize();
                logMessage = logMessage + ", ThreadPoolExecutor- MaximumPoolSize: "
                        + securityHandlerConfig.getThreadPoolExecutorConfig().getMaximumPoolSize();
                logMessage = logMessage + ", ThreadPoolExecutor- KeepAliveTime: "
                        + securityHandlerConfig.getThreadPoolExecutorConfig().getKeepAliveTime();
                logMessage = logMessage + ", StackObjectPool- MaxIdle: "
                        + securityHandlerConfig.getStackObjectPoolConfig().getMaxIdle();
                logMessage = logMessage + ", StackObjectPool- InitIdleCapacity: "
                        + securityHandlerConfig.getStackObjectPoolConfig().getInitIdleCapacity();
                if (securityHandlerConfig.getLimitTransportHeaders().isEnable()) {
                    logMessage = logMessage + ", LimitTransportHeaders: "
                            + securityHandlerConfig.getLimitTransportHeaders().getHeaderSet().toString();
                } else {
                    logMessage = logMessage + ", Limit Transport headers Disabled";
                }
                log.debug(logMessage);
            }
        }
    }
}
