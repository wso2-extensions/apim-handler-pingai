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

package org.wso2.carbon.apimgt.securityenforcer.pingai.dto;

import org.wso2.carbon.apimgt.securityenforcer.pingai.utils.AISecurityHandlerConstants;

import java.util.Set;

/**
 * This class contains the config data for AI Security Handler.
 *
 */

public class AISecurityHandlerConfig {

    private boolean policyEnforcementEnabled = false;
    private boolean applyForAllAPIs = true;
    private boolean skipCertValidation = false;
    private String mode = AISecurityHandlerConstants.SYNC_MODE_STRING;
    private AISecurityHandlerConfig.AseConfig aseConfig;
    private AISecurityHandlerConfig.DataPublisherConfig dataPublisherConfig;
    private AISecurityHandlerConfig.StackObjectPoolConfig stackObjectPoolConfig;
    private AISecurityHandlerConfig.ThreadPoolExecutorConfig threadPoolExecutorConfig;
    private AISecurityHandlerConfig.LimitTransportHeaders limitTransportHeaders;
    private AISecurityHandlerConfig.ModelCreationEndpoint modelCreationEndpointConfig;

    public boolean isPolicyEnforcementEnabled() {
        return policyEnforcementEnabled;
    }

    public void setPolicyEnforcementEnabled(boolean policyEnforcementEnabled) {
        this.policyEnforcementEnabled = policyEnforcementEnabled;
    }

    public boolean isApplyForAllAPIs() {
        return applyForAllAPIs;
    }

    public void setApplyForAllAPIs(boolean applyForAllAPIs) {
        this.applyForAllAPIs = applyForAllAPIs;
    }

    public String getMode() {
        return mode;
    }

    public void setMode(String mode) {
        this.mode = mode;
    }

    public boolean isSkipCertValidation() {

        return skipCertValidation;
    }

    public void setSkipCertValidation(boolean skipCertValidation) {

        this.skipCertValidation = skipCertValidation;
    }

    public AISecurityHandlerConfig.AseConfig getAseConfig() {
        return aseConfig;
    }

    public void setAseConfig(AISecurityHandlerConfig.AseConfig aseConfig) {
        this.aseConfig = aseConfig;
    }

    public DataPublisherConfig getDataPublisherConfig() {
        return dataPublisherConfig;
    }

    public void setDataPublisherConfig(DataPublisherConfig dataPublisherConfig) {
        this.dataPublisherConfig = dataPublisherConfig;
    }

    public ThreadPoolExecutorConfig getThreadPoolExecutorConfig() {
        return threadPoolExecutorConfig;
    }

    public void setThreadPoolExecutorConfig(ThreadPoolExecutorConfig threadPoolExecutorConfig) {
        this.threadPoolExecutorConfig = threadPoolExecutorConfig;
    }

    public StackObjectPoolConfig getStackObjectPoolConfig() {
        return stackObjectPoolConfig;
    }

    public void setStackObjectPoolConfig(StackObjectPoolConfig stackObjectPoolConfig) {
        this.stackObjectPoolConfig = stackObjectPoolConfig;
    }

    public LimitTransportHeaders getLimitTransportHeaders() {
        return limitTransportHeaders;
    }

    public void setLimitTransportHeaders(LimitTransportHeaders limitTransportHeaders) {
        this.limitTransportHeaders = limitTransportHeaders;
    }

    public ModelCreationEndpoint getModelCreationEndpointConfig() {
        return modelCreationEndpointConfig;
    }

    public void setModelCreationEndpointConfig(ModelCreationEndpoint modelCreationEndpointConfig) {
        this.modelCreationEndpointConfig = modelCreationEndpointConfig;
    }

    public static class AseConfig {

        private String primaryAseEndPoint;
        private String backupAseEndPoint;
        // currentEndpoint is the ASE endpoint to which AISecurityHandler will send the
        // requests to at any point of time.
        private String currentEndpoint;

        private String aseToken;

        public String getEndPoint() {
            return currentEndpoint;
        }

        /**
         * This method is called only once when the AISecurityHandler configuration is
         * loaded. It will set the primaryAseEndPoint and currentEndpoint.
         */
        public void setEndPoint(String endPoint) {
            this.primaryAseEndPoint = endPoint;
            this.currentEndpoint = endPoint;
        }

        /**
         * This method takes currEndpoint as an argument that has resulted in a
         * connection refused or connection timeout exception. If shiftEndpoint receives
         * primaryAseEndPoint as argument, currentEndpoint will be set to
         * backupAseEndPoint. If shiftEndpoint receives backupAseEndPoint as argument,
         * currentEndpoint will be set to primaryAseEndPoint. This method is thread safe
         * since it is synchronized.
         */
        public synchronized void shiftEndpoint(String currEndpoint) {
            if (currEndpoint.equalsIgnoreCase(primaryAseEndPoint)) {
                this.currentEndpoint = backupAseEndPoint;
            } else {
                this.currentEndpoint = primaryAseEndPoint;
            }
        }

        public String getBackupAseEndPoint() {
            return backupAseEndPoint;
        }

        public void setBackupAseEndPoint(String backupAseEndPoint) {
            this.backupAseEndPoint = backupAseEndPoint;
        }

        public String getAseToken() {
            return aseToken;
        }

        public void setAseToken(String aseToken) {
            this.aseToken = aseToken;
        }
    }

    public static class DataPublisherConfig {

        private Integer maxOpenConnections = 500;
        private Integer maxPerRoute = 200;
        private Integer connectionTimeout = 30;

        public Integer getMaxOpenConnections() {
            return maxOpenConnections;
        }

        public void setMaxOpenConnections(Integer maxOpenConnections) {
            this.maxOpenConnections = maxOpenConnections;
        }

        public Integer getMaxPerRoute() {
            return maxPerRoute;
        }

        public void setMaxPerRoute(Integer maxPerRoute) {
            this.maxPerRoute = maxPerRoute;
        }

        public Integer getConnectionTimeout() {
            return connectionTimeout;
        }

        public void setConnectionTimeout(Integer connectionTimeout) {
            this.connectionTimeout = connectionTimeout;
        }
    }

    public static class StackObjectPoolConfig {

        private Integer maxIdle = 100;
        private Integer initIdleCapacity = 50;

        public Integer getMaxIdle() {
            return maxIdle;
        }

        public void setMaxIdle(Integer maxIdle) {
            this.maxIdle = maxIdle;
        }

        public Integer getInitIdleCapacity() {
            return initIdleCapacity;
        }

        public void setInitIdleCapacity(Integer initIdleCapacity) {
            this.initIdleCapacity = initIdleCapacity;
        }
    }

    public static class ThreadPoolExecutorConfig {

        private Integer corePoolSize = 200;
        private Integer maximumPoolSize = 500;
        private Long keepAliveTime = 100L;

        public Integer getCorePoolSize() {
            return corePoolSize;
        }

        public void setCorePoolSize(Integer corePoolSize) {
            this.corePoolSize = corePoolSize;
        }

        public Integer getMaximumPoolSize() {
            return maximumPoolSize;
        }

        public void setMaximumPoolSize(Integer maximumPoolSize) {
            this.maximumPoolSize = maximumPoolSize;
        }

        public Long getKeepAliveTime() {
            return keepAliveTime;
        }

        public void setKeepAliveTime(Long keepAliveTime) {
            this.keepAliveTime = keepAliveTime;
        }
    }

    public static class LimitTransportHeaders {

        private boolean enable = false;
        private Set<String> headerSet;

        public boolean isEnable() {
            return enable;
        }

        public void setEnable(boolean enable) {
            this.enable = enable;
        }

        public Set<String> getHeaderSet() {
            return headerSet;
        }

        public void setHeaderSet(Set<String> headerSet) {
            this.headerSet = headerSet;
        }
    }

    public static class ModelCreationEndpoint {

        private boolean enable = false;
        private String managementAPIEndpoint;
        private String accessKey;
        private String secretKey;

        public boolean isEnable() {
            return enable;
        }

        public void setEnable(boolean enable) {
            this.enable = enable;
        }

        public String getManagementAPIEndpoint() {
            return managementAPIEndpoint;
        }

        public void setManagementAPIEndpoint(String managementAPIEndpoint) {
            this.managementAPIEndpoint = managementAPIEndpoint;
        }

        public String getAccessKey() {
            return accessKey;
        }

        public void setAccessKey(String accessKey) {
            this.accessKey = accessKey;
        }

        public String getSecretKey() {
            return secretKey;
        }

        public void setSecretKey(String secretKey) {
            this.secretKey = secretKey;
        }
    }

}
