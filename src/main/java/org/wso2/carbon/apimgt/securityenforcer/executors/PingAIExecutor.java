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

package org.wso2.carbon.apimgt.securityenforcer.executors;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.wso2.carbon.apimgt.securityenforcer.internal.ServiceReferenceHolder;
import org.wso2.carbon.apimgt.securityenforcer.publisher.HttpDataPublisher;
import org.wso2.carbon.apimgt.securityenforcer.utils.AISecurityException;
import org.wso2.carbon.apimgt.securityenforcer.utils.AISecurityHandlerConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.governance.api.generic.GenericArtifactManager;
import org.wso2.carbon.governance.api.generic.dataobjects.GenericArtifact;
import org.wso2.carbon.governance.api.util.GovernanceUtils;
import org.wso2.carbon.governance.registry.extensions.aspects.utils.LifecycleConstants;
import org.wso2.carbon.governance.registry.extensions.interfaces.Execution;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.registry.core.Resource;
import org.wso2.carbon.registry.core.exceptions.RegistryException;
import org.wso2.carbon.registry.core.jdbc.handlers.RequestContext;
import org.wso2.carbon.registry.core.session.UserRegistry;
import org.wso2.carbon.utils.CarbonUtils;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Map;

/**
 * This class is an implementation of the
 * interface {@link org.wso2.carbon.governance.registry.extensions.interfaces.Execution}
 * This class consists methods that will create, prototype, publish, block, deprecate and
 * retire  an API to API Manager.
 * <p/>
 * This executor used to publish a service to API store as a API.
 *
 * @see org.wso2.carbon.governance.registry.extensions.interfaces.Execution
 */

public class PingAIExecutor implements Execution {

    private Log log = LogFactory.getLog(PingAIExecutor.class);
    private String ADDITIONAL_PROPERTY_NAME = "security";
    private String ADDITIONAL_PROPERTY_VALUE = "ping_ai";
    private String API_CONTEXT_RESOURCE_PROPERTY = "api_meta";
    private String API_CONTEXT_RESOURCE_CONJUNCTION = ".";

    /**
     * This method is called when the execution class is initialized.
     * All the execution classes are initialized only once.
     *
     * @param parameterMap Static parameter map given by the user.
     *                     These are the parameters that have been given in the
     *                     lifecycle configuration as the parameters of the executor.
     */
    public void init(Map parameterMap) {
    }

    /**
     * @param context      The request context that was generated from the registry core.
     *                     The request context contains the resource, resource path and other
     *                     variables generated during the initial call.
     * @param currentState The current lifecycle state.
     * @param targetState  The target lifecycle state.
     * @return Returns whether the execution was successful or not.
     */
    public boolean execute(RequestContext context, String currentState, String targetState) {
        try {
            boolean pingAIEnabled = false;

            String property = context.getResource().getProperty(
                    API_CONTEXT_RESOURCE_PROPERTY + API_CONTEXT_RESOURCE_CONJUNCTION + ADDITIONAL_PROPERTY_NAME);

            if (ADDITIONAL_PROPERTY_VALUE.equals(property))
                pingAIEnabled = true;

            if (pingAIEnabled) {
                GenericArtifactManager artifactManager = getArtifactManager(context.getSystemRegistry(), "api");
                Resource apiResource = context.getResource();
                String artifactId = apiResource.getUUID();
                if (artifactId == null || !ServiceReferenceHolder.getInstance().getSecurityHandlerConfig()
                        .getApiDiscoveryConfig().isEnable() || targetState == null) {
                    return false;
                }
                GenericArtifact apiArtifact = artifactManager.getGenericArtifact(artifactId);
                String apiName = apiArtifact.getAttribute(AISecurityHandlerConstants.ARTIFACT_ATTRIBUTE_API_NAME)
                        + AISecurityHandlerConstants.API_NAME_VERSION_CONNECTOR + apiArtifact
                        .getAttribute(AISecurityHandlerConstants.ARTIFACT_ATTRIBUTE_API_VERSION);
                String apiContext = apiArtifact.getAttribute(AISecurityHandlerConstants.ARTIFACT_ATTRIBUTE_API_CONTEXT);

                HttpDataPublisher httpDataPublisher = ServiceReferenceHolder.getInstance().getHttpDataPublisher();

                String accessKey = ServiceReferenceHolder.getInstance().getSecurityHandlerConfig()
                        .getApiDiscoveryConfig().getAccessKey();
                String secretKey = ServiceReferenceHolder.getInstance().getSecurityHandlerConfig()
                        .getApiDiscoveryConfig().getSecretKey();
                String managementAPIEndpoint = ServiceReferenceHolder.getInstance().getSecurityHandlerConfig()
                        .getApiDiscoveryConfig().getManagementAPIEndpoint();

                StatusLine responseStatus = null;
                JSONObject requestBody;

                if (AISecurityHandlerConstants.PUBLISHED.equals(targetState.toUpperCase())) {
                    requestBody = createAPIJSON(apiContext);

                    HttpPost postRequest = new HttpPost(managementAPIEndpoint + "?api_id=" + apiName);
                    postRequest.addHeader(AISecurityHandlerConstants.ASE_MANAGEMENT_HEADER_ACCESS_KEY, accessKey);
                    postRequest.addHeader(AISecurityHandlerConstants.ASE_MANAGEMENT_HEADER_SECRET_KEY, secretKey);
                    postRequest.addHeader(AISecurityHandlerConstants.ASE_MANAGEMENT_HEADER_ACCEPT, "application/json");
                    postRequest.addHeader(AISecurityHandlerConstants.ASE_MANAGEMENT_HEADER_CONTENT_TYPE,
                            "application/json");
                    postRequest.setEntity(new StringEntity(requestBody.toString()));

                    responseStatus = httpDataPublisher
                            .publishToASEManagementAPI(AISecurityHandlerConstants.CREATE, postRequest);
                }
                if (AISecurityHandlerConstants.RETIRED.equals(targetState.toUpperCase())) {
                    HttpDelete deleteRequest = new HttpDelete(managementAPIEndpoint + "?api_id=" + apiName);
                    deleteRequest.addHeader(AISecurityHandlerConstants.ASE_MANAGEMENT_HEADER_ACCESS_KEY, accessKey);
                    deleteRequest.addHeader(AISecurityHandlerConstants.ASE_MANAGEMENT_HEADER_SECRET_KEY, secretKey);
                    deleteRequest
                            .addHeader(AISecurityHandlerConstants.ASE_MANAGEMENT_HEADER_ACCEPT, "application/json");
                    deleteRequest.addHeader(AISecurityHandlerConstants.ASE_MANAGEMENT_HEADER_CONTENT_TYPE,
                            "application/json");

                    responseStatus = httpDataPublisher
                            .publishToASEManagementAPI(AISecurityHandlerConstants.DELETE, deleteRequest);
                }

                if (responseStatus != null) {
                    if (responseStatus.getStatusCode() == AISecurityHandlerConstants.ASE_RESPONSE_CODE_SUCCESS) {
                        log.info(apiName + " is " + targetState + "in ASE");
                    } else {
                        log.info("ASE responded with " + responseStatus.getReasonPhrase() + " For the " + targetState
                                + " request for the " + apiName + " API");
                    }
                }
            }
        } catch (RegistryException e) {
            log.error("Failed to get the generic artifact while executing PingAIExecutor. ", e);
            context.setProperty(LifecycleConstants.EXECUTOR_MESSAGE_KEY, "APIManagementException:" + e.getMessage());
        } catch (AISecurityException | UnsupportedEncodingException e) {
            log.error("Failed to publish service to API store while executing PingAIExecutor. ", e);
            context.setProperty(LifecycleConstants.EXECUTOR_MESSAGE_KEY, "APIManagementException:" + e.getMessage());
        }
        return true;
    }

    /**
     * this method used to initialized the ArtifactManager
     *
     * @param registry Registry
     * @param key      , key name of the key
     * @return GenericArtifactManager
     * @throws AISecurityException if failed to initialized GenericArtifactManager
     */
    private GenericArtifactManager getArtifactManager(Registry registry, String key) throws AISecurityException {
        GenericArtifactManager artifactManager = null;

        try {
            GovernanceUtils.loadGovernanceArtifacts((UserRegistry) registry);
            if (GovernanceUtils.findGovernanceArtifactConfiguration(key, registry) != null) {
                artifactManager = new GenericArtifactManager(registry, key);
            } else {
                log.warn("Couldn't find GovernanceArtifactConfiguration of RXT: " + key
                        + ". Tenant id set in registry : " + ((UserRegistry) registry).getTenantId()
                        + ", Tenant domain set in PrivilegedCarbonContext: " + PrivilegedCarbonContext
                        .getThreadLocalCarbonContext().getTenantId());
            }
        } catch (RegistryException e) {
            String msg = "Failed to initialize GenericArtifactManager";
            log.error(msg, e);
            throw new AISecurityException(e);
        }
        return artifactManager;
    }

    private JSONObject createAPIJSON(String APIContext) {
        FileReader reader;
        JSONParser parser = new JSONParser();
        JSONObject json = null;

        try {
            reader = new FileReader(CarbonUtils.getCarbonConfigDirPath() + File.separator
                    + AISecurityHandlerConstants.ASE_MANAGEMENT_API_REQUEST_PAYLOAD_FILE_NAME);
            json = (JSONObject) parser.parse(reader);
            ((JSONObject) json.get("api_metadata")).remove("url");
            ((JSONObject) json.get("api_metadata")).put("url", APIContext);
        } catch (FileNotFoundException e) {
            log.error("samplePingAIManagementData.json file is not found.");
        } catch (ParseException | IOException e) {
            log.error("Error when parsing the API Create JSON");
        }
        return json;
    }
}

