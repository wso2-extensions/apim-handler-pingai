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

import org.json.simple.JSONObject;
import org.wso2.carbon.apimgt.securityenforcer.utils.AISecurityException;

/**
 * Interface through which data is published to API Security Enforcer. Three implementations of this interface provides
 * the three modes of operations (Async,Sync,Hybrid). Implementations of this
 * interface never returns false when a failure occurs. All errors
 * are signaled by throwing an AISecurityException.
 */
public interface Publisher {

    /**
     * Handler publish request meta data to the API Security Enforcer using this method. If the request is properly
     * sent to the ASE and the response code is the success code, this method should return true. This will never
     * return false. if the ASE response code is not the success code, method should throw an AISecurityException.
     * For all unexpected error conditions, this method must throw an AISecurityException.
     *
     * @param requestMetaData Meta data extracted from the client request in the format which ASE supports
     * @param correlationID The unique ID for the request.
     * @return true if the authentication is successful (In Async Implementation, if not available in cache,
     * this returns through without considering the ASE response)
     * @throws AISecurityException If an request failure or some other error occurs
     */
    boolean verifyRequest(JSONObject requestMetaData, String correlationID) throws AISecurityException;

    /**
     * Handler publish response meta data to the API Security Enforcer using this method. This will never return false.
     * For all unexpected error conditions, this method must throw an AISecurityException.
     *
     *
     * @param requestMetaData Meta data extracted from the client request in the format which ASE supports
     * @param correlationID The unique ID for the request.
     * @return true if the authentication is successful (In Async Implementation, if not available in cache,
     * this returns through without considering the ASE response)
     * @throws AISecurityException If an request failure or some other error occurs
     */
    boolean publishResponse(JSONObject requestMetaData, String correlationID) throws AISecurityException;

}
