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

package org.wso2.carbon.apimgt.securityenforcer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.apimgt.securityenforcer.dto.AseResponseDTO;
import org.wso2.carbon.apimgt.securityenforcer.internal.ServiceReferenceHolder;
import org.wso2.carbon.apimgt.securityenforcer.utils.AISecurityHandlerConstants;

import java.util.concurrent.TimeUnit;
import javax.cache.Cache;
import javax.cache.CacheConfiguration;
import javax.cache.Caching;

/**
 * ASEResponseStore class acts as the cache for the PingAIAuthenticator. It has two hash maps.
 * aseVerificationResponseStore records the ASE response for specific metadata Json.
 * aseResponseWithCorrelationIDStore records the response for ASE/request with the correlation ID. In the handle response
 * method, it will be read and if there is an entry for that correlation ID exists, it will be sent to ASE/Response and
 * clear that data from hash map.
 */

public class ASEResponseStore {

    private static final Log log = LogFactory.getLog(ASEResponseStore.class);
    private static boolean pingAICacheInitialized = false;

    public ASEResponseStore() {
    }

    private static Cache getASEResponseCache() {
        if (!pingAICacheInitialized) {
            pingAICacheInitialized = true;
            if (log.isDebugEnabled()) {
                log.debug("New Cache instance created for Ping AI security handler with the name of "
                        + AISecurityHandlerConstants.CACHE_NAME);
            }
            return Caching.getCacheManager(AISecurityHandlerConstants.CACHE_MANAGER_NAME)
                    .createCacheBuilder(AISecurityHandlerConstants.CACHE_NAME)
                    .setExpiry(CacheConfiguration.ExpiryType.ACCESSED, new CacheConfiguration.Duration(TimeUnit.MINUTES,
                            ServiceReferenceHolder.getInstance().getSecurityHandlerConfig().getCacheExpiryTime()))
                    .setExpiry(CacheConfiguration.ExpiryType.MODIFIED, new CacheConfiguration.Duration(TimeUnit.MINUTES,
                            ServiceReferenceHolder.getInstance().getSecurityHandlerConfig().getCacheExpiryTime()))
                    .setStoreByValue(false).build();
        } else {
            return Caching.getCacheManager(AISecurityHandlerConstants.CACHE_MANAGER_NAME).
                    getCache(AISecurityHandlerConstants.CACHE_NAME);
        }
    }

    public static void writeToASEResponseCache(String cacheKey, AseResponseDTO aseResponseDTO) {
        if (aseResponseDTO != null) {
            Cache cache = getASEResponseCache();
            cache.put(cacheKey, aseResponseDTO);
        }
    }

    public static AseResponseDTO getFromASEResponseCache(String cacheKey) {
        AseResponseDTO aseResponseDTO = null;
        if (cacheKey != null) {
            Cache cache = getASEResponseCache();
            aseResponseDTO = (AseResponseDTO) cache.get(cacheKey);
        }
        return aseResponseDTO;
    }
}
