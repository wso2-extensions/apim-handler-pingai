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
import org.json.simple.JSONObject;
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
    private static boolean cookieCacheInitialized = false;
    private static boolean tokenCacheInitialized = false;
    private static boolean IPCacheInitialized = false;

    public ASEResponseStore() {
    }

    public synchronized static void writeToASEResponseCache(String cacheName, String cacheKey,
                                                            int aseResponseCode) {
        if (cacheKey != null && aseResponseCode != 0) {
            Cache cache = getCache(cacheName);
            cache.put(cacheKey, aseResponseCode);
        }
    }

    public static int getFromASEResponseCache(String cacheName, String cacheKey) {

        int aseResponseCode = 0;
        if (cacheKey != null) {
            Cache cache = getCache(cacheName);
            Object cachedObject = cache.get(cacheKey);
            if (cachedObject != null) {
                aseResponseCode = (int) cachedObject;
            }
        }
        return aseResponseCode;
    }

    public static void updateCache(JSONObject requestBody, int aseResponseCode, String correlationID){
        String token = (String) requestBody.get(AISecurityHandlerConstants.TOKEN_KEY_NAME);
        String cookie = (String) requestBody.get(AISecurityHandlerConstants.COOKIE_KEY_NAME);
        String ip = (String) requestBody.get(AISecurityHandlerConstants.IP_KEY_NAME);

        writeToASEResponseCache(AISecurityHandlerConstants.TOKEN_CACHE_NAME, token, aseResponseCode);
        writeToASEResponseCache(AISecurityHandlerConstants.COOKIE_CACHE_NAME, cookie, aseResponseCode);
        writeToASEResponseCache(AISecurityHandlerConstants.IP_CACHE_NAME, ip, aseResponseCode);
        if (log.isDebugEnabled()) {
            log.debug("Cache updated for " + correlationID + " as  " + aseResponseCode);
        }
    }

    public synchronized static Cache getTokenCache() {

        if (!tokenCacheInitialized) {
            tokenCacheInitialized = true;
            if (log.isDebugEnabled()) {
                log.debug("New Cache instance created for Ping AI security handler with the name of" + AISecurityHandlerConstants.TOKEN_CACHE_NAME);
            }
            return Caching.getCacheManager(AISecurityHandlerConstants.CACHE_MANAGER_NAME)
                    .createCacheBuilder(AISecurityHandlerConstants.TOKEN_CACHE_NAME)
                    .setExpiry(CacheConfiguration.ExpiryType.ACCESSED, new CacheConfiguration.Duration(TimeUnit.MINUTES,
                            ServiceReferenceHolder.getInstance().getSecurityHandlerConfig().getCacheExpiryTime()))
                    .setExpiry(CacheConfiguration.ExpiryType.MODIFIED, new CacheConfiguration.Duration(TimeUnit.MINUTES,
                            ServiceReferenceHolder.getInstance().getSecurityHandlerConfig().getCacheExpiryTime()))
                    .setStoreByValue(false).build();
        } else {
            return Caching.getCacheManager(AISecurityHandlerConstants.CACHE_MANAGER_NAME).getCache(AISecurityHandlerConstants.TOKEN_CACHE_NAME);
        }
    }

    public synchronized static Cache getIPCache() {

        if (!IPCacheInitialized) {
            IPCacheInitialized = true;
            if (log.isDebugEnabled()) {
                log.debug("New Cache instance created for Ping AI security handler with the name of " + AISecurityHandlerConstants.IP_CACHE_NAME);
            }
            return Caching.getCacheManager(AISecurityHandlerConstants.CACHE_MANAGER_NAME)
                    .createCacheBuilder(AISecurityHandlerConstants.IP_CACHE_NAME)
                    .setExpiry(CacheConfiguration.ExpiryType.ACCESSED, new CacheConfiguration.Duration(TimeUnit.MINUTES,
                            ServiceReferenceHolder.getInstance().getSecurityHandlerConfig().getCacheExpiryTime()))
                    .setExpiry(CacheConfiguration.ExpiryType.MODIFIED, new CacheConfiguration.Duration(TimeUnit.MINUTES,
                            ServiceReferenceHolder.getInstance().getSecurityHandlerConfig().getCacheExpiryTime()))
                    .setStoreByValue(false).build();
        } else {
            return Caching.getCacheManager(AISecurityHandlerConstants.CACHE_MANAGER_NAME).getCache(AISecurityHandlerConstants.IP_CACHE_NAME);
        }
    }
    public synchronized static Cache getCookieCache() {

        if (!cookieCacheInitialized) {
            cookieCacheInitialized = true;
            if (log.isDebugEnabled()) {
                log.debug("New Cache instance created for Ping AI security handler with the name of " + AISecurityHandlerConstants.COOKIE_CACHE_NAME);
            }
            return Caching.getCacheManager(AISecurityHandlerConstants.CACHE_MANAGER_NAME)
                    .createCacheBuilder(AISecurityHandlerConstants.COOKIE_CACHE_NAME)
                    .setExpiry(CacheConfiguration.ExpiryType.ACCESSED, new CacheConfiguration.Duration(TimeUnit.MINUTES,
                            ServiceReferenceHolder.getInstance().getSecurityHandlerConfig().getCacheExpiryTime()))
                    .setExpiry(CacheConfiguration.ExpiryType.MODIFIED, new CacheConfiguration.Duration(TimeUnit.MINUTES,
                            ServiceReferenceHolder.getInstance().getSecurityHandlerConfig().getCacheExpiryTime()))
                    .setStoreByValue(false).build();
        } else {
            return Caching.getCacheManager(AISecurityHandlerConstants.CACHE_MANAGER_NAME).getCache(AISecurityHandlerConstants.COOKIE_CACHE_NAME);
        }
    }

    public static Cache getCache (String cacheName){
        switch (cacheName){
            case (AISecurityHandlerConstants.TOKEN_CACHE_NAME):
                return getTokenCache();
            case (AISecurityHandlerConstants.IP_CACHE_NAME):
                return getIPCache();
            case (AISecurityHandlerConstants.COOKIE_CACHE_NAME):
                return getCookieCache();
            default:
                return null;
        }
    }
}
