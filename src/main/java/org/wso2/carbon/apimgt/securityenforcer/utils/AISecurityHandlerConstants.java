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

public class AISecurityHandlerConstants {

    public static final String HTTP_METHOD_STRING = "HTTP_METHOD";
    public static final String BACKEND_RESPONSE_STATUS_CODE = "HTTP_SC";
    public static final String BACKEND_RESPONSE_STATUS_MESSAGE = "HTTP_SC_DESC";
    public static final String API_BASEPATH_STRING = "TransportInURL";
    public static final String JSON_KEY_SOURCE_IP = "source_ip";
    public static final String JSON_KEY_SOURCE_PORT = "source_port";
    public static final String JSON_KEY_METHOD = "method";
    public static final String JSON_KEY_API_BASEPATH = "url";
    public static final String JSON_KEY_HTTP_VERSION = "http_version";
    public static final String JSON_KEY_HEADERS = "headers";
    public static final String JSON_KEY_USER_INFO = "user_info";
    public static final String JSON_KEY_USER_NAME = "username";
    public static final String JSON_KEY_RESPONSE_CODE = "response_code";
    public static final String JSON_KEY_RESPONSE_STATUS = "response_status";
    public static final String ASE_RESOURCE_REQUEST = "request";
    public static final String ASE_RESOURCE_RESPONSE = "response";
    public static final String ASE_TOKEN_HEADER = "ASE-Token";
    public static final String X_CORRELATION_ID_HEADER = "X-CorrelationID";
    public static final String CACHE_MANAGER_NAME = "PING_AI_CACHE";
    public static final String CACHE_NAME = "PingAI";
    public static final String TRANSPORT_HEADER_HOST_NAME = "Host";
    public static final int DUMMY_REQUEST_PORT = 8080;
    public static final int ASE_RESPONSE_CODE_SUCCESS = 200;
    public static final String ASE_RESPONSE_CODE_SUCCESS_MESSAGE = "OK";
    public static final int ASE_RESPONSE_CODE_INCORRECT_JSON = 400;
    public static final int ASE_RESPONSE_CODE_UNKNOWN_API = 503;
    public static final int ASE_RESPONSE_CODE_UNAUTHORIZED = 401;
    public static final int ASE_RESPONSE_CODE_FORBIDDEN = 403;
    public static final String SYNC_MODE_STRING = "sync";
    public static final String ASYNC_MODE_STRING = "async";
    public static final String HYBRID_MODE_STRING = "hybrid";
    public static final String END_USER_NAME = "api.ut.userName";
    public static final String REQUEST_RECEIVED_TIME = "wso2statistics.request.received.time";
    public static final String AUTHORIZATION = "Authorization";
    public static final String APPLICATION_NAME = "api.ut.application.name";
    public static final String CONFIG_FILE_NAME = "api-manager.xml";
    public static final String PUBLISHED = "PUBLISHED";
    public static final String RETIRED = "RETIRED";
    public static final String UPDATE = "UPDATE";
    public static final String DELETE = "DELETE";
    public static final String CREATE = "CREATE";
    public static final String LIST = "LIST";
    public static final String ASE_MANAGEMENT_HEADER_ACCESS_KEY = "x-ase-access-key";
    public static final String ASE_MANAGEMENT_HEADER_SECRET_KEY = "x-ase-secret-key";
    public static final String ASE_MANAGEMENT_HEADER_ACCEPT = "Accept";
    public static final String ASE_MANAGEMENT_HEADER_CONTENT_TYPE = "Content-Type";
    public static final String ASE_MANAGEMENT_API_REQUEST_PAYLOAD_FILE_NAME = "samplePingAIManagementPayload.json";
    public static final String ARTIFACT_ATTRIBUTE_API_NAME = "overview_name";
    public static final String ARTIFACT_ATTRIBUTE_API_VERSION = "overview_version";
    public static final String ARTIFACT_ATTRIBUTE_API_CONTEXT = "overview_context";
    public static final String API_NAME_VERSION_CONNECTOR = "_";
    public static final String AUTHORIZATION_HEADER_NAME = "Authorization";
    public static final String UNAUTHENTICATED_TIER = "Unauthenticated";
    static final String HTTP_VERSION_CONNECTOR = ".";
    static final String API_SECURITY_NS = "http://wso2.org/apimanager/security";
    static final String API_SECURITY_NS_PREFIX = "ams";
    static final String PING_AI_SECURITY_HANDLER_CONFIGURATION = "PingAISecurityHandler";
    static final String OPERATION_MODE_CONFIGURATION = "OperationMode";
    static final String CACHE_EXPIRY_TIME_CONFIG = "CacheExpiryTime";
    static final String APPLY_FOR_ALL_APIS_CONFIG = "ApplyForAllAPIs";
    static final String API_SECURITY_ENFORCER_CONFIGURATION = "APISecurityEnforcer";
    static final String END_POINT_CONFIGURATION = "EndPoint";
    static final String BACKUP_ASE_END_POINT_CONFIGURATION = "BackupEndPoint";
    static final String ASE_TOKEN_CONFIGURATION = "ASEToken";
    static final String MODEL_CREATION_ENDPOINT_CONFIGURATION = "ModelCreationEndpoint";
    static final String ACCESS_KEY_CONFIGURATION = "AccessKey";
    static final String SECRET_KEY_CONFIGURATION = "SecretKey";
    static final String DATA_PUBLISHER_CONFIGURATION = "DataPublisher";
    static final String MAX_PER_ROUTE_CONFIGURATION = "MaxPerRoute";
    static final String MAX_OPEN_CONNECTIONS_CONFIGURATION = "MaxOpenConnections";
    static final String CONNECTIONS_TIMEOUT_CONFIGURATION = "ConnectionTimeout";
    static final String THREAD_POOL_EXECUTOR_CONFIGURATION = "ThreadPoolExecutor";
    static final String CORE_POOL_SIZE_CONFIGURATION = "CorePoolSize";
    static final String MAX_POOL_SIZE_CONFIGURATION = "MaximumPoolSize";
    static final String KEEP_ALIVE_TIME_CONFIGURATION = "KeepAliveTime";
    static final String STACK_OBJECT_POOL_CONFIGURATION = "StackObjectPool";
    static final String MAX_IDLE_CONFIGURATION = "MaxIdle";
    static final String INIT_IDLE_CAPACITY_CONFIGURATION = "InitIdleCapacity";
    static final String LIMIT_TRANSPORT_HEADERS_CONFIGURATION = "LimitTransportHeaders";
    static final String HEADER_CONFIGURATION = "Header";

    private AISecurityHandlerConstants() {
    }

}
