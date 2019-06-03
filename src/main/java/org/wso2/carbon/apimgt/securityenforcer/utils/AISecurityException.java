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

/**
 * Represents an API security violation or a system error that may have occurred
 * while validating security requirements.
 */
public class AISecurityException extends Exception {

    public static final int HANDLER_ERROR = 90100;
    public static final String HANDLER_ERROR_MESSAGE = "AI Security Handler: Unexpected Handler failure";
    public static final int CLIENT_REQUEST_ERROR = 90101;
    public static final String CLIENT_REQUEST_ERROR_MESSAGE = "AI Security Handler: Error with the client request";
    public static final int ACCESS_REVOKED = 901000;
    public static final String ACCESS_REVOKED_MESSAGE = "AI Security Handler: Access Revoked by ASE";

    private int errorCode;

    public AISecurityException(int errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public AISecurityException(int errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    public AISecurityException(Throwable cause) {
        super(cause.getMessage(), cause);
    }

    /**
     * returns an String that corresponds to errorCode passed in
     * @param errorCode - error code
     * @return String
     */
    public static String getAuthenticationFailureMessage(int errorCode) {
        String errorMessage;
        switch (errorCode) {
        case ACCESS_REVOKED:
            errorMessage = ACCESS_REVOKED_MESSAGE;
            break;
        case HANDLER_ERROR:
            errorMessage = HANDLER_ERROR_MESSAGE;
            break;
        case CLIENT_REQUEST_ERROR:
            errorMessage = CLIENT_REQUEST_ERROR_MESSAGE;
            break;
        default:
            errorMessage = HANDLER_ERROR_MESSAGE;
            break;
        }
        return errorMessage;
    }

    public int getErrorCode() {
        return errorCode;
    }
}

