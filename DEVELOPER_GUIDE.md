# WSO2 API Manager extension with PingIntelligence

## What is PingIntelligence for APIs?
PingIntelligence for APIs uses artificial intelligence (AI) to expose active APIs, identify and automatically block cyber attacks on APIs and provide detailed reporting on all API activity. You can deploy the PingIntelligence solution on premises, in public clouds, or in hybrid clouds to monitor API traffic across the environment. PingIntelligence uses AI and machine learning models to detect anomalous API behavior, without relying on specifically defined policies or prior knowledge of attack patterns, in order to stop new and constantly changing attacks. In addition, PingIntelligence uses its continuous learning capabilities to become more accurate at identifying and blocking attacks over time.


#### Types of attacks PingIntelligence protects against
The following are the types of attacks that PingIntelligence can detect.

##### Authentication system attacks
 - **Login system attacks**: Bad actors use credential stuffing and other brute force attacks to test valid credentials from the dark web to determine the validity of these credentials. They then utilize the compromised credentials to access API services. Bots may execute aggressive attacks or run slower attacks designed to blend in with normal login failures.

 - **Account takeover with stolen credential attacks**: Stolen credentials acquired via man-in-the-middle and other attacks are used to penetrate and take over accounts. These credentials include stolen tokens, cookies or API keys that may be used by the hacker to access data authorized to the compromised client.

##### Data and application attacks
 - **API takeover attacks**: Hackers use a valid account to reverse engineer the API and access other accounts using the vulnerabilities they find. Theft of data and private info follows, as well as the takeover of other accounts. Meanwhile, the hacker looks like a normal user at all times since they are using a valid account.

 - **Data extraction or theft**: Hackers use APIs to steal files, photos, credit card information and personal data from accounts available through an API. Since normal outbound activity on one API may be an attack on a different API, PingIntelligence uses its deep understanding of each API to block both normal and extended duration data exfiltration attacks.

 - **Data scraping**: APIs are commonly abused by bots that extract (scrape) data for subsequent use (e.g., competitive pricing), which can negatively impact your business. Data scraping attacks can be executed on the API service directly and can run over extended time frames to avoid detection.

 - **Data deletion or manipulation**: A disgruntled employee or hacker could delete information to sabotage systems or change data to compromise information.

 - **Data injected into an application service**: A hacker can load large data files to overrun system memory or inject excessive data to overload an API service.

 - **Malicious code injection**: A hacker may inject malicious code, such as key loggers, which could compromise other users accessing the service.

 - **Extreme application activity**: A hacker can generate calls that require unusually high system resources that can overwhelm a backend and cause an application-level denial of service.

 - **Probing and fuzzing attacks**: A hacker may look for coding flaws that can be exploited to expose unintended content. The hacker may also try to mask the activity by probing the API over long time periods. These attacks can be used to force API errors to uncover IP and system addresses that can then be used to access resources.

##### API DoS/DDoS attacks
 - **Targeted API DDoS attacks**: Hackers tune attacks to stay below rate limits and exploit API vulnerability with finely crafted API DDoS attacks to disable services provided by the API or damage the user experience. Existing anti-DoS/DDoS security solutions can’t stop these attacks, but PingIntelligence for APIs uses AI to identify and block them.

 - **Extreme client activity**: A bot or hacker may generate extreme levels of inbound activity on an API service.


By analyzing client behavior on the API services, PingIntelligence can detect attacks where hackers have discovered vulnerabilities that circumvent the intended authorization systems or deviate from normal usage of the API service.


## How does integration happen?
The WSO2 API Manager extension for PingIntelligence uses a new custom handler (Ping AI Security Handler) when working with the WSO2 API Gateway data flow. After this handler receives a request from a client, a sideband call is sent to PingIdentity’s API Security Enforcer (ASE) with the client request metadata. The ASE responds after analyzing the metadata with an Artificial Intelligence Engine.

If the response of ASE is 200 OK, the Ping AI Security Handler forwards the request and if the response is 403, it blocks the request.

![alt text](https://raw.githubusercontent.com/wso2-extensions/apim-handler-pingai/1.0.x/images/architecture.png)

#### Data flow
1. The client request is sent to API Gateway.
2. API Gateway makes a **ASE/REQUEST** API call to Ping ASE with request metadata.
3. ASE logs metadata and checks the following.
    - Checks if it is an unregistered API, format error, or bad Auth token.
        - If yes, return specified code.
    - Checks if the origin IP/Cookie/API Key/OAuth Token is on the blacklist.
        - If on the blacklist, returns **403**.
    - Otherwise, returns **200-OK**.
4. WSO2 API Gateway receives the ASE response:
    - If the response is **200-OK**, it sends the API request to the App server.
    - If the response is **403**, it blocks the client.
5. WSO2 API Gateway receives API response from the app server.
6. WSO2 API Gateway makes a **ASE/RESPONSE** API call to pass the response metadata.
7. ASE logs the metadata and sends a **200-OK** response.
8. API Gateway sends an API response to the client.

![alt text](https://raw.githubusercontent.com/wso2-extensions/apim-handler-pingai/1.0.x/images/requestFlow.png)

#### Prerequisites

- **Install Java 7 or 8.**
(http://www.oracle.com/technetwork/java/javase/downloads/)

- **Install Apache Maven 3.x.x**
 (https://maven.apache.org/download.cgi#)

- **This branch is for API manager versions of 2.x. Download the relevant API manager**
(https://wso2.com/api-management/)

    Installing WSO2 is very fast and easy. Before you begin, be sure you have met the installation prerequisites, and then follow the [installation instructions for your platform](https://docs.wso2.com/display/AM260/Installing+the+Product).

- **PingIntelligence software installation.**

    PingIntelligence v4 software is installed and configured. For installation of PingIntelligence software,
    see the
    * [Automated Deployment guide](https://support.pingidentity.com/s/document-item?bundleId=pingintelligence-40&topicId=qyk1564008978881.html)
    * [Manual Deployment guide](https://support.pingidentity.com/s/document-item?bundleId=pingintelligence-40&topicId=zmn1564008976506.html)
    * [Product Downloads Site](https://www.pingidentity.com/en/resources/downloads/pingintelligence.html)

- **Verify that ASE is in sideband mode.**

  Make sure that the ASE is in sideband mode by running the following command in the ASE command line:
    ```
   /opt/pingidentity/ase/bin/cli.sh status
   API Security Enforcer
   status                  : started
   mode                    : sideband
   http/ws                 : port 80
   https/wss               : port 443
   firewall                : enabled
   abs                     : enabled, ssl: enabled
   abs attack              : disabled
   audit                   : enabled
   sideband authentication : disabled
   ase detected attack     : disabled
   attack list memory      : configured 128.00 MB, used 25.60 MB, free 102.40 MB
    ```

    If the ASE is not in sideband mode, stop the ASE, set mode as **sideband** in the
    */opt/pingidentity/ase/config/ase.conf* file, and start ASE.

- **Enable sideband authentication.**

  For a secure communication between WSO2 Gateway and the ASE, enable sideband authentication by entering the following
  command in the ASE command line:
   ```
    # ./bin/cli.sh -u admin -p admin enable_sideband_authentication
   ```

- **Generate a sideband authentication token.**

   A token is required for WSO2 Gateway to authenticate with the ASE. To generate the token in the ASE, enter the following
   command in the ASE command line:
   ```
   # ./bin/cli.sh -u admin -p admin create_sideband_token
   ```
   Save the generated authentication token for further use.

- **Add the certificate of the ASE to the WSO2 client keystore.**

    Use *wso2carbon* as the default keystore password.
   ```
    keytool -importcert -file <ase_request_endpoint_cert_name>.cer -keystore <APIM_HOME>/repository/resources/security/client-truststore.jks -alias "ASE request endpoint"

    keytool -importcert -file <ase_management_endpoint_cert_name>.cer -keystore <APIM_HOME>/repository/resources/security/client-truststore.jks -alias "ASE management endpoint"
   ```
    [Obtaining ASE request endpoint and management endpoint public key certificates](https://github.com/wso2-extensions/apim-handler-pingai/blob/1.0.x/README.md#obtaining-ase-certificates)

## Deploy WSO2 Extension with PingIntelligence

### For System Admin

1. Download the extension and navigate to the **apim-handler-pingai** directory and run the following Maven command to build the distribution.
   ```
    mvn clean install
     ```
     Use the following table to update pom.xml with the corresponding dependency versions for API manager.

     | Dependency                |   APIM 3.0.0   |  APIM 2.6.0   |  APIM 2.5.0   |  APIM 2.2.0   |  APIM 2.1.0   |
     | ------------------------- | :------------: | :-----------: | :-----------: | :-----------: | :-----------: |
     | carbon.apimgt.version     |    6.5.349     |    6.4.50     |    6.3.95     |    6.2.201    |    6.1.66     |
     | carbon.kernel.version     |     4.5.1      |    4.4.35     |    4.4.32     |    4.4.26     |    4.4.11     |
     | carbon.governance.version |     4.8.10     |    4.7.29     |    4.7.27     |    4.7.23     |     4.7.0     |
     | synapse.version           | 2.1.7-wso2v131 | 2.1.7-wso2v80 | 2.1.7-wso2v65 | 2.1.7-wso2v48 | 2.1.7-wso2v10 |

2. Add the JAR file of the extension to the **<APIM_HOME>/repository/components/dropins** directory.
   You can find the org.wso2.carbon.apimgt.securityenforcer-\<version>.jar file in the **apim-handler-pingai/target** directory.

3. Add the bare minimum configurations to the **<APIM_HOME>/repository/conf/api-manager.xml** file within the \<APIManager> tag.

    ```
    <PingAISecurityHandler>
        <OperationMode>sync</OperationMode>
        <APISecurityEnforcer>
            <EndPoint>ASE_ENDPOINT</EndPoint>
            <BackupEndPoint>BACKUP_ASE_END_POINT</BackupEndPoint>
            <ASEToken>SIDEBAND_AUTHENTICATION_TOKEN</ASEToken>
            <ModelCreationEndpoint>
                <EndPoint>ASE_REST_API_ENDPOINT</EndPoint>
                <AccessKey>ASE_REST_API_ACCESS_KEY</AccessKey>
                <SecretKey>ASE_REST_API_SECRET_KEY</SecretKey>
            </ModelCreationEndpoint>
       </APISecurityEnforcer>
    </PingAISecurityHandler>
   ```
     **Note:**

    - Select the Operation mode from **[sync](https://github.com/wso2-extensions/apim-handler-pingai/blob/1.0.x/DEVELOPER_GUIDE.md#sync-mode)**,
        **[async](https://github.com/wso2-extensions/apim-handler-pingai/blob/1.0.x/DEVELOPER_GUIDE.md#async-mode)** and
        **[hybrid](https://github.com/wso2-extensions/apim-handler-pingai/blob/1.0.x/DEVELOPER_GUIDE.md#hybrid-mode)**.
        If the mode is not set, the default mode is set as **sync**.
   - ASE_ENDPOINT : https://\<ase-host-machine-ip>:\<data-port>
   - BACKUP_ASE_SIDEBAND_REQUEST_ENDPOINT : https://\<backup-ase-host-machine-ip>:\<data-port>
   - ASE_REST_API_ENDPOINT: https://\<ase-host-machine-ip>:\<management-port>/\<REST-API-version>/ase/api.
   - If ModelCreationEndpoint configurations are not set, you need to manually create ASE models.
   - Include the [sideband authentication token](https://github.com/wso2-extensions/apim-handler-pingai/blob/1.0.x/DEVELOPER_GUIDE.md#prerequisites)
         obtained from the ASE as the ASEToken.
   - For additional security you can [encrypt](https://github.com/wso2-extensions/apim-handler-pingai/blob/1.0.x/DEVELOPER_GUIDE.md#encrypting-passwords-with-cipher-tool) the SIDEBAND_AUTHENTICATION_TOKEN, ASE_REST_API_ACCESS_KEY, and the ASE_REST_API_SECRET_KEY.

4. To engage the handler to APIs, you need to update the **<APIM_HOME>/repository/resources/api_templates/velocity_template.xml** file.
   Add the handler class as follows inside the *\<handlers xmlns="http://ws.apache.org/ns/synapse">* just after the foreach loop.
   ```
   <handler class="org.wso2.carbon.apimgt.securityenforcer.PingAISecurityHandler"/>
   ```
   In the default velocity_template.xml file, it should be as follows.
     ```
   <handlers xmlns="http://ws.apache.org/ns/synapse">
   #foreach($handler in $handlers)
   <handler xmlns="http://ws.apache.org/ns/synapse" class="$handler.className">
       #if($handler.hasProperties())
       #set ($map = $handler.getProperties() )
       #foreach($property in $map.entrySet())
       <property name="$!property.key" value="$!property.value"/>
       #end
       #end
   </handler>
   #end
   <handler class="org.wso2.carbon.apimgt.securityenforcer.PingAISecurityHandler"/>
   </handlers>
     ```

5. Deploy WSO2 API Manager and open the management console: https://localhost:9443/carbon.
Navigate to Extensions > Configure > Lifecycles and click the View/Edit link that corresponds to the default API LifeCycle.
Update the **APILifeCycle.xml** with a new execution for the **Publish** event under **Created** and **Prototyped** states.
Do not update the already existing execution for the publish event. Add a new execution.
    ```
    <execution forEvent="Publish"
        class="org.wso2.carbon.apimgt.securityenforcer.executors.PingAIExecutor">
    </execution>
    ```

6. Add another execution for the **Retire** event under the **Deprecated** state.
   This deletes the model associated with the API in the ASE when the API is retired.
    ```
    <execution forEvent="Retire"
        class="org.wso2.carbon.apimgt.securityenforcer.executors.PingAIExecutor">
    </execution>
    ```

### For the API Publisher

**For new APIs**

- When the API is successfully [created](https://docs.wso2.com/display/AM260/Quick+Start+Guide#QuickStartGuide-CreatinganAPIfromscratch) and the life cycle state changes to **PUBLISHED**,
 a new model is created in the ASE for the API and the handler is added to the data flow.
 When the API state changes to **RETIRED**, the model is deleted.

**For existing APIs**

- The recommended method is to create a [new version](https://docs.wso2.com/display/AM260/Quick+Start+Guide#QuickStartGuide-VersioningtheAPI) for the API with PingIntelligence enabled.

    *Although changing the status of a live API is not recommended, republishing the API will update the Synapse config
    with the handler and by demoting to the CREATED or PROTOTYPED state and thereafter changing the life cycle back to the PUBLISHED state
    it will create a new model for the API in the ASE.*


![alt text](https://raw.githubusercontent.com/wso2-extensions/apim-handler-pingai/1.0.x/images/publishedState.png)


**Note:**
By default, PingIntelligence is enabled in all APIs that are published with an individual AI model.
However, if needed you can configure PingIntelligence to be [applied only for selected APIs.](https://github.com/wso2-extensions/apim-handler-pingai/blob/1.0.x/DEVELOPER_GUIDE.md#add-the-policy-only-for-selected-apis)


#### Verify api creation on ASE:

1. Open the Synapse configuration of the published API, located in in the <APIM_HOME>/repository/deployment/server/synapse-configs/default/api directory.
Check whether the \<handler class="org.wso2.carbon.apimgt.securityenforcer.PingAISecurityHandler"/>  handler is added under \<handlers>.
2. Open ASE command line. Use the CLI tool to list the published APIs in ASE.
Check whether the API is listed as <API_NAME>_\<VERSION>.
    Eg: HelloWorld_1.0.0
3. Run a curl command to check if the API is published to ASE. Check whether the API is listed as <API_NAME>_\<VERSION>.
    ```
    curl -k -X GET \
        https://<ase-host-machine-ip>:<management-port>/v4/ase/api \
        -H 'x-ase-access-key: <ase_access_key>' \
        -H 'x-ase-secret-key: <ase_secret_key>'
    ```


## Configurations
#### Bare minimum configurations
Add the following configurations to the  <APIM_HOME>/repository/conf/api-manager.xml file under the \<APIManager> tag. If the mode is not set, the default mode is set as async. If the ModelCreationEndpoint configurations are not set, you need to manually create the ASE models.

```
    <PingAISecurityHandler>
        <OperationMode>sync</OperationMode>
        <APISecurityEnforcer>
            <EndPoint>ASE_ENDPOINT</EndPoint>
            <BackupEndPoint>BACKUP_ASE_END_POINT</BackupEndPoint>
            <ASEToken>SIDEBAND_AUTHENTICATION_TOKEN</ASEToken>
            <ModelCreationEndpoint>
                <EndPoint>ASE_REST_API_ENDPOINT</EndPoint>
                <AccessKey>ASE_REST_API_ACCESS_KEY</AccessKey>
                <SecretKey>ASE_REST_API_SECRET_KEY</SecretKey>
            </ModelCreationEndpointiscovery>
       </APISecurityEnforcer>
    </PingAISecurityHandler>
   ```

## Modes of operation
WSO2 has implemented a custom handler with the handleRequest and handleResponse methods in iorder to integrate this feature with WSO2 API Manager. For every request, WSO2 Gateway sends two sideband calls to the API Security Enforcer (ASE). The first one is to analyze the metadata (Endpoint: ASE/request). The second one is to pass the status of the overall request after connecting to the backend (EndPoint: ASE/response). The second sideband call is mainly for the learning mode of the AI Engine.


There are three modes of operation when implementing the extension.
* Sync Mode
* Async Mode
* Hybrid Mode

The difference with all these modes is only with the first sideband request. The second sideband request will be asynchronous in all three modes.

### Sync mode
In the sync mode, the first sideband call is sent synchronously to the request data flow. Depending on the ASE response, the handler will allow each request to connect to the backend.

As this is a thread blocking call, every request will wait until the ASE responds.

   **Total time  =~0.2ms + ASE Sideband call time**


![alt text](https://raw.githubusercontent.com/wso2-extensions/apim-handler-pingai/1.0.x/images/syncFlow.png)

### Async mode
In this mode, both the sideband calls are sent asynchronously. There is a cache which records the response of each request sent to ASE.

As the metadata set of each client request is unique to the client (with the authorization header), the cache records the ASE response with the metadata. The metadata is hashed with MD5 and the hash code is used as the key.

**Total time = < 0.2ms**

![alt text](https://raw.githubusercontent.com/wso2-extensions/apim-handler-pingai/1.0.x/images/asyncFlow.png)

**Important:**
*There is a slip rate because the requests received until the first cache update is forwarded to the backend without monitoring.*


### Hybrid mode

In this mode, if there is no ASE response for the metadata in the cache, the thread is blocked and the sideband call to the ASE is sent synchronously. The cache is updated with the response and the request will be processed depending on the reponse.

The next request of the same client will be handled according to the cached response. However, later on the cache will be updated asynchronously.

Requests until the first cache update is handled in sync mode and after that it will be handled in async mode.

Each record in the cache has an expiry time, which is 15min from the last cache update.

![alt text](https://raw.githubusercontent.com/wso2-extensions/apim-handler-pingai/1.0.x/images/hybridFlow.png)

### Response

The second sideband request of each request is sent to ASE asynchronously with the status of the backend server.

![alt text](https://raw.githubusercontent.com/wso2-extensions/apim-handler-pingai/1.0.x/images/responseFlow.png)

## ASE Model creation
There is a new model created in the security engine for every API deployed with this feature. Security decisions are taken according to this model. A template of the ASE configuration file is used with default values and the API context is used as the URL. When OAuth protection is enabled, the authentication token is sent as the API key with the default header name “APIKey”. If you need to change any of the default values with regard to an API, you can do this by adding additional properties. If you need to change any of the default values with regard to all the APIs, you can do this by updating the default JSON (apim-handler-pingai-<version>/src/main/resources/org/wso2/carbon/apimgt/securityenforcer/internal/samplePingAIManagementPayload.json) file. However, note that after you change the default JSON, you can not change it back, because it is inside the bundle. Therefore, if you need to change it back, you have to build the apim-handler-pingai distribution again.
 The model creation request is sent to the ASE REST API when the API’s state changes from the CREATED state or PROTOTYPED state to the PUBLISHED state. When the API state changes to RETIRED, this model will be deleted.

#### ASE configurations - API JSON configuration file

    {
        "api_metadata": {
            "protocol": "http",
            "url": "/will_be_updated_with_API",
            "hostname": "*",
            "cookie": "",
            "cookie_idle_timeout": "200m",
            "logout_api_enabled": false,
            "cookie_persistence_enabled": false,
            "oauth2_access_token": false,
            "apikey_qs": "",
            "apikey_header": "APIKey",
            "login_url": "",
            "enable_blocking": true,
            "api_memory_size": "128mb",
            "server_ssl": false,
            "decoy_config": {
                "decoy_enabled": false,
                "response_code": 200,
                "response_def": "",
                "response_message": "",
                "decoy_subpaths": []
            }
        }
    }


 **Note:** After the Authentication handler (APIAuthenticationHandler) gets executed, by default the Authorization header is removed from the transport headers. However, the **auth token** will be sent as the API Key and will be added to the request metadata payload as a new transport header **APIKey**. If you want the Authorization header to be present in the transport headers, you can either add the PingAISecurityHandler before the Authentication handler or you can change the default configuration of the Authentication handler so that it does not remove the Authorization header after the handler processes the request.

#### Changing the ASE model parameters
The API JSON file parameters define the behavior and properties of the API and the learning model. If there are more configurations for the AI model, add those configurations as additional properties before publishing the API. If you do not add any additional parameters, the default values are used.

**Supported configurations :**
- protocol: API request type with supported values of http - HTTP.
    - Default -"http".
- cookie: Name of cookie used by the backend servers.
    - Default -"".
- hostname: Hostname for the API.
    - Default - "*" : matches any host.
- login_url: Public URL used by a client to connect to the application.
    - Default - "".
- oauth2_access_token:  When true, ASE captures OAuth2 Access Tokens. When false, ASE does not look for OAuth2 Tokens.
    - Default - false.
- apikey_header:When API key is part of the header field, ASE uses the specified parameter name to capture the API key value.
    - Default - "".
- apikey_qs: When API key is sent in the query string, ASE uses the specified parameter name to capture the API key value.
    - Default - "".
- enable_blocking: When true, ASE blocks all types of attack on this API. When false, no attacks are blocked.
    - Default - false.
- api_memory_size: Maximum ASE memory allocation for an API. The data unit can be MB or GB.
    - Default - "128mb".

![alt text](https://raw.githubusercontent.com/wso2-extensions/apim-handler-pingai/1.0.x/images/ASEConfigsAsAdditionalProperties.png)

## Adding additional configurations
Add the required configurations to the  <APIM_HOME>/repository/conf/api-manager.xml file under the \<PingAISecurityHandler> tag in order to add additional configurations with regard to the PingIntelligence extension.

    <PingAISecurityHandler>
        <ApplyForAllAPIs>false</ApplyForAllAPIs>
        <CacheExpiryTime>15</CacheExpiryTime>
        <DataPublisher>
           <MaxPerRoute>500</MaxPerRoute>
           <MaxOpenConnections>200</MaxOpenConnections>
           <ConnectionTimeout>30</ConnectionTimeout>
       </DataPublisher>
       <ThreadPoolExecutor>
           <CorePoolSize>200</CorePoolSize>
           <MaximumPoolSize>500</MaximumPoolSize>
           <KeepAliveTime>100</KeepAliveTime>
       </ThreadPoolExecutor>
       <StackObjectPool>
           <MaxIdle>100</MaxIdle>
           <InitIdleCapacity>50</InitIdleCapacity>
       </StackObjectPool>
       <LimitTransportHeaders>
            <Header>HEADER_1</Header>
            <Header>HEADER_2</Header>
            <Header>HEADER_3</Header>
            <Header>HEADER_4</Header>
       </LimitTransportHeaders>
    </PingAISecurityHandler>

### Add the policy only for selected APIs
By default, PingIntelligence is enabled in all APIs that are published with an individual AI model. Follow the instructions below to enable PingIntelligence only on selected APIs:
1. Add the additional configuration \<ApplyForAllAPIs>false\</ApplyForAllAPIs> with the configs in the api-manager.xml file.
2. Instead of updating the velocity-template with the handler, add the following code inside \<handlers xmlns="http://ws.apache.org/ns/synapse"> just after the foreach loop.
      ```
        #if($apiObj.additionalProperties.get('ai_security') == "enable")
            <handler class="org.wso2.carbon.apimgt.securityenforcer.PingAISecurityHandler"/>
        #end
     ```

    In the default velocity_template.xml file, it should be as follows:
    ```
     <handlers xmlns="http://ws.apache.org/ns/synapse">
    #foreach($handler in $handlers)
    <handler xmlns="http://ws.apache.org/ns/synapse" class="$handler.className">
        #if($handler.hasProperties())
        #set ($map = $handler.getProperties() )
        #foreach($property in $map.entrySet())
        <property name="$!property.key" value="$!property.value"/>
        #end
        #end
    </handler>
    #end
    #if($apiObj.additionalProperties.get('ai_security') == "enable")
        <handler class ="org.wso2.carbon.apimgt.securityenforcer.PingAISecurityHandler"/>
    #end
    </handlers>
   ```

3. Sign in to the API Publisher and create a new API. Before publishing the API, add a new additional property named **ai_security** with the value **enable**.

4. Change the life cycle state to **PUBLISHED**.

![alt text](https://raw.githubusercontent.com/wso2-extensions/apim-handler-pingai/1.0.x/images/enablePolicyWithAdditionalProperties.png)

### Limit transport headers
All transport headers found in the client request and backend response will be sent to ASE by default. To limit the headers, add the following code. For more information, see [Adding additional configurations](https://github.com/wso2-extensions/apim-handler-pingai/blob/1.0.x/DEVELOPER_GUIDE.md#adding-additional-configurations).
   ```
    <LimitTransportHeaders>
        <Header>HEADER_1</Header>
        <Header>HEADER_2</Header>
        <Header>HEADER_3</Header>
        <Header>HEADER_4</Header>
    </LimitTransportHeaders>
   ```

Only the intercept of headers mentioned and present in the transport headers are sent to ASE in both sideband calls.

*If there is a transport header which changes with each request, it is essential to use this feature and drop that header. Otherwise, this extension will not be useful when working with async and hybrid modes.*

### Other configurations
#### HTTP client configurations
Configurations with regard to the HTTP Client can be changed as follows.
  ```
    <DataPublisher>
        <MaxPerRoute>500</MaxPerRoute>
        <MaxOpenConnections>200</MaxOpenConnections>
        <ConnectionTimeout>30</ConnectionTimeout>
    </DataPublisher>
   ```

#### Thread pool and stack object pool configurations
Concurrent requests received for the handler are handled by a thread pool combined with a stack object pool.

   ```
    <ThreadPoolExecutor>
        <CorePoolSize>200</CorePoolSize>
        <MaximumPoolSize>500</MaximumPoolSize>
        <KeepAliveTime>100</KeepAliveTime>
    </ThreadPoolExecutor>
    <StackObjectPool>
        <MaxIdle>1000</MaxIdle>
        <InitIdleCapacity>200</InitIdleCapacity>
    </StackObjectPool>
```


## Encrypting passwords with Cipher Tool
The configuration file contains the ASE access token, Management API Access Key, and the Secret Key. If needed, you can use the Cipher Tool to encrypt sensitive data.

1. Add the following to the <APIM_HOME>/repository/conf/security/cipher-tool.properties file.
    - **APIManager.PingAISecurityHandler.ASE.ASEToken**=repository/conf/api-manager.xml//APIManager/PingAISecurityHandler/APISecurityEnforcer/ASEToken,false
    - **APIManager.PingAISecurityHandler.ASE.AccessKey**=repository/conf/api-manager.xml//APIManager/PingAISecurityHandler/APISecurityEnforcer/ModelCreationEndpoint/AccessKey,false
    - **APIManager.PingAISecurityHandler.ASE.SecretKey**=repository/conf/api-manager.xml//APIManager/PingAISecurityHandler/APISecurityEnforcer/ModelCreationEndpoint/SecretKey,false


2. Add the following to the <APIM_HOME>/repository/conf/security/cipher-text.properties file. Note that you should enclose the password within square brackets.
    - **APIManager.PingAISecurityHandler.ASE.ASEToken**=[ASE_TOKEN]
    - **APIManager.PingAISecurityHandler.ASE.AccessKey**=[ACCESS_KEY]
    - **APIManager.PingAISecurityHandler.ASE.SecretKey**=[SECRET_KEY]

    *If your password contains a backslash character (\) you need to use an alias with the escape characters. For example, if your password is admin\\} the value should be given as shown in the example below.*
    - **APIManager.PingAISecurityHandler.ASE.AccessKey**=[admin\\\\}]

3. Open a command prompt and go to the <APIM_HOME>/bin directory, where the Cipher Tool scripts (for Windows and Linux) are stored.
4. Execute the Cipher Tool script from the command prompt using the command relevant to your OS:
    - On Windows: ./ciphertool.bat -Dconfigure
    - On Linux: ./ciphertool.sh -Dconfigure
5. The following message will be prompted:

    "[Please Enter Primary KeyStore Password of Carbon Server :]"

6. Enter the keystore password (which is "wso2carbon" for the default keystore) and proceed. If the script execution is successful, you will see the following message:

    "[Secret Configurations are written to the property file successfully]"
7. Now, to verify the password encryption:

    Open the cipher-text.properties file and see that the plain text passwords are replaced by a Cipher value.

#### Changing encrypted passwords
Follow the instructions below to change a password that you had previously encrypted:

1. Shut down the server.
2. Open a command prompt and go to the <APIM_HOME>/bin directory, where the Cipher Tool scripts (for Windows and Linux) are stored.
3. Execute one of the following commands based on your OS:
    - On Linux: ./ciphertool.sh -Dchange
    - On Windows: ./ciphertool.bat -Dchange

    If you are using the Cipher Tool for the first time, this command will first initialize the tool for your product. The tool will then encrypt any plain text passwords that are specified in the cipher-text.properties file for automatic encryption.
5. It will prompt for the primary keystore password. Enter the keystore password, which is "wso2carbon" for the default keystore.
6. The alias values of all the passwords that you encrypted will now be shown in a numbered list.
7. When prompted select the alias of the password which you want to change. Enter the list number of the password alias.
8. When prompted, enter the new password (twice). Enter your new password.


## Configurations guide

| Field           | input                                                       | DefaultValue | Description                                                                                                                   |
| --------------- | ----------------------------------------------------------- | ------------ | ----------------------------------------------------------------------------------------------------------------------------- |
| OperationMode   | (String)<ul><li>async</li><li>sync</li><li>hybrid</li></ul> | sync         | The operation mode. <ul><li>Asynchronous mode -  async</li><li>Synchronous mode - sync</li><li>Hybrid mode - hybrid</li></ul> |
| ApplyForAllAPIs | (Boolean)                                                   | true         | Apply Ping Intelligence for all APIs published.                                                                               |
| CacheExpiryTime | (Integer)                                                   | 15           | Cache Expiry time in minutes.                                                                                                 |

#### APISecurityEnforcer - ASE configurations

| Field    | input    | DefaultValue | Description                                       |
| -------- | -------- | ------------ | ------------------------------------------------- |
| EndPoint | (String) | -            | The endpoint of ASE. Support both HTTP and HTTPS. |
| ASEToken | (String) | -            | If access token needed to communicate with ASE.   |

#### ModelCreationEndpoint - ASE Management REST API configurations

| Field     | input    | DefaultValue | Description                                                  |
| --------- | -------- | ------------ | ------------------------------------------------------------ |
| Endpoint  | (String) | -            | The management endpoint of ASE. Support both HTTP and HTTPS. |
| AccessKey | (String) | -            | AccessKey to the management endpoint.                        |
| SecretKey | (String) | -            | SecretKey to the management endpoint.                        |

#### DataPublisher - HTTP client configurations

| Field              | input     | DefaultValue | Description                                                                                                            |
| ------------------ | --------- | ------------ | ---------------------------------------------------------------------------------------------------------------------- |
| MaxPerRoute        | (Integer) | 500          | The maximum number of HTTP connections allowed across all routes.                                                      |
| MaxOpenConnections | (Integer) | 200          | The maximum number of HTTP connections allowed for a route.                                                            |
| ConnectionTimeout  | (Integer) | 30           | Connection timeout for the HTTP request in seconds. The socket timeout is set with the addition of another 10 seconds. |

#### ThreadPoolExecutor - ThreadPoolExecutor configurations

| Field           | input     | DefaultValue | Description                                                                                                                                                   |
| --------------- | --------- | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| CorePoolSize    | (Integer) | 200          | The number of threads to keep in the pool, even if they are idle.                                                                                             |
| MaximumPoolSize | (Integer) | 500          | The maximum number of threads to allow in the pool.                                                                                                           |
| KeepAliveTime   | (Long)    | 100          | When the number of threads is greater than the core, this is the maximum time in seconds that excess idle threads will wait for new tasks before terminating. |

#### StackObjectPool - StackObjectPool configurations

| Field            | input     | DefaultValue | Description                                                                                                          |
| ---------------- | --------- | ------------ | -------------------------------------------------------------------------------------------------------------------- |
| MaxIdle          | (Integer) | 100          | Cap on the number of "sleeping" instances in the pool.                                                               |
| InitIdleCapacity | (Integer) | 50           | Initial size of the pool (this specifies the size of the container, it does not cause the pool to be pre-populated.) |

#### LimitTransportHeaders

| Field  | input    | DefaultValue | Description                               |
| ------ | -------- | ------------ | ----------------------------------------- |
| Header | (String) | -            | Name of the header needed to sent to ASE. |
