# WSO2 API Manager extension with Ping Intelligence

## What is PingIntelligence for APIs?
PingIntelligence for APIs uses artificial intelligence (AI) to expose active APIs, identify and automatically block cyber attacks on APIs and provide detailed reporting on all API activity. Deployed on premises, in public clouds or in hybrid clouds, the solution monitors API traffic across the environment. It uses AI and machine learning models to detect anomalous API behavior without relying on specifically defined policies or prior knowledge of attack patterns in which, can stop new and constantly changing attacks. Using continuous learning capabilities, it becomes more accurate at identifying and blocking attacks over time. 


#### PingIntelligence protects against three main types of attacks, specifically:

##### Authentication System Attacks
 - **Login system attacks**: Bad actors use credential stuffing and other brute force attacks to test valid credentials from the dark web to determine the validity of these credentials. They then utilize the compromised credentials to access API services. Bots may execute aggressive attacks or run slower attacks designed to blend in with normal login failures.

 - **Account takeover with stolen credential attacks**: Stolen credentials acquired via man-in-the-middle and other attacks are used to penetrate and take over accounts. These credentials include stolen tokens, cookies or API keys which may be used by the hacker to access data authorized to the compromised client.

##### Data and Application Attacks
 - **API takeover attacks**: Hackers use a valid account to reverse engineer the API and access other accounts using the vulnerabilities they found. Theft of data and private info follows, as well as the takeover of other accounts. Meanwhile, the hacker looks like a normal user at all times since they are using a valid account.

 - **Data extraction or theft**: Hackers use APIs to steal files, photos, credit card information and personal data from accounts available through an API. Since normal outbound activity on one API may be an attack on a different API, PingIntelligence uses its deep understanding of each API to block both normal and extended duration data exfiltration attacks.

 - **Data scraping**: APIs are commonly abused by bots which extract (scrape) data for subsequent use (e.g., competitive pricing) which can negatively impact your business. Data scraping attacks can be executed on the API service directly and can run over extended time frames to avoid detection.

 - **Data deletion or manipulation**: A disgruntled employee or hacker could delete information to sabotage systems or change data to compromise information.

 - **Data injected into an application service**: A hacker can load large data files to overrun system memory or inject excessive data to overload an API service.

 - **Malicious code injection**: A hacker may inject malicious code, such as key loggers, which could compromise other users accessing the service.

 - **Extreme application activity**: A hacker can generate calls that require unusually high system resources which can overwhelm a backend and cause an application-level denial of service.

 - **Probing and fuzzing attacks**: A hacker may look for coding flaws which can be exploited to expose unintended content. The hacker may also try to mask the activity by probing the API over long time periods. These attacks can be used to force API errors to uncover IP and system addresses that can then be used to access resources.

##### API DoS/DDoS Attacks
 - **Targeted API DDoS attacks**: Hackers tune attacks to stay below rate limits and exploit API vulnerability with finely crafted API DDoS attacks to disable services provided by the API or damage the user experience. Existing anti-DoS/DDoS security solutions can’t stop these attacks, but PingIntelligence for APIs uses AI to identify and block them.

 - **Extreme client activity**: A bot or hacker may generate extreme levels of inbound activity on an API service.

 
By analyzing client behavior on the API services, PingIntelligence can detect attacks where hackers have discovered vulnerabilities that circumvent the intended authorization systems or deviate from normal usage of the API service.


## How does integration happen?
There is a handler for the WSO2 API Gateway and once it receives a request from a client, a sideband call will be sent to PingIdentitys’ API Security Enforcer (ASE) with the client requests’ metadata. ASE will analyze the metadata with an Artificial Intelligence Engine and respond. 

If the response of ASE is 200 OK, the handler will forward the request and if the response is 403, it will block the request.

![alt text](https://raw.githubusercontent.com/wso2-extensions/apim-handler-pingai/master/images/architecture.png)

#### Data flow
1. Client request to API Gateway.
2. API Gateway makes **ASE/REQUEST** API call to Ping ASE with request metadata.
3. ASE logs metadata and checks:
    - Unregistered API, format error, bad auth token? 
        - If yes, return specified code.
    - Origin IP/Cookie/API Key/OAuth Token on the blacklist?
        - If on the blacklist, return **403**.
    - Otherwise, return **200-OK**.
4. API Gateway receives ASE response:
    - If **200-OK**, send the API request to the App server.
    - If **403**, block client.
5. API Gateway receives API response from the app server.
6. API Gateway makes **ASE/RESPONSE** API call to pass response metadata.
7. ASE logs metadata and sends a **200-OK** response.
8. API Gateway sends an API response to the client.

![alt text](https://raw.githubusercontent.com/wso2-extensions/apim-handler-pingai/master/images/requestFlow.png)

#### Prerequisites

- **Install Java 7 or 8.** 
(http://www.oracle.com/technetwork/java/javase/downloads/)
    
- **Install Apache Maven 3.x.x**
 (https://maven.apache.org/download.cgi#)

- **Install the latest WSO2 API Manager**
(https://wso2.com/api-management/)

    Installing WSO2 is very fast and easy. Before you begin, be sure you have met the installation prerequisites, and then follow the [installation instructions for your platform](https://docs.wso2.com/display/AM260/Installing+the+Product).

- **PingIntelligence software installation.**

    PingIntelligence software is installed and configured. For installation of PingIntelligence software, 
    see the [manual or platform specific automated deployment guides](https://docs.pingidentity.com/bundle/PingIntelligence_For_APIs_Deployment_Guide_pingintel_32/page/pingintelligence_product_deployment.html).
- **Verify that ASE is in sideband mode.**
  
  Make sure that in ASE is in sideband mode by running the following command in the ASE command line:
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
    
    If ASE is not in sideband mode, then stop ASE and change the mode by editing the 
    */opt/pingidentity/ase/config/ase.conf* file. Set mode as **sideband** and start ASE.

- **Enable sideband authentication.**
  
  For a secure communication between WSO2 gateway and ASE, enable sideband authentication by entering the following 
  command in the ASE command line:
   ```
    # ./bin/cli.sh -u admin -p admin enable_sideband_authentication
   ```
   
- **Generate sideband authentication token.**

   A token is required for WSO2 gateway to authenticate with ASE. To generate the token in ASE, enter the following 
   command in the ASE command line:
   ```
   # ./bin/cli.sh -u admin -p admin create_sideband_token
   ```
   Save the generated authentication token for further use.
   
- **Add the certificate of ASE to WSO2 client keystore.**
 
    User *wso2carbon* as the default keystore password.
   ```
    keytool -importcert -file <certificate_name>.cer -keystore <APIM_HOME>/repository/resources/security/client-truststore.jks -alias "Alias"
   ```

## Deploy WSO2 Extension with Ping Intelligence

### For System admin

1. Download the extension and navigate to the **apim-handler-pingai** directory and run the following Maven command.
   ```
    mvn clean install
     ```
    org.wso2.carbon.apimgt.securityenforcer-\<version>.jar file can be found in **apim-handler-pingai/target** directory. 

2. Add the JAR file of the extension to the directory **<APIM_HOME>/repository/components/dropins**. 

3. Add the bare minimum configurations to the *api-manager.xml* within the tag \<APIManager>, which can be found in 
**<APIM_HOME>/repository/conf** folder.

    ```
    <PingAISecurityHandler>
        <OperationMode>async</OperationMode>
        <APISecurityEnforcer>
            <EndPoint>ASE_ENDPOINT</EndPoint>
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
        
    - Select the Operation mode from **[sync](https://github.com/wso2-extensions/apim-handler-pingai/blob/master/DEVELOPER_GUIDE.md#sync-mode)**,
        **[async](https://github.com/wso2-extensions/apim-handler-pingai/blob/master/DEVELOPER_GUIDE.md#async-mode)** and 
        **[hybrid](https://github.com/wso2-extensions/apim-handler-pingai/blob/master/DEVELOPER_GUIDE.md#hybrid-mode)**.
        If mode is not set, the default mode is set as **async**. 
   - If ModelCreationEndpoint configurations are not set,manual creation of ASE models will be needed.
   - Include the [sideband authentication token](https://github.com/wso2-extensions/apim-handler-pingai/blob/master/DEVELOPER_GUIDE.md#prerequisites)
         obtained from ASE as the ASEToken.
   - For additional security SIDEBAND_AUTHENTICATION_TOKEN, ASE_REST_API_ACCESS_KEY, ASE_REST_API_SECRET_KEY can be 
   [encrypted](https://github.com/wso2-extensions/apim-handler-pingai/blob/master/DEVELOPER_GUIDE.md#encrypting-passwords-with-cipher-tool).   

4. To engage the handler to APIs, you need to update the *velocity_template.xml* file. 
It can be found in **<APIM_HOME>/repository/resources/api_templates** directory.
   Add the handler class as follows inside the *\<handlers xmlns="http://ws.apache.org/ns/synapse">* just after the foreach loop.
   ```
   <handler class="org.wso2.carbon.apimgt.securityenforcer.PingAISecurityHandler"/> 
   ```
   In default velocity_template.xml file, it should be as follows.
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
  
5. Deploy the WSO2 API Manager and open the management console: https://localhost:9443/carbon.
    
    Start the API Manager by going to <APIM_HOME>/bin using the command-line and executing wso2server.bat (for Windows) or wso2server.sh (for Linux.) 

6. Navigate to **Extensions** > **Configure** > **Lifecycles** and Click the *View/Edit* link corresponding to the 
*default API LifeCycle*.

7. Add a new execution for the **Publish** event under **CREATED** and **PROTOTYPED** states. 
Do not update the already existing execution for the publish event. Add a new execution.
    ```
    <execution forEvent="Publish" 
        class="org.wso2.carbon.apimgt.securityenforcer.executors.PingAIExecutor">
    </execution>
    ```
 
8. Add another execution for the **Retire** event under the **DEPRECATED** state.
   This will delete the model associated with the API in the ASE once the API is retired.
    ```
    <execution forEvent="Retire" 
        class="org.wso2.carbon.apimgt.securityenforcer.executors.PingAIExecutor">
    </execution>
    ```
     
### For the API Publisher

**For new APIs**

- Once the API is successfully [created](https://docs.wso2.com/display/AM260/Quick+Start+Guide#QuickStartGuide-CreatinganAPIfromscratch)
 and the life cycle state changed to **PUBLISHED**,
 a new model will be created in the ASE for the API and the handler will be added to the data flow. 
 Once the API state changed to **RETIRED**, the model will be deleted.

**For existing APIs**

- The recommended method is to create a [new version](https://docs.wso2.com/display/AM260/Quick+Start+Guide#QuickStartGuide-VersioningtheAPI) 
for the API with Ping Intelligence enabled.

    *Although changing the status of a live API is not recommended, republishing the API will update the synapse config 
    with the handler and by demoting to CREATED or PROTOTYPED state and changing the life cycle back to PUBLISHED state 
    will create a new model for API in the ASE.*

![alt text](https://raw.githubusercontent.com/wso2-extensions/apim-handler-pingai/master/images/publishedState.png)


**Note:**
By default, Ping intelligence policy will be included in all APIs published with individual AI model for each API. 
But this can be configured to [apply only for selected APIs.](https://github.com/wso2-extensions/apim-handler-pingai/blob/master/DEVELOPER_GUIDE.md#add-the-policy-only-for-selected-apis)


#### Verify the policy deployment:

1. Open the synapse Configuration of the published API, located in <APIM_HOME>/repository/deployment/server/synapse-configs/default/api directory. 
Check whether \<handler class="org.wso2.carbon.apimgt.securityenforcer.PingAISecurityHandler"/>  added under \<handlers>.
2. Open ASE command line. Using the CLI tool, you can list the published APIs in ASE.
Check whether the API is listed as <API_NAME>_\<VERSION>.
    Eg: HelloWorld_1.0.0

   
## Configurations
#### Bare minimum configurations
Add the following configurations to the  <APIM_HOME>/repository/conf/api-manager.xml file under \<APIManager> tag. If mode is not set, the default mode is set as async. If ModelCreationEndpoint configurations are not set, manual creation of ASE models will be needed.

```
    <PingAISecurityHandler>
        <OperationMode>async</OperationMode>
        <APISecurityEnforcer>
            <EndPoint>ASE_ENDPOINT</EndPoint>
            <ASEToken>SIDEBAND_AUTHENTICATION_TOKEN</ASEToken>
            <ModelCreationEndpoint>
                <EndPoint>ASE_REST_API_ENDPOINT</EndPoint>
                <AccessKey>ASE_REST_API_ACCESS_KEY</AccessKey>
                <SecretKey>ASE_REST_API_SECRET_KEY</SecretKey>
            </ModelCreationEndpointiscovery>
       </APISecurityEnforcer>
    </PingAISecurityHandler>
   ```

## Modes of Operation
To integrate this feature to WSO2 API Manager, a custom handler is implemented with the handleRequest and handleResponse methods. For every request, WSO2 gateway will send two sideband calls to ASE. First one is to analyze the metadata (Endpoint: ASE/request). The second one is to pass the status of the overall request after connecting to the backend (EndPoint: ASE/response). Second sideband call is mainly for the learning mode of AI Engine.


There are three modes of operation when implementing the extension.
1. Sync Mode
2. Async Mode
3. Hybrid Mode

The difference with all these modes is only with the first sideband request. The second sideband request will be asynchronous in all three modes.

### Sync Mode
In the sync mode, first sideband call is sent synchronously to the request dataflow. Depends on the ASE response, the handler will allow each request to connect the backend. 

This is a thread blocking call and every request will wait until the ASE respond.

   **Total time  =~0.2ms + ASE Sideband call time**


![alt text](https://raw.githubusercontent.com/wso2-extensions/apim-handler-pingai/master/images/syncFlow.png)

### Async Mode
In this mode, both sideband calls are sent asynchronously. There is a cache which records the response of each request sent to ASE. 

Since the metadata set of each client request is unique to the client (with the authorization header), the cache will record ASE response with the metadata. Metadata will be hashed with MD5 and the hash code is used as the key.

**Total time = < 0.2ms**

![alt text](https://raw.githubusercontent.com/wso2-extensions/apim-handler-pingai/master/images/asyncFlow.png)

**Important:**
*There is a slip rate as the requests received until the first cache update will be forwarded to the backend without monitoring.*


### Hybrid Mode

In this mode, if an ASE response for the metadata is not present in the cache, the thread will be blocked and the sideband call to ASE will be sent synchronously. With its response, the cache will be updated and depends on the response, the request will be processed.

The next request of the same client will be handled according to the cached response and later cache will be updated asynchronously.

Requests until the first cache update will be handled in the sync mode and after that, it will be handled in async mode.

For the cache, there is an expiry time for each record which is 15 mins after the last cache update.

![alt text](https://raw.githubusercontent.com/wso2-extensions/apim-handler-pingai/master/images/hybridFlow.png)

### Response

The second sideband request of each request is sent to ASE asynchronously with the status of the backend server.

![alt text](https://raw.githubusercontent.com/wso2-extensions/apim-handler-pingai/master/images/responseFlow.png)

## ASE Model Creation
For every API deployed with this feature, there will be a new model created at the security engine. Security decisions will be taken according to this model. A Template of the ASE configuration file is used with default values and API context is used as the url. When OAuth protected, authentication token is sent as the API key with default header name “APIKey”. If any of these values needs to be changed with API, that can be done with additional properties. Model creation request will be sent to the ASE REST API when the API’s state is changed to PUBLISHED from CREATE state or PROTOTYPED state. Once the API state changes to RETIRED, this model will be deleted.

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
    
    
 **Note:** After the Authentication handler, by default Authorization header will be removed from the transport headers. 
 However **auth token** will be sent as the API Key and will be added to the request metadata payload as a new transport header **APIKey**.
 If you want Authorization header to be present in the transport headers, either by adding the PingAISecurityHandler before Authentication handler or 
 by changing the default configuration of Authentication handler not to remove Authorization header after the handler, you can achieve that.
#### Changing the ASE model parameters
The API JSON file parameters define the behavior and properties of the API and the learning model. If there are more configurations for the AI model, add those configurations as additional properties before publishing the API. If no additional parameters added, default values will be used.

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

![alt text](https://raw.githubusercontent.com/wso2-extensions/apim-handler-pingai/master/images/ASEConfigsAsAdditionalProperties.png)

## Additional Configurations of Extension
Add the required configurations to the  <APIM_HOME>/repository/conf/api-manager.xml file under \<PingAISecurityHandler> tag.
   
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
By default, Ping intelligence will be included in all APIs with individual AI models for each API. To limit that to selected APIs, 
1. Add the additional configuration \<ApplyForAllAPIs>false\</ApplyForAllAPIs> with the configs in api-manager.xml.
2. Instead of updating the velocity-template with the handler, add following code inside the \<handlers xmlns="http://ws.apache.org/ns/synapse"> just after the foreach loop.
      ```
        #if($apiObj.additionalProperties.get('ai_security') == "enable")
            <handler class="org.wso2.carbon.apimgt.securityenforcer.PingAISecurityHandler"/>
        #end
     ```
     
    In default velocity_template.xml file, it should be as follows.
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

3. Log into the API Publisher and create a new API. Before publishing, add a new additional property named **ai_security** and valued **enable**.

4. Change the life cycle state to **PUBLISHED**.

![alt text](https://raw.githubusercontent.com/wso2-extensions/apim-handler-pingai/master/images/enablePolicyWithAdditionalProperties.png)

### Limit Transport Headers
All transport headers found in the client request and backend response will be sent to ASE by default. To limit the headers, add 
   ```
    <LimitTransportHeaders>
        <Header>HEADER_1</Header>
        <Header>HEADER_2</Header>
        <Header>HEADER_3</Header>
        <Header>HEADER_4</Header>
    </LimitTransportHeaders>
   ```

Only the intercept of headers mentioned and present in the transport headers will be sent to ASE in both sideband calls.

*If there is a transport header which changes with each request, it is essential to use this feature and drop that header. Otherwise feature will not be useful in the async and hybrid modes.*

### Other Configurations
#### Http Client Configurations
Configurations regarding the Http Client can be changed as follows.
  ```
    <DataPublisher>
        <MaxPerRoute>500</MaxPerRoute>
        <MaxOpenConnections>200</MaxOpenConnections>
        <ConnectionTimeout>30</ConnectionTimeout>
    </DataPublisher>   
   ```

#### Thread pool and stack object pool configurations
Concurrent requests received for the handler will be handled by a thread pool combined with a stack object pool.

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

## Encrypting Passwords with Cipher tool
The configuration file contains ASE access token, Management API Access Key and Secret Key. If encryption of sensitive data is needed, that capability is provided with the Cipher tool.

1. Open the cipher-tool.properties file stored in the <APIM_HOME>/repository/conf/security folder and add the following lines.
    - **APIManager.PingAISecurityHandler.ASE.ASEToken**=repository/conf/api-manager.xml//APIManager/PingAISecurityHandler/APISecurityEnforcer/ASEToken,false
    - **APIManager.PingAISecurityHandler.ASE.AccessKey**=repository/conf/api-manager.xml//APIManager/PingAISecurityHandler/APISecurityEnforcer/ModelCreationEndpoint/AccessKey,false
    - **APIManager.PingAISecurityHandler.ASE.SecretKey**=repository/conf/api-manager.xml//APIManager/PingAISecurityHandler/APISecurityEnforcer/ModelCreationEndpoint/SecretKey,false
 

2. Open the cipher-text.properties file stored in the <APIM_HOME>/repository/conf/security folder. Add the following lines to the cipher-text.properties file.(Password should be enclosed within square brackets)
    - **APIManager.PingAISecurityHandler.ASE.ASEToken**=[ASE_TOKEN]
    - **APIManager.PingAISecurityHandler.ASE.AccessKey**=[ACCESS_KEY]
    - **APIManager.PingAISecurityHandler.ASE.SecretKey**=[SECRET_KEY]

    *If your password contains a backslash character (\) you need to use an alias with the escape characters. For example, if your password is admin\\} the value should be given as shown in the example below.*
    - **APIManager.PingAISecurityHandler.ASE.AccessKey**=[admin\\\\}]

3. Open a command prompt and go to the <APIM_HOME>/bin directory, where the cipher tool scripts (for Windows and Linux) are stored. 
4. Execute the cipher tool script from the command prompt using the command relevant to your OS: 
    - On Windows: ./ciphertool.bat -Dconfigure
    - On Linux: ./ciphertool.sh -Dconfigure
5. The following message will be prompted: 
 
    "[Please Enter Primary KeyStore Password of Carbon Server :]"
    
6. Enter the keystore password (which is "wso2carbon" for the default keystore) and proceed. If the script execution is successful, you will see the following message: 

    "[Secret Configurations are written to the property file successfully]"
7. Now, to verify the password encryption: 

    Open the cipher-text.properties file and see that the plain text passwords are replaced by a cipher value.

#### Changing encrypted passwords
To change any password which we have encrypted already, follow the below steps:

1. Be sure to shut down the server.
2. Open a command prompt and go to the <APIM_HOME>/bin directory, where the cipher tool scripts (for Windows and Linux) are stored. 
3. Execute the following command for your OS:
    - On Linux: ./ciphertool.sh -Dchange
    - On Windows: ./ciphertool.bat -Dchange
    
    If you are using the cipher tool for the first time, this command will first initialize the tool for your product. The tool will then encrypt any plain text passwords that are specified in the cipher-text.properties file for automatic encryption.
5. It will prompt for the primary keystore password. Enter the keystore password (which is "wso2carbon" for the default keystore).
6. The alias values of all the passwords that you encrypted will now be shown in a numbered list. 
7. The system will then prompt you to select the alias of the password which you want to change. Enter the list number of the password alias.
8. The system will then prompt you (twice) to enter the new password. Enter your new password.


## Configurations Guide

| Field  | input| DefaultValue | Description|
| ------------- | ------------- | ------------- | ------------- |
|OperationMode|(String)<ul><li>async</li><li>sync</li><li>hybrid</li></ul>|async|The operation mode. <ul><li>Asynchronous mode -  async</li><li>Synchronous mode - sync</li><li>Hybrid mode - hybrid</li></ul>|
|ApplyForAllAPIs|(Boolean)|true|Apply Ping Intelligence for all APIs published.|
|CacheExpiryTime|(Integer)|15|Cache Expiry time in minutes.|

#### APISecurityEnforcer - ASE Configurations

| Field  | input| DefaultValue | Description|
| ------------- | ------------- | ------------- | ------------- |
|EndPoint|(String)|-|The endpoint of ASE. Support both HTTP and HTTPS.|
|ASEToken|(String)|-|If access token needed to communicate with ASE.|

#### ModelCreationEndpoint - ASE Management REST API Configurations

| Field  | input| DefaultValue | Description|
| ------------- | ------------- | ------------- | ------------- |
|Endpoint|(String)|-|The management endpoint of ASE. Support both HTTP and HTTPS.|
|AccessKey|(String)|-|AccessKey to the management endpoint.|
|SecretKey|(String)|-|SecretKey to the management endpoint.|

#### DataPublisher - HTTP Client configurations

| Field  | input| DefaultValue | Description|
| ------------- | ------------- | ------------- | ------------- |
|MaxPerRoute|(Integer)|500|The maximum number of HTTP connections allowed across all routes.|
|MaxOpenConnections|(Integer)|200|The maximum number of HTTP connections allowed for a route.|
|ConnectionTimeout|(Integer)|30|Connection timeout for the HTTP request in seconds. The socket timeout is set with the addition of another 10 seconds.|

#### ThreadPoolExecutor - ThreadPoolExecutor configurations

| Field  | input| DefaultValue | Description|
| ------------- | ------------- | ------------- | ------------- |
|CorePoolSize|(Integer)|200|The number of threads to keep in the pool, even if they are idle.|
|MaximumPoolSize|(Integer)|500|The maximum number of threads to allow in the pool.|
|KeepAliveTime|(Long)|100|When the number of threads is greater than the core, this is the maximum time in seconds that excess idle threads will wait for new tasks before terminating.|

#### StackObjectPool - StackObjectPool Configurations

| Field  | input| DefaultValue | Description|
| ------------- | ------------- | ------------- | ------------- |
|MaxIdle|(Integer)|100|Cap on the number of "sleeping" instances in the pool.|
|InitIdleCapacity|(Integer)|50|Initial size of the pool (this specifies the size of the container, it does not cause the pool to be pre-populated.)|

#### LimitTransportHeaders

| Field  | input| DefaultValue | Description|
| ------------- | ------------- | ------------- | ------------- |
|Header|(String)|-|Name of the header needed to sent to ASE.|


