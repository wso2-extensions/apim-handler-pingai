# Introduction

WSO2 API Manager is a full lifecycle API Management solution which has an API Gateway and a Microgateway. 

This explains how WSO2 API Manager plans to integrate with Ping Intelligence and expose APIs protected with 
Artificial Intelligence.

## API Manager Extension with Ping Intelligence

### What is PingIntelligence for APIs?
PingIntelligence for APIs uses artificial intelligence (AI) to expose active APIs, identify and automatically block cyber attacks on APIs and provide detailed reporting on all API activity. Deployed on premises, in public clouds or in hybrid clouds, the solution monitors API traffic across the environment. It uses AI and machine learning models to detect anomalous API behavior without relying on specifically defined policies or prior knowledge of attack patterns in which, can stop new and constantly changing attacks. Using continuous learning capabilities, it becomes more accurate at identifying and blocking attacks over time. 

PingIntelligence for APIs can detect many types of cyberattacks, most of which are not visible to API teams today and can go undetected for very long times. 

[Read more about cyber attacks which can be detected by Ping Intelligence.](https://github.com/1akshitha/apim-handler-pingai/blob/master/DEVELOPER_GUIDE.md)

### How does integration happen?

There is a handler for the WSO2 API Gateway and once it receives a request from a client, a sideband request will be sent to PingIdentitys’ API Security Enforcer (ASE) with the client requests’ metadata. ASE will analyze the metadata with an Artificial Intelligence Engine and respond. 

If the response of ASE is 200 OK, the handler will forward the request and if the response is 403, it will block the request.

![alt text](https://raw.githubusercontent.com/1akshitha/apim-handler-pingai/master/images/architecture.png)


## Quick Start Guide

### Prerequisites

- **PingIntelligence software installation.**

    PingIntelligence 3.2.1 software is installed and configured. For installation of PingIntelligence software, 
    see the manual or platform specific automated deployment guides.
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
    # ./bin/cli.sh enable_sideband_authentication -u admin –p
   ```
   
- **Generate sideband authentication token.**

   A token is required for WSO2 gateway to authenticate with ASE. To generate the token in ASE, enter the following 
   command in the ASE command line:
   ```
   # ./bin/cli.sh -u admin -p admin create_sideband_token
   ```
   Save the generated authentication token for further use.
   
- **Add the certificate of ASE to WSO2 client keystore.**
   ```
    keytool -importcert -file <certificate_name>.cer -keystore <APIM_HOME>/repository/resources/security/client-truststore.jks -alias "Alias"
   ```

   

## Deploy WSO2 Extension with Ping Intelligence

### For System admin

1. Add the JAR file of the extension to the directory **<APIM_HOME>/repository/components/dropins**. 

    Name of the JAR should be *org.wso2.carbon.apimgt.securityenforcer-\<version>-SNAPSHOT.jar*

2. Add the bare minimum configurations to the *api-manager.xml* within the tag \<APIManager>, which can be found in 
**<PRODUCT_HOME>/repository/conf** folder.

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
    **Note:**
    - Select the Operation mode from **[sync](https://github.com/1akshitha/apim-handler-pingai/blob/master/DEVELOPER_GUIDE.md#sync-mode)**,
    **[async](https://github.com/1akshitha/apim-handler-pingai/blob/master/DEVELOPER_GUIDE.md#async-mode)** and 
    **[hybrid](https://github.com/1akshitha/apim-handler-pingai/blob/master/DEVELOPER_GUIDE.md#hybrid-mode)**.
    If mode is not set, the default mode is set as **async**. 
    - If ModelCreationEndpoint configurations are not set,manual creation of ASE models will be needed.
    - Include the [sideband authentication token](https://github.com/1akshitha/apim-handler-pingai/blob/master/DEVELOPER_GUIDE.md#prerequisites)
     obtained from ASE as the ASEToken.
     - For additional security SIDEBAND_AUTHENTICATION_TOKEN, ASE_REST_API_ACCESS_KEY, ASE_REST_API_SECRET_KEY can be added to the secure vault.   

3. To engage the handler to APIs, you need to update the *velocity_template.xml* file. 
It can be found in **<APIM_HOME>/repository/resources/api_templates** directory.
   Add the handler as follows inside the 
   *\<handlers xmlns="http://ws.apache.org/ns/synapse">* just after the foreach loop.
   ```
   <handler class="org.wso2.carbon.apimgt.securityenforcer.PingAISecurityHandler"/> 
   ```
  
4. Deploy the WSO2 API Manager and open the management console: https://localhost:9443/carbon.

5. Navigate to **Extensions** > **Configure** > **Lifecycles** and Click the *View/Edit* link corresponding to the 
*default API LifeCycle*.

6. Add a new execution for the **Publish** event under **CREATED** and **PROTOTYPED** states. 
Do not update the already existing execution for the publish event. Add a new execution.
    ```
    <execution forEvent="Publish" 
        class="org.wso2.carbon.apimgt.securityenforcer.executors.PingAIExecutor">
    </execution>
    ```
 
7. Add another execution for the **Retire** event under the **DEPRECATED** state.
   This will delete the model associated with the API in the ASE once the API is retired.
    ```
    <execution forEvent="Retire" 
        class="org.wso2.carbon.apimgt.securityenforcer.executors.PingAIExecutor">
    </execution>
    ```
     
### For the API Publisher

**For new APIs**

- Once the API is successfully created and the life cycle state changed to **PUBLISHED**,
 a new model will be created in the ASE for the API and the handler will be added to the data flow. 
 Once the API state changed to **RETIRED**, the model will be deleted.

**For existing APIs**

- The recommended method is to create a new version for the API with Ping Intelligence enabled.

    *Republishing the API will update the synapse config with the handler and by changing the life cycle to PUBLISHED 
    will create a new model.*


**Note:**
By default, Ping intelligence policy will be included in all APIs published with individual AI model for each API. 
But this can be configured to [apply only for selected APIs.](https://github.com/1akshitha/apim-handler-pingai/blob/master/DEVELOPER_GUIDE.md#add-the-policy-only-for-selected-apis)


### Developer Guide

Developer Guide can be found in [here](https://github.com/1akshitha/apim-handler-pingai/blob/master/DEVELOPER_GUIDE.md).