# Introduction

WSO2 API Manager is a full lifecycle API Management solution which has an API Gateway and a Microgateway.

This explains how WSO2 API Manager plans to integrate with PingIntelligence and expose APIs protected with
artificial intelligence (AI).

## WSO2 API Manager Extension with PingIntelligence

### What is PingIntelligence for APIs?
PingIntelligence for APIs uses artificial intelligence (AI) to expose active APIs, identify and automatically block cyber attacks on APIs and provide detailed reporting on all API activity. You can deploy the PingIntelligence solution on premises, in public clouds, or in hybrid clouds to monitor API traffic across the environment. PingIntelligence uses AI and machine learning models to detect anomalous API behavior, without relying on specifically defined policies or prior knowledge of attack patterns, in order to stop new and constantly changing attacks. In addition, PingIntelligence uses its continuous learning capabilities to become more accurate at identifying and blocking attacks over time.

PingIntelligence for APIs can detect many types of cyberattacks, most of which are not visible to API teams today and can go undetected for very long times.

[Read more about cyber attacks that can be detected by Ping Intelligence.](https://github.com/wso2-extensions/apim-handler-pingai/blob/1.0.x/DEVELOPER_GUIDE.md#types-of-attacks-pingintelligence-protects-against)

### How does integration happen?
The WSO2 API Manager extension for PingIntelligence uses a new custom handler (Ping AI Security Handler) when working with the WSO2 API Gateway data flow. After this handler receives a request from a client, a sideband call is sent to PingIdentity’s API Security Enforcer (ASE) with the client request metadata. The ASE responds after analyzing the metadata with an Artificial Intelligence Engine.

If the response of ASE is 200 OK, the Ping AI Security Handler forwards the request and if the response is 403, it blocks the request.

![alt text](https://raw.githubusercontent.com/wso2-extensions/apim-handler-pingai/1.0.x/images/architecture.png)

## Quick Start Guide

### Prerequisites

- **Install Java 7 or 8.**
(http://www.oracle.com/technetwork/java/javase/downloads/)

- **Install Apache Maven 3.x.x**
 (https://maven.apache.org/download.cgi#)

- **This branch is for API manager versions of 2.x. Download the relevant API manager**
(https://wso2.com/api-management/)

    Installing WSO2 is very fast and easy. Before you begin, be sure you have met the installation prerequisites,
    and then follow the [installation instructions for your platform](https://docs.wso2.com/display/AM260/Installing+the+Product).

- **Install the PingIntelligence software.**

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

    If ASE is not in sideband mode, then stop the ASE and change the mode by editing the
    */opt/pingidentity/ase/config/ase.conf* file. Set the mode as **sideband** and start the ASE.

- **Enable sideband authentication.**

  To ensure a secure communication between WSO2 Gateway and the ASE, enable sideband authentication by entering the following
  command in the ASE command line:
   ```
    # ./bin/cli.sh -u admin –p admin enable_sideband_authentication
   ```

- **Generate sideband authentication token.**

   A token is required for WSO2 Gateway to authenticate with ASE. To generate the token in the ASE, enter the following
   command in the ASE command line:
   ```
   # ./bin/cli.sh -u admin -p admin create_sideband_token
   ```
   Save the generated authentication token for further use.


- **Add the certificates of the ASE sideband request endpoint and management endpoint to the WSO2 client keystore.**

    Use *wso2carbon* as the default keystore password.
   ```
    keytool -importcert -file <ase_request_endpoint_cert_name>.cer -keystore <APIM_HOME>/repository/resources/security/client-truststore.jks -alias "ASE request endpoint"

    keytool -importcert -file <ase_management_endpoint_cert_name>.cer -keystore <APIM_HOME>/repository/resources/security/client-truststore.jks -alias "ASE management endpoint"
   ```
    [Obtaining ASE request endpoint and management endpoint public key certificates](#obtaining-ase-certificates)

## Deploy the WSO2 extension with PingIntelligence

### For system admin

1. Download the extension and navigate to the **apim-handler-pingai** directory. Update the pom.xml with corresponding dependency versions and run the following Maven command.
    ```
    mvn clean install
    ```
    org.wso2.carbon.apimgt.securityenforcer-\<version>.jar file can be found in **apim-handler-pingai/target** directory.

    Use the following table to update pom.xml with the corresponding dependency versions for API manager.

     | Dependency                |   APIM 3.0.0   |  APIM 2.6.0   |  APIM 2.5.0   |  APIM 2.2.0   |  APIM 2.1.0   |
     | ------------------------- | :------------: | :-----------: | :-----------: | :-----------: | :-----------: |
     | carbon.apimgt.version     |    6.5.349     |    6.4.50     |    6.3.95     |    6.2.201    |    6.1.66     |
     | carbon.kernel.version     |     4.5.1      |    4.4.35     |    4.4.32     |    4.4.26     |    4.4.11     |
     | carbon.governance.version |     4.8.10     |    4.7.29     |    4.7.27     |    4.7.23     |     4.7.0     |
     | synapse.version           | 2.1.7-wso2v131 | 2.1.7-wso2v80 | 2.1.7-wso2v65 | 2.1.7-wso2v48 | 2.1.7-wso2v10 |


2. Add the JAR file of the extension to the directory **<APIM_HOME>/repository/components/dropins**.

3. Add the bare minimum configurations to the *api-manager.xml* within the tag \<APIManager>, which can be found in the
**<APIM_HOME>/repository/conf** directory.

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
    **[async](https://github.com/wso2-extensions/apim-handler-pingai/blob/1.0.x/DEVELOPER_GUIDE.md#async-mode)**, and
    **[hybrid](https://github.com/wso2-extensions/apim-handler-pingai/blob/1.0.x/DEVELOPER_GUIDE.md#hybrid-mode)**.
    If the mode is not set, the default mode is set as **sync**.
    - ASE_ENDPOINT : https://\<ase-host-machine-ip>:\<data-port>
    - BACKUP_ASE_SIDEBAND_REQUEST_ENDPOINT : https://\<backup-ase-host-machine-ip>:\<data-port>
    - ASE_REST_API_ENDPOINT: https://\<ase-host-machine-ip>:\<management-port>/\<REST-API-version>/ase/api.
    - If you have not set the ModelCreationEndpoint configurations, you will need to manually create the ASE models.
    - Include the [sideband authentication token](https://github.com/wso2-extensions/apim-handler-pingai/blob/1.0.x/DEVELOPER_GUIDE.md#prerequisites)
     that you obtained from the ASE as the ASEToken.
     - For additional security you can [encrypt](https://github.com/wso2-extensions/apim-handler-pingai/blob/1.0.x/DEVELOPER_GUIDE.md#encrypting-passwords-with-cipher-tool) the SIDEBAND_AUTHENTICATION_TOKEN, ASE_REST_API_ACCESS_KEY, ASE_REST_API_SECRET_KEY.

4. Update the **<APIM_HOME>/repository/resources/api_templates/velocity_template.xml** file in order to engage the handler to APIs. Add the handler class as follows inside the
   *\<handlers xmlns="http://ws.apache.org/ns/synapse">* just after the foreach loop.
   ```
   <handler class="org.wso2.carbon.apimgt.securityenforcer.PingAISecurityHandler"/>
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

- After the API is successfully created and the life cycle state changes to **PUBLISHED**,
 a new model is created in the ASE for the API and the handler is added to the data flow.
 When the API state changes to **RETIRED**, the model will be deleted.

**For existing APIs**

- The recommended method is to create a [new version](https://docs.wso2.com/display/AM260/Quick+Start+Guide#QuickStartGuide-VersioningtheAPI)
for the API with PingIntelligence enabled.

    *Although changing the status of a live API is not recommended, when an API is republished, it updates the Synapse config with the handler and
    by demoting to CREATED or PROTOTYPED state and changing the life cycle back to PUBLISHED state
   will create a new model for API in the ASE.*


**Note:**
By default, PingIntelligence is enabled in all APIs that are published with an individual AI model.
However, if needed you can configure PingIntelligence to be [applied only for selected APIs.](https://github.com/wso2-extensions/apim-handler-pingai/blob/1.0.x/DEVELOPER_GUIDE.md#add-the-policy-only-for-selected-apis)


### Developer Guide

For more information, see the [Developer Guide](https://github.com/wso2-extensions/apim-handler-pingai/blob/1.0.x/DEVELOPER_GUIDE.md).

### Obtaining ASE certificates

openssl client can be used to obtain the ASE sideband request endpoint and management endpoint certificates.
```
openssl s_client -showcerts -connect <ase-host-machine-ip>:<data-port>

openssl s_client -showcerts -connect <ase-host-machine-ip>:<management-port>
```

Copy the content from -----BEGIN CERTIFICATE----- to -----END CERTIFICATE----- into <ase_request_endpoint_cert_name>.cer and <ase_management_endpoint_cert_name>.cer files. These certs can be imported into WSO2 client keystore.
