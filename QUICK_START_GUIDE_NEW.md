# WSO2 API Manager extension with PingIntelligence

#### Prerequisites

- **Install Java 7 or 8.**
(http://www.oracle.com/technetwork/java/javase/downloads/)

- **Install Apache Maven 3.x.x**
 (https://maven.apache.org/download.cgi#)

- **Install the latest WSO2 API Manager**. If you are using API manager versions 2.x, please use the 1.0.x branch of this repository.
(https://wso2.com/api-management/)

    Installing WSO2 is very fast and easy. Before you begin, be sure you have met the installation prerequisites, 
    and then follow the [installation instructions for your platform](https://apim.docs.wso2.com/en/latest/install-and-setup/install/installing-the-product/installing-the-product/).

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

- **Add the certificates of the ASE sideband request endpoint and management endpoint to the WSO2 client keystore.**

    Use *wso2carbon* as the default keystore password.
   ```
    keytool -importcert -file <ase_request_endpoint_cert_name>.cer -keystore <APIM_HOME>/repository/resources/security/client-truststore.jks -alias "ASE request endpoint"

    keytool -importcert -file <ase_management_endpoint_cert_name>.cer -keystore <APIM_HOME>/repository/resources/security/client-truststore.jks -alias "ASE management endpoint"
   ```
   [Obtaining ASE request endpoint and management endpoint public key certificates](https://github.com/wso2-extensions/apim-handler-pingai/blob/master/QUICK_START_GUIDE_NEW.md#obtaining-ase-certificates)

## Deploy WSO2 Extension with PingIntelligence

**IMPORTANT**

Following configurations are for WSO2 Api Manager 3.0.0 or newer versions. For older versions, please refer
 [Developer Guide.](https://github.com/wso2-extensions/apim-handler-pingai/blob/master/DEVELOPER_GUIDE_OLD.md)


### For System Admin

1. Download the extension and navigate to the **apim-handler-pingai** directory. Update the pom.xml with corresponding dependency versions and run the following Maven command.
   ```
    mvn clean install
     ```
    org.wso2.carbon.apimgt.securityenforcer-\<version>.jar file can be found in **apim-handler-pingai/target** directory.

    Use the following table to update pom.xml with the corresponding dependency versions for API manager.

     | Dependency                |  APIM 3.2.0      |  APIM 3.1.0   |  APIM 3.0.0   |  
     | ------------------------- | :---------------:| :-----------: | :-----------: | 
     | org.wso2.carbon.apimgt    |    6.7.206       |    6.6.163    |    6.5.349    | 

2. Add the JAR file of the extension to the **<APIM_HOME>/repository/components/dropins** directory.
   You can find the org.wso2.carbon.apimgt.securityenforcer-\<version>.jar file in the **apim-handler-pingai/target** directory.

3. Add the bare minimum configurations to the *deployment.toml* file, which can be found in the
**<APIM_HOME>/repository/conf** directory.

   ```
    [apim.ai_security]
    operation_mode = "sync"
    sideband_request_endpoint = "ASE_SIDEBAND_REQUEST_ENDPOINT"
    backup_sideband_request_endpoint = "BACKUP_ASE_SIDEBAND_REQUEST_ENDPOINT"
    ase_token = "SIDEBAND_AUTHENTICATION_TOKEN"
    model_creation_endpoint = "ASE_REST_API_ENDPOINT"
    access_key = "ASE_REST_API_ACCESS_KEY"
    secret_key = "ASE_REST_API_SECRET_KEY"
   ```
     **Note:**

    - Select the Operation mode from **[sync](https://github.com/wso2-extensions/apim-handler-pingai/blob/master/DEVELOPER_GUIDE_NEW.md#sync-mode)**,
        **[async](https://github.com/wso2-extensions/apim-handler-pingai/blob/master/DEVELOPER_GUIDE_NEW.md#async-mode)** and
        **[hybrid](https://github.com/wso2-extensions/apim-handler-pingai/blob/master/DEVELOPER_GUIDE_NEW.md#hybrid-mode)**.
        If the mode is not set, the default mode is set as **sync**.
   - ASE_SIDEBAND_REQUEST_ENDPOINT : https://\<ase-host-machine-ip>:\<data-port>
   - BACKUP_ASE_SIDEBAND_REQUEST_ENDPOINT : https://\<backup-ase-host-machine-ip>:\<data-port>
   - ASE_REST_API_ENDPOINT: https://\<ase-host-machine-ip>:\<management-port>/\<REST-API-version>/ase/api.
   - If ModelCreationEndpoint configurations are not set, you need to manually create ASE models.
   - Include the [sideband authentication token](https://github.com/wso2-extensions/apim-handler-pingai/blob/master/DEVELOPER_GUIDE_NEW.md#prerequisites)
         obtained from the ASE as the ASEToken.
   - For additional security you can [encrypt](https://github.com/wso2-extensions/apim-handler-pingai/blob/master/DEVELOPER_GUIDE_NEW.md#encrypting-passwords-with-cipher-tool) the SIDEBAND_AUTHENTICATION_TOKEN, ASE_REST_API_ACCESS_KEY, and the ASE_REST_API_SECRET_KEY.

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
7. Update the **<API_HOME>/repository/resources/conf/templates/repository/conf/api-manager.xml.j2** file for wso2 to pick up the back up ASE end point configuration.
    Add the below line in \<APISecurityEnforcer> tag under <EndPoint>{{apim.ai_security.sideband_request_endpoint}}</EndPoint>
    ```
    <BackupEndPoint>{{apim.ai_security.backup_sideband_request_endpoint}}</BackupEndPoint>
    ```
   
   If you want to disable certificate validation of both ASE and Management endpoints, add the following line in the
    api-manager.xml after the if condition of ApplyForAllAPIs.
    
    ```
   {% if apim.ai_security.skip_cert_validation is defined %}
   <SkipCertValidation>{{apim.ai_security.skip_cert_validation}}</SkipCertValidation>
   {% endif %}
   ```

### For the API Publisher

**For new APIs**

- When the API is successfully [created](https://apim.docs.wso2.com/en/latest/getting-started/quick-start-guide/#step-1-create-and-publish-an-api) and the life cycle state changes to **PUBLISHED**,
 a new model is created in the ASE for the API and the handler is added to the data flow.
 When the API state changes to **RETIRED**, the model is deleted.

**For existing APIs**

- The recommended method is to create a new version for the API with PingIntelligence enabled.

    *Although changing the status of a live API is not recommended, republishing the API will update the Synapse config
    with the handler and by demoting to the CREATED or PROTOTYPED state and thereafter changing the life cycle back to the PUBLISHED state
    it will create a new model for the API in the ASE.*


![alt text](https://raw.githubusercontent.com/wso2-extensions/apim-handler-pingai/master/images/life-cycles-new.png)


**Note:**
By default, PingIntelligence is enabled in all APIs that are published with an individual AI model.
However, if needed you can configure PingIntelligence to be [applied only for selected APIs.](https://github.com/wso2-extensions/apim-handler-pingai/blob/master/DEVELOPER_GUIDE_NEW.md#add-the-policy-only-for-selected-apis)


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

## Obtaining ASE certificates

openssl client can be used to obtain the ASE sideband request endpoint and management endpoint certificates.
```
openssl s_client -showcerts -connect <ase-host-machine-ip>:<data-port>

openssl s_client -showcerts -connect <ase-host-machine-ip>:<management-port>
```

Copy the content from -----BEGIN CERTIFICATE----- to -----END CERTIFICATE----- into <ase_request_endpoint_cert_name>.cer and <ase_management_endpoint_cert_name>.cer files. These certs can be imported into WSO2 client keystore.

### Developer Guide

For more information, see the [Developer Guide](https://github.com/wso2-extensions/apim-handler-pingai/blob/master/DEVELOPER_GUIDE_NEW.md).

