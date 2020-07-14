# Introduction

WSO2 API Manager is a full lifecycle API Management solution which has an API Gateway and a Microgateway.

This explains how WSO2 API Manager plans to integrate with PingIntelligence and expose APIs protected with
artificial intelligence (AI).

## WSO2 API Manager Extension with PingIntelligence

### What is PingIntelligence for APIs?
PingIntelligence for APIs uses artificial intelligence (AI) to expose active APIs, identify and automatically block cyber attacks on APIs and provide detailed reporting on all API activity. You can deploy the PingIntelligence solution on premises, in public clouds, or in hybrid clouds to monitor API traffic across the environment. PingIntelligence uses AI and machine learning models to detect anomalous API behavior, without relying on specifically defined policies or prior knowledge of attack patterns, in order to stop new and constantly changing attacks. In addition, PingIntelligence uses its continuous learning capabilities to become more accurate at identifying and blocking attacks over time.

PingIntelligence for APIs can detect many types of cyberattacks, most of which are not visible to API teams today and can go undetected for very long times.

[Read more about cyber attacks that can be detected by Ping Intelligence.](https://github.com/wso2-extensions/apim-handler-pingai/blob/master/DEVELOPER_GUIDE.md#types-of-attacks-pingintelligence-protects-against)

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

### How does integration happen?
The WSO2 API Manager extension for PingIntelligence uses a new custom handler (Ping AI Security Handler) when working with the WSO2 API Gateway data flow. After this handler receives a request from a client, a sideband call is sent to PingIdentity’s API Security Enforcer (ASE) with the client request metadata. The ASE responds after analyzing the metadata with an Artificial Intelligence Engine.

If the response of ASE is 200 OK, the Ping AI Security Handler forwards the request and if the response is 403, it blocks the request.

![alt text](https://raw.githubusercontent.com/wso2-extensions/apim-handler-pingai/master/images/architecture.png)





### Quick Start Guide

To use this extension with WSO2 API Manager 3.0.0 or newer versions, see [Quick Start Guide New](https://github.com/wso2-extensions/apim-handler-pingai/blob/master/QUICK_START_GUIDE_NEW.md).

WSO2 API Manager 2.6.0 or older versions, see [Quick Start Guide Old](https://github.com/wso2-extensions/apim-handler-pingai/blob/master/QUICK_START_GUIDE_OLD.md).
