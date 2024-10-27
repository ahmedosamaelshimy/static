
### Introduction to Azure Activity Logs and Elastic for Security Investigations

Azure Activity Logs provide a comprehensive record of actions taken by users, roles, or Azure services within the Azure environment. These logs capture detailed information about API calls made to Azure resources, including who made the call, the originating resource, and the actions performed.

For example, when an administrator creates a new virtual machine or modifies a network security group, Azure Activity Logs document this activity, offering crucial data for auditing and forensic analysis.

Understanding Azure Activity Logs is vital as they provide visibility into the operations of Azure services and applications. Think of them as security cameras for your cloud infrastructure, recording every action that occurs. This visibility is essential for:

- **Compliance**: Ensuring adherence to regulatory standards.
- **Security Investigation**: Tracing the source of security incidents or breaches.
- **Operational Troubleshooting**: Understanding actions that may impact system performance.

Azure Activity Logs are invaluable for forensic analysts, as they contain a detailed history of Azure service activities, which can be crucial for identifying unauthorized access or changes in the environment.

Elastic is a powerful platform designed to analyze large volumes of data, making it an ideal tool for examining Azure Activity Logs. With Elastic, you can efficiently search and visualize data from various sources, including Azure Activity Logs, enabling the identification of patterns, trends, and anomalies that can enhance your log analysis.

### Identifying and Investigating Unauthorized Access

In the vast cloud environment, security incidents such as unauthorized access pose significant threats to organizational assets and data. Cloud forensics in Azure involves techniques and methodologies to analyze security incidents occurring within Microsoft Azure. By focusing on Azure Activity Logs, we can gain insights into user activities and API usage, which are essential for tracing unauthorized access attempts and compromised accounts.

Unauthorized access often begins with a compromised account. Attackers may exploit weak passwords, conduct brute-force attacks, or utilize stolen credentials to gain access. Once inside, they can move laterally across the network, accessing sensitive data and resources. Identifying threats among potentially thousands of log entries requires a structured approach that starts broad and narrows down to specific anomalies.

1. **Start Broad**: Review all Azure Activity Log data within a specific timeframe. Consider what normal activity looks like and identify any outliers.
2. **Filter by Event Type**: Focus on authentication activities. Are there any anomalies, such as an unusual number of failed login attempts?
3. **Analyze Failures**: Aggregate failed login attempts to highlight potential unauthorized access.
4. **Spot the Anomaly**: Investigate isolated suspicious activities. Are there legitimate explanations for these failures, or do they indicate a compromised account?

To begin the investigation, concentrate on analyzing Azure Activity Logs through Elastic queries. These logs provide a targeted dataset for analysis. By focusing on authentication-related events, we can effectively pinpoint access attempts and potential compromises.

After identifying a potentially compromised account, the next step is to determine the scope of unauthorized access.

- **Define the Scope**: What does unauthorized access entail in your Azure environment? Is it limited to specific Azure Blob Storage containers, or does it extend to modifying role assignments?
- **Use Elastic to Isolate Events**: Investigate the actions of the compromised account. What resources were accessed or modified, and when did these activities occur?
- **Determine the Timeline**: Establishing a timeline of unauthorized activities helps understand the sequence of events. Utilize Elastic to sort and visualize this data effectively.
- **Evaluate the Impact**: Assess the sensitivity of the accessed data and the potential impact of the unauthorized access.

### Analyzing Configuration Changes and Unauthorized Persistence

Configuration changes in cloud environments, particularly those affecting security settings like Azure Storage access policies, can have significant implications. Unauthorized changes may expose sensitive data, leading to breaches. Monitoring and analyzing these changes is crucial for maintaining the security posture of your Azure environment.

Using Elastic, we can sift through Azure Activity Logs to identify any storage accounts modified to allow public access. Understanding how attackers exploit misconfigured settings to access sensitive data is critical, as public exposure can lead to serious financial and reputational damage.

- Narrow down the search to Azure Activity Logs.
- Filter for changes to access policies indicating modifications to public access settings.
- Refine the search to actions taken by suspected compromised accounts.
- Analyze results to identify affected resources.

Attackers often create new user accounts or modify group memberships to maintain persistence and elevate privileges within a compromised environment. Detecting these activities early can help mitigate damage.

To detect unauthorized user creation, focus on user creation events within Azure Activity Logs. Filter these events for analysis to identify accounts that may have been created by attackers.

To identify group modifications, look for changes in group membership to understand the access scope granted to unauthorized users.

When constructing and analyzing queries, it’s essential to understand not just the "how" but also the "why." Each component of an Elastic query serves a specific purpose, from narrowing the focus to relevant logs to isolating events indicating security actions or concerns.

Understanding the purpose of each query allows for adaptation and modification as needed, empowering you to be not just a user of Elastic but a proficient analyst capable of navigating complex cloud environments.

--- 

Sure! Here’s a walkthrough that includes educational content based on the questions you provided, focusing on Azure and Elastic:

---

### Walkthrough: Investigating Security Incidents in Azure Using Elastic

This walkthrough will guide you through the process of investigating security incidents in Azure using Elastic, highlighting key concepts and techniques for effective analysis. Each step corresponds to critical questions related to a hypothetical security incident.

#### Step 1: Identify the Origin of Suspicious Activity

**Question:** As a US-based company, the security team has observed significant suspicious activity from an unusual country. What is the name of the country from which the attacker originated?  
**Answer:** Germany  

**Educational Content:**  
Understanding the geographical origin of traffic is crucial for identifying potential threats. By analyzing the `source.geo.country_name` field in your logs, you can quickly identify where suspicious activity is coming from. This information can help prioritize your response based on the risk profile of that region.

**KQL Query:**  
```
source.geo.country_name: "Germany"
```

---

#### Step 2: Determine the Number of IPs Used by the Attacker

**Question:** How many IPs were employed by the attacker?  
**Answer:** 9  

**Educational Content:**  
Tracking the number of unique IP addresses involved in suspicious activities can provide insights into the scale of an attack. Multiple IPs may indicate an organized effort or the use of proxies to mask the attacker’s true location.

**KQL Query:**  
```
source.geo.country_name: "Germany"
```
**Follow-Up:** Check `source.ip` statistics.

---

#### Step 3: Establish an Incident Timeline

**Question:** What is the timestamp of the initial activity originating from the country?  
**Answer:** 05-10-2023 15:09:57  

**Educational Content:**  
Creating a timeline of events is vital for understanding the sequence of an attack. By sorting logs by timestamp, you can visualize the progression of the incident, making it easier to pinpoint when specific actions were taken.

**KQL Query:**  
```
source.geo.country_name: "Germany"
```
**Follow-Up:** Sort by oldest.

---

#### Step 4: Identify the Compromised User Account

**Question:** What is the display name of the user account that was compromised?  
**Answer:** alice  

**Educational Content:**  
Identifying compromised accounts is essential for assessing the impact of a security incident. Using the `event.category` and `event.outcome` fields can help filter for successful authentications, leading you to affected user accounts.

**KQL Query:**  
```
source.geo.country_name: "Germany" AND event.category: "authentication" AND event.outcome: "success"
```

---

#### Step 5: Analyze Access to Blob Storage

**Question:** What is the name of the script file the attacker accessed within blob storage?  
**Answer:** service-config.ps1  

**Educational Content:**  
Understanding what resources an attacker accessed can reveal their intentions and methods. Investigating blob storage access, especially for sensitive files, can uncover potential data exfiltration or further exploitation.

**KQL Query:**  
```
azure.eventhub.operationName: "GetBlob"
```

---

#### Step 6: Identify the Storage Account

**Question:** What is the name of the storage account housing the script file?  
**Answer:** cactusstorage2023  

**Educational Content:**  
Identifying the specific storage account linked to malicious activity helps assess risk and remediate vulnerabilities. Checking the `accountName` field will guide you to the resources involved.

**Follow-Up:**  
Check `azure.eventhub.properties.accountName`.

---

#### Step 7: Investigate Additional Compromised Accounts

**Question:** What is the user principal name (UPN) of the second user account compromised?  
**Answer:** it.admin1@cybercactus.onmicrosoft.com  

**Educational Content:**  
Understanding the scope of the attack includes identifying all compromised accounts. Analyzing logs for successful authentication can help discover additional victims of the attack.

**KQL Query:**  
```
source.geo.country_name: "Germany" AND event.category: "authentication" AND event.outcome: "success"
```

---

#### Step 8: Assess VM Activity

**Question:** What is the name of the Virtual Machine (VM) the attacker started?  
**Answer:** Dev01VM  

**Educational Content:**  
Monitoring virtual machine activity can reveal whether attackers are leveraging your infrastructure. Tracking actions like starting VMs helps you understand their operational footprint.

**KQL Query:**  
```
azure.activitylogs.identity.authorization.action: *start*
```
**Follow-Up:** Check the `azure.resource.name` field.

---

#### Step 9: Evaluate Data Exposure

**Question:** What is the name of the database exported?  
**Answer:** CustomerDataDB  

**Educational Content:**  
Understanding data exports is crucial for assessing potential data breaches. Knowing which databases were accessed can inform your response and remediation strategies.

**KQL Query:**  
```
azure.activitylogs.identity.authorization.action: *export*
```
**Follow-Up:** Check the `azure.resource.name` field.

---

#### Step 10: Discover Persistence Techniques

**Question:** What is the display name associated with the user account you have discovered?  
**Answer:** IT Support  

**Educational Content:**  
Attackers often create new accounts or modify existing ones to maintain access. Identifying these accounts is vital for mitigating ongoing threats.

**KQL Query:**  
```
azure.auditlogs.properties.operation_type: "Add"
```

---

#### Step 11: Determine Added Roles

**Question:** What role was added to the account created to persist in the environment?  
**Answer:** Owner  

**Educational Content:**  
Understanding the roles assigned to compromised accounts helps assess the potential impact of an attack. High-level roles may grant attackers extensive access to resources.

**KQL Query:**  
```
azure.activitylogs.identity.authorization.action: *role*
```
**Follow-Up:** Check the `azure.activitylogs.identity.authorization.evidence.role` field.

---

#### Step 12: Analyze Login Activity

**Question:** What is the timestamp of the first successful login recorded for this user account?  
**Answer:** 06-10-2023 07:30:43  

**Educational Content:**  
Recording successful login timestamps helps build a complete timeline of an attack. This information can aid in understanding how long an attacker has had access and what actions they may have taken.

**KQL Query:**  
```
azure.signinlogs.identity: "IT Support" AND event.outcome: "success"
```

---

### Conclusion

This walkthrough highlights the key steps and considerations for investigating security incidents in Azure using Elastic. By focusing on the provided questions and corresponding queries, you can build a comprehensive understanding of the incident, identify affected resources, and develop effective remediation strategies.

---

Feel free to adjust any part of the walkthrough to better suit your needs!
