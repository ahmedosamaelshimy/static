### Investigating Security Incidents in Azure Using Azure Activity Logs and Elastic

---

#### Introduction to Azure Activity Logs and Elastic

Azure Activity Logs provide a rich record of events and actions across Azure resources, tracking all interactions that take place, including API calls, resource creation, and configuration changes. These logs answer critical questions, like who initiated an action, what resources were affected, and when changes occurred, making them an essential tool for both auditing and forensic analysis. For example, Azure Activity Logs will show when an administrator sets up a virtual machine, modifies a network security group, or grants new permissions, all of which are crucial actions that shape an environment’s security posture.

These logs provide crucial visibility across Azure operations, enabling organizations to:

- **Achieve Compliance**: Meet regulatory and industry standards by tracking user activities and changes.
- **Investigate Security Incidents**: Trace actions that may signal malicious activity or unauthorized access.
- **Resolve Operational Issues**: Pinpoint and resolve actions that might impact service performance or stability.

For security analysts, Azure Activity Logs offer a historical view of all major actions within the Azure environment, which is essential for identifying unauthorized access or unexpected changes. Elastic complements this by allowing analysts to efficiently sift through and analyze these logs, spotting trends, anomalies, and patterns indicative of potential threats.

---

### Investigating Unauthorized Access in Azure Environments

Unauthorized access is one of the top security threats in cloud environments. Attackers often gain access by compromising user accounts—leveraging weak passwords, conducting brute-force attacks, or using stolen credentials. Once inside, they may move laterally across the network, accessing sensitive resources and deploying persistence mechanisms to retain access. Here’s a systematic approach to use Azure Activity Logs in Elastic to identify, investigate, and assess the impact of unauthorized access.

#### Step 1: Identify the Source of Suspicious Activity

A critical first step is to identify where unusual or suspicious activity originated, which can help analysts understand the scope and origin of the potential threat. For instance, if a US-based company detects multiple login attempts from a country with no prior activity, this could signal a compromised account or an attempted brute-force attack.

To find the origin of suspicious activity in Elastic, filter logs by `source.geo.country_name`, isolating records by country. Suspicious locations often highlight anomalies, revealing possible bad actors or compromised accounts. Identifying this early allows analysts to focus on regions or IPs that represent higher risk and understand the attacker’s methods or intentions.

```KQL
source.geo.country_name: "Germany"
```

---

#### Step 2: Establish a Timeline of Events

After identifying the source, understanding the sequence of activities is essential to uncover how and when the breach began. By arranging logs by timestamp, analysts can create a timeline that reveals patterns of behavior, showing exactly when the attacker gained access and which actions were taken immediately after.

In Elastic, sort Azure Activity Logs chronologically to piece together the attacker’s movements, identifying the initial access point, any escalations in privileges, and their progression across resources. Analyzing the timeline of actions can reveal if attackers moved quickly, attempting data exfiltration, or if they laid low, focusing on maintaining long-term access without detection.

```KQL
source.geo.country_name: "Germany"
```
*Follow-Up*: Sort by timestamp to visualize the progression of events.

---

#### Step 3: Determine the Compromised User Account

Identifying compromised accounts is a crucial part of understanding the attacker’s impact. Azure Activity Logs provide detailed authentication records, which can help you pinpoint which user accounts were exploited. Reviewing successful authentication events tied to anomalous activity can lead directly to the accounts the attacker used to access the environment.

To identify these accounts in Elastic, focus on authentication events, filtering for `event.category` set to "authentication" and `event.outcome` to "success." By correlating these logs with the anomalous geographic location or unusual times of access, analysts can quickly narrow down compromised accounts, helping contain the incident by revoking access or forcing password resets.

```KQL
source.geo.country_name: "Germany" AND event.category: "authentication" AND event.outcome: "success"
```

---

#### Step 4: Investigate Access to Blob Storage

One common objective for attackers is accessing data stored in Azure Blob Storage. Here, they may attempt to download, modify, or exfiltrate data. Investigating specific actions on Blob Storage helps determine if sensitive data has been accessed or compromised.

Elastic allows filtering of Azure Activity Logs to track interactions with Blob Storage. Use the `operationName` field set to "GetBlob" to see access events specifically targeting Blob Storage resources. This helps analysts identify if unauthorized users accessed files, such as sensitive configurations or customer data, which would require urgent remediation.

```KQL
azure.eventhub.operationName: "GetBlob"
```

---

#### Step 5: Identify Associated Storage Accounts

Understanding where critical data is stored and which specific storage accounts were accessed provides insight into the scope of the breach. Identifying the name of the storage account in question allows analysts to isolate specific compromised resources, assess the sensitivity of the data involved, and prioritize incident response actions.

In Elastic, after identifying Blob access, further refine the search to include storage account names. Checking the `accountName` field within Azure Activity Logs will pinpoint exactly which accounts were involved, helping analysts focus remediation efforts on the most sensitive data stores.

*Follow-Up*: Check `azure.eventhub.properties.accountName`.

---

#### Step 6: Search for Additional Compromised Accounts

In some incidents, attackers target multiple accounts to escalate privileges or evade detection. Identifying all affected accounts gives a more comprehensive view of the breach’s impact and helps analysts take actions like locking or resetting passwords across affected users.

To uncover other compromised accounts in Elastic, continue filtering for successful authentication attempts, focusing on the same indicators used to identify the initial compromised account. This approach can quickly expand the investigation to include all users exhibiting similar signs of compromise, ensuring no account remains unexamined.

```KQL
source.geo.country_name: "Germany" AND event.category: "authentication" AND event.outcome: "success"
```

---

#### Step 7: Investigate Virtual Machine Activity

Attackers may start or stop virtual machines (VMs) within the environment to establish persistence, launch attacks, or deploy additional tools. Monitoring VM activity is essential to understand whether attackers are leveraging infrastructure resources for their activities or as a way to expand access.

By analyzing the Azure Activity Logs in Elastic, focus on actions indicating that VMs were started or modified. Filter for authorization actions with `action` fields including “start” or similar keywords, and then review the resource names associated with these events to understand if specific VMs were targeted for malicious purposes.

```KQL
azure.activitylogs.identity.authorization.action: *start*
```
*Follow-Up*: Check the `azure.resource.name` field.

---

#### Step 8: Check for Data Exports

Exported databases are a serious security concern, as they often contain valuable organizational data. If attackers managed to export a database, it could indicate a significant data breach with potential legal, regulatory, and operational implications.

To identify exported data in Elastic, search Azure Activity Logs for actions labeled with “export.” This helps trace specific database exports, allowing analysts to assess the type of data at risk and consider immediate containment measures.

```KQL
azure.activitylogs.identity.authorization.action: *export*
```

---

#### Step 9: Detect Unauthorized Persistence Mechanisms

Attackers frequently create new accounts or alter roles to ensure they retain access even if the original entry point is closed. Detecting these persistence techniques is essential for fully remediating a breach.

Search Azure Activity Logs in Elastic for any events related to user creation or role modification, filtering by the operation type "Add." This identifies if any unauthorized accounts were created or if an attacker elevated privileges to secure persistent access.

```KQL
azure.auditlogs.properties.operation_type: "Add"
```

---

#### Step 10: Review Role Assignments

An attacker’s impact is often amplified by the roles or privileges assigned to their accounts. Identifying unauthorized role assignments provides insight into what access the attacker obtained and what additional resources they might control.

To review role assignments in Elastic, filter by `action` fields indicating role-related activities. This can highlight if critical roles like "Owner" were assigned to unauthorized accounts, signifying increased risk and priority for immediate remediation.

```KQL
azure.activitylogs.identity.authorization.action: *role*
```

---

#### Step 11: Track Successful Login Activity

Recording the exact times when a compromised account successfully logged in is critical for tracking the incident's progression. Knowing when attackers first accessed the environment and how often they returned helps analysts establish the length and scope of the compromise.

In Elastic, filter for successful login events using the display name of the suspicious account, enabling you to map out each instance of unauthorized access in detail. This step aids in building a complete timeline, essential for both response and reporting.

```KQL
azure.signinlogs.identity: "IT Support" AND event.outcome: "success"
```

---

### Conclusion

Using Azure Activity Logs and Elastic together creates a powerful combination for investigating security incidents within Azure environments. By focusing on key logs, filtering effectively, and identifying indicators of unauthorized access or persistence mechanisms, analysts can trace incident details, assess affected resources, and develop a thorough incident response plan. This systematic approach empowers organizations to detect, analyze, and remediate cloud-based security threats swiftly, helping maintain secure and resilient cloud operations.
