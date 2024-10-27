# AzureHunt Walkthrough

### Investigating Suspicious Activity and Potential Compromise in Azure with Elastic
In an Azure environment, logs are the key to understanding user activities, configuration changes, and data access patterns—essential for maintaining security and responding to potential threats. When unexpected activity is detected, three primary logs—`Azure AD` Logs, `Activity Logs`, and `Blob Logs`—provide critical data points for identifying threats and tracing suspicious behavior.

This walkthrough demonstrates a practical approach to investigating a surge of suspicious activity originating from an unusual country. With your Azure environment configured to forward AD Logs, Activity Logs, and Blob Logs to ELK, you can use these logs to assess the situation from initial entry to persistent tactics, ultimately containing and remediating the threat.

#### Azure AD Logs

Azure Active Directory (AD) Logs capture authentication events, user sign-ins, conditional access results, and role-based access control (RBAC) changes. These logs are foundational for identifying who accessed Azure resources and how, providing insight into both successful and failed authentication attempts. For example:

- **Sign-In Logs**: Track each user login attempt, including location, device, and IP address.
- **Audit Logs**: Document changes to user roles, group memberships, and security policies.

Azure AD Logs allow SOC analysts to detect unauthorized access attempts, monitor suspicious login patterns, and spot privilege escalation activities, making them an essential component in tracking identity-based threats.

---

#### Azure Activity Logs

Azure Activity Logs provide a record of actions taken across Azure resources, from virtual machine deployments to network security changes. This log type covers operations performed at the management plane level, capturing data on actions initiated by users, systems, and applications. Activity Logs are particularly valuable for:

- **Change Tracking**: Monitoring modifications to resources and configurations.
- **Access Monitoring**: Logging administrative actions, such as starting or stopping services, enabling SOC teams to detect irregular behavior or potentially malicious changes.

By analyzing Activity Logs, analysts can determine what changes were made, by whom, and when, which is crucial for assessing the impact of configuration changes and identifying unauthorized modifications.

---

#### Blob Logs

Blob Storage in Azure is often used for storing data files, application logs, and other important information. Blob Logs track interactions with Blob Storage, recording events like file access, download, and upload activities. These logs are useful for:

- **Data Access Monitoring**: Tracking when files are accessed or modified, especially useful for detecting unauthorized downloads of sensitive files.
- **Exfiltration Detection**: Identifying abnormal file access patterns, which may indicate potential data theft.

Blob Logs are especially important in understanding if an attacker has accessed sensitive information within Azure Blob Storage, enabling analysts to determine if sensitive data has been exposed.

---

#### The Role of ELK in Azure Log Analysis

ELK (Elasticsearch, Logstash, and Kibana) is a powerful open-source stack for ingesting, storing, and visualizing large volumes of log data. When integrated with Azure AD, Activity, and Blob Logs, ELK enables SOC analysts to perform rapid searches, apply filters, and generate visualizations that clarify complex security incidents. Here’s how each component contributes:

- **Elasticsearch**: Stores and indexes Azure logs, allowing fast, scalable searches.
- **Logstash**: Ingests data from Azure logs, parsing and structuring it for easy querying.
- **Kibana**: Visualizes log data, displaying patterns and trends, which helps analysts spot anomalies and understand the bigger picture.

Using ELK, SOC analysts can sift through extensive Azure log data, trace security incidents from initial access to data access, and assess configuration changes. This setup provides the visibility necessary to uncover threats, analyze attack scope, and take action to secure the environment.



---





### 1. Identify the Country of Origin for Suspicious Activity
To begin, analyze the geographic source of the anomalous activity. Since your organization operates primarily in the U.S., any unexpected logins or resource access attempts from another country could signal unauthorized access. By examining the `source.geo.country_name` field in ELK, you can pinpoint the specific country associated with the activity and determine if it’s abnormal. This step establishes whether the activity warrants a deeper investigation.

**KQL Query:**
```KQL
source.geo.country_name: *
```

and check other sources `source.geo.country_name`.

---

### 2. Establish a Timeline of Events

Once the country of origin is identified, the next step is to create an incident timeline. Sorting the logs by timestamp reveals the exact sequence of actions, from initial access onward. A timeline is critical to understanding how quickly the attacker moved within the environment and what actions were prioritized. This view forms the foundation for your investigation, allowing you to see the entire attack flow in context.

**KQL Query:**
```KQL
source.geo.country_name: "<attacker's_company>"
```
*Sort by oldest timestamp to capture the first event.*

---

### 3. Identify the Initial Compromised Account

The timeline helps pinpoint when and how the attacker entered. Using Azure AD Logs in ELK, focus on authentication events to identify which user account was compromised. By filtering for `event.category` as "authentication" and `event.outcome` as "success," you can isolate the compromised account and trace its access patterns, providing a clear picture of the attacker’s entry point.

**KQL Query:**
```KQL
source.geo.country_name: "<attacker's_company>" AND event.category: "authentication" AND event.outcome: "success"
```

---

### 4. Investigate Blob Storage Access

Blob Logs in ELK are crucial for determining if the attacker accessed sensitive files within Blob Storage. Filter by `operationName` set to "GetBlob" to see if any files were accessed, which may indicate data exfiltration attempts or recon activity. This step highlights which files, if any, were accessed and allows you to assess the potential impact.

**KQL Query:**
```KQL
azure.eventhub.operationName: "GetBlob"
```

---


### 5. Identify the Compromised Storage Account

After identifying any accessed files, look at the specific storage account involved by checking the `accountName` field in the Blob Logs. Knowing which storage account was compromised is essential for assessing data exposure, particularly if it involves sensitive or regulated data. This helps prioritize follow-up actions based on the data’s sensitivity.

*Check `azure.eventhub.properties.accountName`.*

---
### 6. Identify Additional Compromised Accounts

Attackers often compromise multiple accounts to spread their access across the environment. Check for similar successful authentication events within AD Logs to see if other accounts were accessed from the unusual country. Identifying additional compromised accounts ensures that all affected users are addressed in your response plan.

**KQL Query:**
```KQL
source.geo.country_name: "<attacker's_company>" AND event.category: "authentication" AND event.outcome: "success"
```

---
### 7. Review Virtual Machine (VM) Activity

Azure Activity Logs provide insight into actions taken across Azure resources, such as VMs. Attackers may start or modify VMs to deploy malicious tools, establish persistence, or expand access. Filter for actions involving VM starts to check for any irregular activity within the environment. Understanding VM actions can reveal infrastructure used by the attacker for their activity.

**KQL Query:**
```KQL
azure.activitylogs.identity.authorization.action: "Microsoft.Compute/virtualMachines/start/action"
```
*Check the `azure.resource.name` field to identify specific VMs involved.*


| Operation | Description |
| --- | --- |
| Microsoft.Compute/virtualMachines/start/action | Starts the virtual machine |
| Microsoft.Compute/virtualMachines/restart/action | Deletes a managed cluster |
| Microsoft.Compute/virtualMachines/write | Creates a new virtual machine or updates an existing one |
| Microsoft.Compute/virtualMachines/deallocate/action | Powers off the virtual machine and releases the compute resources |
| Microsoft.Compute/virtualMachines/extensions/write | Creates a new virtual machine extension or updates an existing one |
| Microsoft.Compute/virtualMachineScaleSets/write | Starts the instances of the virtual machine scale set |

---

### 8. Check for Data Export Activity

Data export actions are significant, as they often indicate attempts to exfiltrate sensitive data. Use Activity Logs in ELK to look for any actions labeled "export." By identifying these actions, you gain visibility into what data the attacker might have targeted for extraction, enabling you to assess the potential impact and prioritize containment actions.

**KQL Query:**
```KQL
azure.activitylogs.identity.authorization.action: *export*
```
*Check `azure.resource.name` for the specific database involved.*

---

### 9. Detect Unauthorized Persistence Mechanisms

Attackers commonly attempt to create persistence by adding new user accounts or modifying roles. Searching AD Logs for account creation events reveals unauthorized persistence tactics. Look for any "Add" operations to uncover any new accounts or roles that may have been created to maintain access covertly.

**KQL Query:**
```KQL
azure.auditlogs.operation_name: "Add User"
```

---

### 10. Review Role Assignments for Escalated Privileges

Role assignments are critical for understanding the access level the attacker gained. Check Activity Logs for role-related actions and review the `authorization.evidence.role` field. High-level roles like "Owner" can significantly increase the impact of the attack, and detecting these escalations helps inform containment and remediation measures.

**KQL Query:**
```KQL
azure.activitylogs.operation_name: "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"
```
*Check `azure.activitylogs.identity.authorization.evidence.role` for the specific role-related actions.*


---
---


### Step 11: Verify Successful Login Timestamps

Finally, reviewing timestamps of successful logins provides a complete incident timeline, showing exactly when the attacker accessed the environment and how long they were active. This timeline, created by analyzing successful login events in AD Logs, gives a complete view of the breach progression and helps determine the duration and depth of the compromise.

**KQL Query:**
```KQL
azure.signinlogs.identity: "<Created_User>" AND event.outcome: "success"
```



---


This comprehensive walkthrough demonstrates how Azure AD Logs, Activity Logs, and Blob Logs in ELK can uncover the full scope of suspicious activity within Azure. By following each step, SOC analysts gain visibility into each phase of the attack, from initial access to persistence tactics, and can take swift, effective action to secure the environment. This approach not only clarifies complex incidents but also provides the insights needed for a well-rounded incident response.




references:
- https://learn.microsoft.com/en-us/azure/virtual-machines/monitor-vm-reference?toc=%2Fazure%2Fvirtual-machines%2Ftoc.json
- https://www.elastic.co/guide/en/beats/filebeat/current/exported-fields-azure.html
- 
