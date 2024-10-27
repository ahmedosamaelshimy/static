# AzureHunt Walkthrough

### Investigating Suspicious Activity and Potential Compromise in Azure with Elastic




---
---
### Investigating Anomalous Activity in Azure Using AD Logs, Activity Logs, Blob Logs, and ELK

In an Azure environment, logs are the key to understanding user activities, configuration changes, and data access patterns—essential for maintaining security and responding to potential threats. When unexpected activity is detected, three primary logs—Azure AD Logs, Activity Logs, and Blob Logs—provide critical data points for identifying threats and tracing suspicious behavior. By integrating these logs with an ELK (Elasticsearch, Logstash, and Kibana) stack, Security Operations Center (SOC) analysts can monitor, search, and analyze these data sources efficiently, uncovering the full scope of suspicious activity and taking action to secure the environment. 

This walkthrough demonstrates a practical approach to investigating a surge of suspicious activity originating from an unusual country. With your Azure environment configured to forward AD Logs, Activity Logs, and Blob Logs to ELK, you can use these logs to assess the situation from initial entry to persistent tactics, ultimately containing and remediating the threat.

---

### Step 1: Identify the Country of Origin for Suspicious Activity

To begin, analyze the geographic source of the anomalous activity. Since your organization operates primarily in the U.S., any unexpected logins or resource access attempts from another country could signal unauthorized access. By examining the `source.geo.country_name` field in ELK, you can pinpoint the specific country associated with the activity and determine if it’s abnormal. This step establishes whether the activity warrants a deeper investigation.

**KQL Query:**
```KQL
source.geo.country_name: "Germany"
```

---

### Step 2: Establish a Timeline of Events

Once the country of origin is identified, the next step is to create an incident timeline. Sorting the logs by timestamp reveals the exact sequence of actions, from initial access onward. A timeline is critical to understanding how quickly the attacker moved within the environment and what actions were prioritized. This view forms the foundation for your investigation, allowing you to see the entire attack flow in context.

**KQL Query:**
```KQL
source.geo.country_name: "Germany"
```
*Sort by oldest timestamp to capture the first event.*

---

### Step 3: Identify the Initial Compromised Account

The timeline helps pinpoint when and how the attacker entered. Using Azure AD Logs in ELK, focus on authentication events to identify which user account was compromised. By filtering for `event.category` as "authentication" and `event.outcome` as "success," you can isolate the compromised account and trace its access patterns, providing a clear picture of the attacker’s entry point.

**KQL Query:**
```KQL
source.geo.country_name: "Germany" AND event.category: "authentication" AND event.outcome: "success"
```

---

### Step 4: Investigate Blob Storage Access

Blob Logs in ELK are crucial for determining if the attacker accessed sensitive files within Blob Storage. Filter by `operationName` set to "GetBlob" to see if any files were accessed, which may indicate data exfiltration attempts or recon activity. This step highlights which files, if any, were accessed and allows you to assess the potential impact.

**KQL Query:**
```KQL
azure.eventhub.operationName: "GetBlob"
```

---

### Step 5: Identify the Compromised Storage Account

After identifying any accessed files, look at the specific storage account involved by checking the `accountName` field in the Blob Logs. Knowing which storage account was compromised is essential for assessing data exposure, particularly if it involves sensitive or regulated data. This helps prioritize follow-up actions based on the data’s sensitivity.

*Check `azure.eventhub.properties.accountName`.*

---

### Step 6: Identify Additional Compromised Accounts

Attackers often compromise multiple accounts to spread their access across the environment. Check for similar successful authentication events within AD Logs to see if other accounts were accessed from the unusual country. Identifying additional compromised accounts ensures that all affected users are addressed in your response plan.

**KQL Query:**
```KQL
source.geo.country_name: "Germany" AND event.category: "authentication" AND event.outcome: "success"
```

---

### Step 7: Review Virtual Machine (VM) Activity

Azure Activity Logs provide insight into actions taken across Azure resources, such as VMs. Attackers may start or modify VMs to deploy malicious tools, establish persistence, or expand access. Filter for actions involving VM starts to check for any irregular activity within the environment. Understanding VM actions can reveal infrastructure used by the attacker for their activity.

**KQL Query:**
```KQL
azure.activitylogs.identity.authorization.action: *start*
```
*Check the `azure.resource.name` field to identify specific VMs involved.*

---

### Step 8: Check for Data Export Activity

Data export actions are significant, as they often indicate attempts to exfiltrate sensitive data. Use Activity Logs in ELK to look for any actions labeled "export." By identifying these actions, you gain visibility into what data the attacker might have targeted for extraction, enabling you to assess the potential impact and prioritize containment actions.

**KQL Query:**
```KQL
azure.activitylogs.identity.authorization.action: *export*
```
*Check `azure.resource.name` for the specific database involved.*

---

### Step 9: Detect Unauthorized Persistence Mechanisms

Attackers commonly attempt to create persistence by adding new user accounts or modifying roles. Searching AD Logs for account creation events reveals unauthorized persistence tactics. Look for any "Add" operations to uncover any new accounts or roles that may have been created to maintain access covertly.

**KQL Query:**
```KQL
azure.auditlogs.properties.operation_type: "Add"
```

---

### Step 10: Review Role Assignments for Escalated Privileges

Role assignments are critical for understanding the access level the attacker gained. Check Activity Logs for role-related actions and review the `authorization.evidence.role` field. High-level roles like "Owner" can significantly increase the impact of the attack, and detecting these escalations helps inform containment and remediation measures.

**KQL Query:**
```KQL
azure.activitylogs.identity.authorization.action:*role*
```

---

### Step 11: Verify Successful Login Timestamps

Finally, reviewing timestamps of successful logins provides a complete incident timeline, showing exactly when the attacker accessed the environment and how long they were active. This timeline, created by analyzing successful login events in AD Logs, gives a complete view of the breach progression and helps determine the duration and depth of the compromise.

**KQL Query:**
```KQL
azure.signinlogs.identity: "IT Support" AND event.outcome: "success"
```

---

This comprehensive walkthrough demonstrates how Azure AD Logs, Activity Logs, and Blob Logs in ELK can uncover the full scope of suspicious activity within Azure. By following each step, SOC analysts gain visibility into each phase of the attack, from initial access to persistence tactics, and can take swift, effective action to secure the environment. This approach not only clarifies complex incidents but also provides the insights needed for a well-rounded incident response.

