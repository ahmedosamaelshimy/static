# AzureHunt Walkthrough: Investigating Suspicious Activity in Azure with ELK

This walkthrough provides a structured approach for SOC analysts to investigate suspicious activity in an Azure environment using Elastic (ELK) for log analysis. Covering three key logs—`Azure AD Logs`, `Activity Logs`, and `Blob Logs`.

---

### Log Overview and Their Role in Threat Detection

In Azure, logs are crucial to understanding activities, configuration changes, and data access, enabling effective monitoring, detection, and response. This walkthrough utilizes:

- **Azure AD Logs**: Focuses on identity-related events, tracking user access, authentication attempts, and role modifications.
- **Azure Activity Logs**: Captures management-level changes across resources, including configuration and access-related actions.
- **Blob Logs**: Monitors data access events, tracking file interactions within Blob Storage, especially for exfiltration detection.

Using ELK, SOC analysts can integrate these logs, conduct fast searches, and create visualizations to clarify attack scope and impact.

---
### ELK Integration for Enhanced Threat Detection

With Azure logs configured to forward to the ELK stack, SOC analysts can leverage ELK's capabilities to conduct rapid searches, apply filters, and generate meaningful visualizations. The ELK stack allows for quick analysis of extensive Azure log data, making it easier to:

- Identify patterns and anomalies across logs.
- Track attack progression from initial access to data access and configuration changes.
- Execute a timely and structured incident response based on comprehensive insights.

Each component of ELK plays a critical role:

- **Elasticsearch**: Enables high-speed search across log data.
- **Logstash**: Structures and enriches log data for accurate querying.
- **Kibana**: Facilitates visualization, making it easier to spot anomalies and identify incident trends.

---

### Step-by-Step Incident Analysis

#### 1. **Identify the Geographic Origin of Suspicious Activity**

Analyze the geographic origin of the activity, as access attempts from an unusual location could signal unauthorized access. Check the `source.geo.country_name` field in ELK to identify the country associated with the activity, establishing whether it warrants further investigation.

---

#### 2. **Establish a Timeline of Events**

Creating a timeline of events reveals the sequence and speed of actions, allowing analysts to track the flow of suspicious activities. Sorting logs by timestamp helps identify when the attacker gained initial access and subsequent actions.

**KQL Query**:
```KQL
source.geo.country_name: "<country_name>"
```
*Sort by Old-New*

---

#### 3. **Identify the Initial Compromised Account**

Identifying the first compromised account provides insights into the attacker’s entry point. Filter Azure AD Logs in ELK to isolate successful authentication events from unusual locations, helping to identify compromised accounts.

**KQL Query**:
```KQL
source.geo.country_name: "<country_name>" AND event.category: "authentication" AND event.outcome: "success"
```

---

#### 4. **Investigate Blob Storage Access**

To determine if the attacker accessed sensitive data, examine Blob Logs for `GetBlob` events, which indicate file access. This analysis helps identify potential data exfiltration or reconnaissance activities targeting sensitive files.

**KQL Query**:
```KQL
azure.eventhub.operationName: "GetBlob"
```

---

#### 5. **Identify the Compromised Storage Account**

Understanding which storage accounts were accessed or compromised is essential, especially if they contain sensitive data. Look for specific storage accounts in the Blob Logs using the `accountName` field.

*Check `azure.eventhub.properties.accountName` for the involved accounts.*

---

#### 6. **Identify Additional Compromised Accounts**

Attackers often spread access by compromising multiple accounts. Search for other successful authentication events from unusual locations within Azure AD Logs to ensure all impacted accounts are identified.

**KQL Query**:
```KQL
source.geo.country_name: "<country_name>" AND event.category: "authentication" AND event.outcome: "success"
```

---

#### 7. **Review Virtual Machine (VM) Activity**

Azure Activity Logs are useful for identifying malicious activity on virtual machines, such as starting VMs to deploy tools or establish persistence. Filter for VM start actions to check if any irregular actions were taken on virtual machines.

**KQL Query**:
```KQL
azure.activitylogs.identity.authorization.action: "Microsoft.Compute/virtualMachines/start/action"
```
*Check the `azure.resource.name` field for specific VMs involved.*

| Operation | Description |
| --- | --- |
| Microsoft.Compute/virtualMachines/start/action | Starts the virtual machine |
| Microsoft.Compute/virtualMachines/restart/action | Restarts the virtual machine |
| Microsoft.Compute/virtualMachines/write | Creates or updates a virtual machine |
| Microsoft.Compute/virtualMachines/deallocate/action | Powers off and deallocates the VM |
| Microsoft.Compute/virtualMachines/extensions/write | Creates or updates a VM extension |
| Microsoft.Compute/virtualMachineScaleSets/write | Starts instances in a VM scale set |

---

#### 8. **Check for Data Export Activity**

Data export activity often signals exfiltration attempts. Use Azure Activity Logs in ELK to detect any export operations, which could indicate attempts to move data outside the Azure environment.

**KQL Query**:
```KQL
azure.activitylogs.identity.authorization.action: *export*
```
*Check `azure.resource.name` for the database or resource involved.*

---

#### 9. **Detect Unauthorized Persistence Mechanisms**

Attackers may attempt to maintain access by creating new user accounts or roles. Investigate account creation events within Azure AD Logs to detect any unauthorized persistence mechanisms.

**KQL Query**:
```KQL
azure.auditlogs.operation_name: "Add User"
```

---

#### 10. **Review Role Assignments for Privilege Escalation**

Role assignments reveal if the attacker gained elevated privileges. Analyze Activity Logs for role-related actions to identify any unauthorized role assignments, particularly for high-level roles like "Owner."

**KQL Query**:
```KQL
azure.activitylogs.operation_name: "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"
```
*Check `azure.activitylogs.identity.authorization.evidence.role` for specific roles assigned.*

---

#### 11. **Verify Successful Login Timestamps**

Finally, review the timestamps of successful logins to create a complete incident timeline. This helps determine how long the attacker had access and the extent of their activity, forming a basis for a detailed incident report.

**KQL Query**:
```KQL
azure.signinlogs.identity: "<Compromised_User>" AND event.category: "authentication" AND event.outcome: "success"
```
*Sort by Old-New*

---


### Additional Resources

1. [Azure Monitoring and Management with Log Analytics](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/log-analytics-overview)
2. [Azure Security Logging and Auditing Recommendations](https://learn.microsoft.com/en-us/azure/security/fundamentals/logging-auditing)
3. [Elastic Security Solution for Azure](https://www.elastic.co/solutions/azure-security)
4. [Investigating Security Incidents with Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/tutorial-investigate)
5. [Azure AD Security Best Practices](https://learn.microsoft.com/en-us/azure/active-directory/fundamentals/security-best-practices)

