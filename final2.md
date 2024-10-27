# AzureHunt Walkthrough

### Investigating Suspicious Activity and Potential Compromise in Azure with ELK

In Azure environments, understanding user activities, configuration changes, and data access patterns is key to detecting and responding to security threats. When unexpected activity arises, especially from unusual locations, logs are invaluable in tracing behavior and identifying potential breaches. This walkthrough demonstrates a practical approach to investigating suspicious activity using three primary logs—`Azure AD Logs`, `Activity Logs`, and `Blob Logs`—integrated with ELK (Elasticsearch, Logstash, and Kibana). Together, these tools help SOC analysts gain full visibility, assess the threat scope, and implement containment measures.

---

### Overview of Azure Logs for Security Monitoring

- **Azure AD Logs** capture authentication events, user sign-ins, and changes to roles and permissions, allowing analysts to detect unauthorized access and monitor login patterns.
- **Activity Logs** track changes to Azure resources and administrative actions, offering a detailed view of modifications and access across the infrastructure.
- **Blob Logs** record access events in Azure Blob Storage, helping detect unauthorized file access and potential data exfiltration attempts.

When forwarded to ELK, these logs become searchable, filterable, and visualizable, making it easier to investigate incidents, analyze trends, and take action.

---

### Step-by-Step Investigation

#### 1. Identify the Country of Origin for Suspicious Activity

Since the organization operates primarily in the U.S., any logins or access attempts from unexpected locations may indicate unauthorized activity. Use the `source.geo.country_name` field to identify the country associated with the suspicious activity, determining whether it warrants deeper investigation.

**KQL Query:**
```KQL
source.geo.country_name: *
```
*Review results and verify the location against other fields.*

---

#### 2. Establish a Timeline of Events

Next, create a timeline of the incident. Sorting logs by timestamp reveals the sequence of events, allowing analysts to understand how quickly the attacker moved and which actions were prioritized. This timeline provides essential context for the overall attack flow.

**KQL Query:**
```KQL
source.geo.country_name: "<attacker's_country>"
```
*Sort by oldest timestamp to capture the first event.*

---

#### 3. Identify the Initial Compromised Account

Use Azure AD Logs to focus on authentication events, identifying which user account was first compromised. Filter by `event.category` as "authentication" and `event.outcome` as "success" to isolate the account and trace initial access.

**KQL Query:**
```KQL
source.geo.country_name: "<attacker's_country>" AND event.category: "authentication" AND event.outcome: "success"
```

---

#### 4. Investigate Blob Storage Access

Blob Logs in ELK help determine if sensitive files within Blob Storage were accessed. Filter by `operationName` set to "GetBlob" to see if data exfiltration or recon activities occurred. This step highlights which files were accessed and allows assessment of the potential impact.

**KQL Query:**
```KQL
azure.eventhub.operationName: "GetBlob"
```

---

#### 5. Identify the Compromised Storage Account

Examine the `accountName` field in the Blob Logs to identify the specific storage account involved. Knowing the storage account helps prioritize follow-up actions, especially if sensitive or regulated data is involved.

*Check `azure.eventhub.properties.accountName`.*

---

#### 6. Identify Additional Compromised Accounts

Attackers often target multiple accounts. Review AD Logs for similar successful authentication events originating from the suspicious location, ensuring that all compromised accounts are addressed in your response.

**KQL Query:**
```KQL
source.geo.country_name: "<attacker's_country>" AND event.category: "authentication" AND event.outcome: "success"
```

---

#### 7. Review Virtual Machine (VM) Activity

Activity Logs reveal actions taken across resources like VMs. Attackers may start or modify VMs to deploy malicious tools or establish persistence. Filter for VM start actions to check for irregular activity, and use the resource name to identify specific VMs.

**KQL Query:**
```KQL
azure.activitylogs.identity.authorization.action: "Microsoft.Compute/virtualMachines/start/action"
```

| Operation | Description |
| --- | --- |
| Microsoft.Compute/virtualMachines/start/action | Starts the virtual machine |
| Microsoft.Compute/virtualMachines/restart/action | Restarts the virtual machine |
| Microsoft.Compute/virtualMachines/write | Creates or updates a virtual machine |
| Microsoft.Compute/virtualMachines/deallocate/action | Powers off the VM, releasing compute resources |
| Microsoft.Compute/virtualMachines/extensions/write | Creates or updates VM extensions |
| Microsoft.Compute/virtualMachineScaleSets/write | Starts instances in a scale set |

---

#### 8. Check for Data Export Activity

Data export actions often signal attempts to exfiltrate sensitive data. Use Activity Logs to search for "export" actions, which reveal if the attacker extracted critical data. This insight helps assess impact and prioritize containment actions.

**KQL Query:**
```KQL
azure.activitylogs.identity.authorization.action: *export*
```
*Check `azure.resource.name` for details on the specific database involved.*

---

#### 9. Detect Unauthorized Persistence Mechanisms

Attackers commonly create persistence by adding user accounts or modifying roles. Search AD Logs for "Add" operations to identify new accounts or roles created to maintain unauthorized access.

**KQL Query:**
```KQL
azure.auditlogs.operation_name: "Add User"
```

---

#### 10. Review Role Assignments for Escalated Privileges

Role assignments are crucial to understanding the attacker’s level of access. Check Activity Logs for role-related actions, particularly "Owner" assignments, which increase the impact of the breach. Review the `authorization.evidence.role` field for specific role actions.

**KQL Query:**
```KQL
azure.activitylogs.operation_name: "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"
```

---

#### 11. Verify Successful Login Timestamps

Finally, review successful login timestamps to complete the incident timeline, showing when the attacker accessed the environment and how long they remained active. This timeline provides insight into the attack duration and the extent of compromise.

**KQL Query:**
```KQL
azure.signinlogs.identity: "<Created_User>" AND event.outcome: "success"
```

---

### Summary

This AzureHunt walkthrough demonstrates a step-by-step investigation process for suspicious activity in Azure using Azure AD Logs, Activity Logs, and Blob Logs within ELK. By following these steps, SOC analysts gain visibility into each stage of an attack—from initial access and data exfiltration to persistence tactics—enabling them to take swift, informed actions to secure the environment. Integrating these logs into ELK allows analysts to visualize, search, and filter extensive data sources, facilitating a comprehensive and efficient incident response.

---

### References

- Microsoft, "Azure Active Directory Reporting," https://learn.microsoft.com/en-us/azure/active-directory/reports-monitoring/
- Microsoft, "Azure Activity Logs," https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log
- Microsoft, "Azure Storage Monitoring and Logging," https://learn.microsoft.com/en-us/azure/storage/blobs/monitor-blob-storage
- Elastic, "Azure Module for Filebeat," https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-module-azure.html
- Microsoft, "Monitoring and Troubleshooting for VMs," https://learn.microsoft.com/en-us/azure/virtual-machines/monitor-vm
