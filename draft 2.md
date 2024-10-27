### Walkthrough: Investigating Suspicious Activity and Potential Compromise in Azure with Elastic

In this walkthrough, we’ll explore how to investigate suspicious activity and potential account compromise within an Azure environment using Elastic. The process covers initial detection, establishing timelines, identifying compromised resources, and assessing potential persistence. Each step leverages Azure Activity Logs filtered in Elastic to pinpoint key events and understand attacker tactics.

---

**Step 1: Identify Unusual Geographic Activity**

The first step is to check for activity originating from unexpected locations. For example, if your organization operates primarily in the U.S., activity from an unusual country might raise a red flag. To investigate, filter the logs by the `source.geo.country_name` field to see if there are any unexpected locations associated with login or access attempts. Identifying this geographic anomaly is a foundational clue that helps determine the origin of the potential breach.

**KQL Query:**
```KQL
source.geo.country_name: "Germany"
```

---

**Step 2: Establish an Incident Timeline**

After identifying a suspicious source, it’s critical to create a timeline. Sorting the logs chronologically shows the exact timestamp of the first recorded activity, helping you understand the sequence of events. This timeline is essential for tracking the attacker’s movements from the point of entry onward, giving you insight into how quickly they progressed.

**KQL Query:**
```KQL
source.geo.country_name: "Germany"
```
*Sort by oldest timestamp.*

---

**Step 3: Determine the Compromised User Account**

Next, identify which user account was initially compromised. To do this, filter for successful authentication events associated with the unusual location. In Elastic, you can focus on the `event.category` field set to "authentication" and `event.outcome` set to "success." This step is key in identifying the entry point the attacker used to access your environment.

**KQL Query:**
```KQL
source.geo.country_name: "Germany" AND event.category: "authentication" AND event.outcome: "success"
```

---

**Step 4: Investigate Blob Storage Access**

Attackers often seek out sensitive data, so it’s essential to check whether they accessed any storage accounts. Specifically, look for `operationName` set to "GetBlob" to see if the attacker interacted with blob storage files. This can reveal which data they accessed and potentially compromised.

**KQL Query:**
```KQL
azure.eventhub.operationName: "GetBlob"
```

---

**Step 5: Identify the Storage Account Involved**

To further narrow down the impact, look into the storage account name associated with the accessed data. Using the `accountName` field, you can identify which specific storage account held the data the attacker accessed. This allows you to determine the sensitivity of the information and prioritize your containment response.

*Check `azure.eventhub.properties.accountName`.*

---

**Step 6: Check for Additional Compromised Accounts**

It’s common for attackers to target multiple accounts to widen their access. By filtering for similar successful authentication events, you can identify any other accounts that might have been compromised in the same timeframe. This step helps ensure that all affected accounts are accounted for in the investigation.

**KQL Query:**
```KQL
source.geo.country_name: "Germany" AND event.category: "authentication" AND event.outcome: "success"
```

---

**Step 7: Investigate Virtual Machine Activity**

Attackers may attempt to start or modify Virtual Machines (VMs) to gain further access or use your infrastructure for additional attacks. Filter for actions involving VM starts to trace any infrastructure changes that may indicate unauthorized use of resources.

**KQL Query:**
```KQL
azure.activitylogs.identity.authorization.action: *start*
```
*Check the `azure.resource.name` field for specific VMs.*

---

**Step 8: Look for Data Export Activity**

To assess potential data exfiltration, check if any databases were exported. Filter for actions labeled “export” and review the database names involved. This helps you gauge if sensitive data was accessed and may require immediate containment efforts.

**KQL Query:**
```KQL
azure.activitylogs.identity.authorization.action: *export*
```
*Check `azure.resource.name`.*

---

**Step 9: Detect Persistence Mechanisms**

To establish persistence, attackers might create new user accounts or modify roles. Search for user creation events or changes in group memberships, which can indicate unauthorized privileges. This step is vital to ensure the attacker doesn’t maintain hidden access within the environment.

**KQL Query:**
```KQL
azure.auditlogs.properties.operation_type: "Add"
```

---

**Step 10: Review Role Assignments**

Look for any high-level roles, such as “Owner,” added to unauthorized accounts. Reviewing the `authorization.evidence.role` field helps you understand the privileges granted, which directly impacts your response and containment actions.

**KQL Query:**
```KQL
azure.activitylogs.identity.authorization.action:*role*
```

---

**Step 11: Track Successful Login Timestamps**

Finally, track the first successful login timestamp for any newly discovered accounts associated with suspicious activity. By identifying each login event, you can create a complete timeline, which is crucial for understanding the duration and extent of the breach.

**KQL Query:**
```KQL
azure.signinlogs.identity: "IT Support" AND event.outcome: "success"
```

---

This walkthrough provides a structured approach to using Azure Activity Logs in Elastic for investigating suspicious activity. Each step, from identifying geographic anomalies to tracking login events, builds a comprehensive picture of the incident, allowing you to respond effectively and reduce the risk of future incidents.
