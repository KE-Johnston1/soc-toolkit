# Phishing — Entry-Level Response Playbook

## Purpose
Provide a repeatable workflow for a suspected phishing or impersonation report.

## Trigger
User report, mail-security alert, suspicious sender/header evidence, malicious link/attachment indicator, or identity activity following a suspicious message.

## 1. Preserve evidence
Record:
- message identifiers
- sender and recipient details
- relevant headers
- subject and timestamp
- URLs / attachment names
- user-reported actions

Avoid opening suspicious content outside the approved analysis environment.

## 2. Validate
Check:
- sender identity and authentication results
- display-name vs actual sender
- URL/domain context
- whether the user clicked or opened content
- whether credentials were entered
- whether suspicious authentication followed

## 3. Scope
Identify:
- other recipients
- related messages
- affected accounts
- affected endpoints
- suspicious sign-ins or mailbox activity

## 4. Assessment
Do not label a message malicious from appearance alone. Record the evidence supporting the assessment and any unresolved questions.

## 5. Response recommendation
If compromise is supported and authorised procedures permit it:
- remove or quarantine the message
- protect affected accounts
- revoke sessions where appropriate
- reset credentials if required
- investigate endpoint activity
- preserve relevant evidence

## 6. Lessons learned
Record the indicator that triggered the investigation and whether a reusable detection or awareness improvement is warranted.

> Synthetic-training playbook. It does not send, receive, execute, or automatically remove real phishing content.
