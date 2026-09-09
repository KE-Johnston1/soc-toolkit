# Compromised Account — Entry-Level Response Playbook

## Purpose
Provide a cautious workflow for investigating a suspected compromised user account.

## Trigger
A successful authentication or identity alert is correlated with suspicious source, device, timing, privilege, or post-authentication activity.

## 1. Validate identity activity
- Confirm the account and authentication event.
- Check source IP, device, location/context, and authentication method.
- Review recent successful and failed authentications.
- Identify whether MFA was used and whether any recovery or registration changes occurred.

## 2. Scope
Review:
- affected account(s)
- affected hosts/applications
- privileged access
- unusual session activity
- suspicious process or network activity after authentication

## 3. Form hypotheses
1. Legitimate user activity.
2. User error or unusual but authorised activity.
3. Credential compromise.
4. Session/token compromise.

Use independent evidence to distinguish them.

## 4. Response recommendation
If compromise is supported and the response is authorised:
- protect the account
- revoke sessions/tokens as appropriate
- reset credentials
- review MFA and recovery settings
- investigate affected endpoints
- preserve evidence before destructive actions where practical

## 5. Recovery
- Confirm the account is secured.
- Validate that suspicious access has stopped.
- Monitor for recurrence.
- Document affected systems and evidence gaps.

## Closure criteria
Close only when the assessment is supported by the available evidence, required evidence gaps are resolved or explicitly accepted, and the rationale is recorded.

> Synthetic-training playbook. This document does not perform account changes or live containment.
