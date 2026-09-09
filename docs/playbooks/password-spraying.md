# Password Spraying — Entry-Level Response Playbook

## Purpose
Provide a repeatable analyst workflow for a password-spraying detection lead. This is a training playbook, not an automated containment procedure.

## Trigger
`AUTH-REPEAT-001` or another authentication analytic identifies repeated failures from one source across multiple accounts.

## 1. Validate the alert
- Confirm the source IP and time window.
- Confirm the targeted accounts are distinct.
- Check whether timestamps are trustworthy and timezone-aware.
- Determine whether the source is expected administrative infrastructure, a scanner, VPN, proxy, or other authorised service.

## 2. Scope the activity
Collect:
- source IP / hostname
- targeted accounts
- failure count
- successful authentications from the same source
- affected hosts
- first and last observed timestamps
- relevant authentication method

## 3. Investigate
Ask:
- Did any authentication succeed after the failures?
- Is a privileged account involved?
- Did the account authenticate to a new or unusual host?
- Is there endpoint or network activity following a successful login?
- Does the source belong to an approved service?

## 4. Assessment
Use evidence-based language:
- **Benign / expected:** authorised activity is supported by evidence.
- **Requires Investigation:** suspicious pattern exists but context is incomplete.
- **Likely malicious:** multiple independent observations support an attack hypothesis.

Do not treat the alert itself as proof of compromise.

## 5. Containment recommendation
If compromise is supported and authorised response procedures permit it:
- protect affected accounts
- revoke active sessions where appropriate
- reset credentials through the approved process
- block or restrict malicious infrastructure where authorised
- preserve relevant evidence

## 6. Recovery and closure
- Confirm the suspicious activity has stopped.
- Validate affected accounts and hosts.
- Record evidence and decisions.
- Document unresolved evidence gaps.
- Tune the detection only after reviewing the false-positive context.

## Analyst hand-off
Escalate when there is evidence of successful compromise, privileged-account involvement, lateral movement, or material business impact.

> Synthetic-training playbook. It does not execute live credential attacks or automated containment.
