# Threat Hunt — Suspicious Authentication Followed by Activity

## Hypothesis
A successful authentication following unusual failures may represent a compromised credential and may be followed by suspicious endpoint or network activity.

## Data required
- authentication success/failure events
- source and destination host
- account
- timestamp
- privileged status where available
- endpoint/network activity after authentication

## Hunt approach
1. Identify unusual authentication sequences.
2. Find successful authentication following repeated failures.
3. Scope the account and host.
4. Review post-authentication process and network events.
5. Compare the activity with known maintenance or user context.

## Analyst questions
- Was the account expected to authenticate from this source?
- Did the account access a new host?
- Did a privileged action follow?
- Did endpoint or network behaviour change after the login?

## Conclusion standard
Treat the sequence as a lead. Require independent evidence before describing the account as compromised.
