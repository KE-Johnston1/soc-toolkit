# Threat Hunt — Password Spraying

## Hypothesis
An external or unauthorised source may be attempting the same credential pattern against multiple user accounts.

## Data required
- Authentication failures
- Source IP
- Account/user
- Timestamp
- Successful authentications
- Source ownership/context

## Hunt approach
1. Group authentication failures by source IP over a short window.
2. Count distinct target accounts.
3. Review sources with repeated failures against multiple accounts.
4. Correlate with successful authentication from the same source.
5. Check whether the source belongs to approved infrastructure.

## KQL/SPL starting point
Reuse `detections/queries/microsoft-sentinel/ssh-password-spray.kql` and `detections/queries/splunk/ssh-password-spray.spl` as reference implementations.

## Expected benign explanations
- vulnerability scanners
- authorised administration
- shared gateways or proxies
- test environments

## Conclusion standard
The hunt identifies investigation leads. It does not establish malicious intent or account compromise without corroborating evidence.
