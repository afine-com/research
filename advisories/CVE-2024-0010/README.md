# CVE-2024-0010
GlobalProtect Portal < 9.1.17, < 10.1.11-h1, < 10.1.12 - Reflected Cross-Site Scripting (XSS)

## Timeline
- Vulnerability reported to vendor: 22.03.2023 
- New fixed 5.0 version released: 14.02.2024
- Public disclosure: 30.02.2024

## Description

A reflected cross-site scripting (XSS) vulnerability, identified as CVE-2024-0010, has been discovered in the GlobalProtect portal feature of Palo Alto Networks’ PAN-OS software. This flaw allows malicious JavaScript to execute in a user’s browser if they click on a crafted link, potentially leading to phishing attacks and credential theft. The vulnerability affects PAN-OS versions prior to 9.0.17-h4, 9.1.17, 10.1.11-h1, and 10.1.12. Palo Alto Networks has addressed this issue in the aforementioned versions and later releases. Additionally, customers with a Threat Prevention subscription can mitigate this vulnerability by enabling Threat ID 94972, available in Applications and Threats content update 8810. As of the latest information, there are no reports of this vulnerability being exploited maliciously.

## Affected versions
< 9.1.17
< 10.1.11-h1
< 10.1.12

## Advisory
Update AdmirorFrames Joomla! Extension to version 9.1.17, 10.1.11-h1, 10.1.12 or newer.

### References
* https://security.paloaltonetworks.com/CVE-2024-0010
* https://nvd.nist.gov/vuln/detail/cve-2024-0010
* https://www.cve.org/CVERecord?id=CVE-2024-0010
