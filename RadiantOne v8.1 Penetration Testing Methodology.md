# RadiantOne v8.1 Penetration Testing Methodology

## Network Reconnaissance and Service Enumeration

Begin by mapping out the RadiantOne Identity Management (IDM) services on the network. RadiantOne’s Federation Identity Directory (FID) service is typically accessed via LDAP on a non-standard default port **2389** (and LDAPS on **2636**). The administrative web interfaces (Control Panels) run on their own ports (HTTP on **7070** and HTTPS on **7171**), and the platform also exposes REST/SCIM web services on default ports **8089/8090** for HTTP/HTTPS API calls. Perform a thorough port scan to identify these services:

- **LDAP/LDAPS Enumeration:**  
  Check for the LDAP service on 2389 and LDAPS on 2636. Use an LDAP browser or command-line tool to query the Root DSE of the directory. The Root DSE may reveal the `vendorVersion` attribute (e.g., “RadiantOne v8.1.x”), helping fingerprint the exact version. Note any other open ports (e.g., a ZooKeeper coordination service if in cluster mode – often on port 2181 – as RadiantOne uses a ZooKeeper ensemble for clustering) and plan to probe those as well.

- **Web Interface Enumeration:**  
  Identify the Control Panel URLs. The Main Control Panel (for cluster-wide management) and Server Control Panels (node-specific) are web-based. Try accessing the default HTTP/HTTPS ports (7070/7171). If a login page is present, it indicates the service is running. Also, probe the REST API endpoints on 8089/8090 (e.g., try a GET to `/scim/v2/Users`) to see if they respond or require authentication. Any endpoints accessible without credentials should be flagged.

## Federation Identity Directory (FID) Attack Vectors

### Anonymous Bind & Default Access
Attempt an anonymous bind to the LDAP service (no credentials). By default, RadiantOne accepts empty-password binds as anonymous. Once bound, perform read/search operations to retrieve naming contexts, entries, or the Root DSE. If sensitive data is exposed, enable the “Bind Requires Password” option in the Admin UI.

### Default Credentials and Privileged Accounts
RadiantOne uses a directory administrator account `cn=Directory Manager`. Its password is set during installation (no vendor default). Verify this password has been changed. Also test any initial “wizard” or sample accounts mentioned in deployment guides.

### Access Control Misconfiguration
Review Access Control Instructions (ACIs). RadiantOne’s default “global read” ACI grants broad read access. Test if non-admin or anonymous binds can read restricted attributes or perform write operations. Look for internal groups that bypass ACI checks for replication—if unprotected, adding yourself to such groups disables ACL enforcement.

### Inter-Cluster Replication Abuse
In multi-node clusters, replication uses a peer LDAP connection. Identify the replication account or certificate. If replication traffic is unencrypted or unauthenticated, attempt to impersonate a replication partner to extract a full directory copy. Confirm mutual authentication.

## Connector and Synchronization Exploitation

- **Credential Extraction:**  
  Connectors store Bind DN and password. Retrieve these via the Admin UI (“Data Sources → Edit Connector → Show Password”) or from config files. Use extracted credentials to bind to backend systems (e.g., AD) with high privileges.

- **Misconfigured Connector Security:**  
  Test if connectors enforce SSL/TLS. If connectors use plaintext LDAP (port 389), perform a MITM to capture credentials. Verify certificate validation.

- **Synchronization & Provisioning Abuse:**  
  Examine Global Sync pipelines. If management access is available, reconfigure connectors to point to a malicious LDAP server to inject entries. From outside, monitor propagation of rogue accounts created in trusted sources.

- **Testing Trust Boundaries:**  
  RadiantOne’s authentication bind-order may allow lower-priority sources to override higher ones. Create a user in a less-secure source and observe if authentication flows treat it as the same identity. Also test group merging from multiple sources.

- **Connector Extensibility:**  
  Review any custom connectors or scripts for vulnerabilities. Test External Token Validators (OIDC/SAML) for improper signature validation or token replay.

## Web Interfaces and API Security

- **Admin Control Panel Access:**  
  Verify all UI pages require authentication. Test default login credentials (e.g., `cn=Directory Manager`) or initial setup accounts. Enumerate UI functions like directory export or plugin deployment for potential code execution.

- **REST/SCIM API Testing:**  
  Confirm API endpoints require HTTP Basic auth. Test with low-privilege credentials what data is returned (e.g., GET `/scim/v2/Users`). Attempt CRUD operations to identify excessive privileges or broken access controls.

- **Web App Vulnerabilities:**  
  Perform standard tests: LDAP/SQL injection in login forms, XSS in user-editable fields, IDORs on parameterized endpoints, file upload validation, session handling (HttpOnly/Secure flags), and error message leakage for internal details.

## Configuration and Deployment Weaknesses

- **Weak Password Policies:**  
  Check account lockout settings and hashing algorithms (e.g., Digest-MD5). Attempt password cracking if hashes are exposed.

- **Default Keys/Certificates:**  
  Verify keystore password (often `changeit` or `radiantlogic`). Extract private keys if default passwords are used. Ensure TLS (LDAPS/StartTLS) is enforced and keystore passwords are rotated.

- **Hardening Settings:**  
  Enforce “Bind Requires Password,” remove default global read ACIs, enable “Always Authenticate,” and configure RootDSE ACI. Test if default settings allow unintended access.

- **Cluster Security:**  
  Ensure ZooKeeper uses SSL and authentication. Test if znodes are readable/writable. Confirm secure configuration of cloud connectors (e.g., Secure Data Connector).

- **Audit & Monitoring:**  
  Verify logging of failed binds, config changes, and suspicious activity. Increase audit levels and test detection of example attacks.

---

By following this structured approach—from network enumeration, through LDAP/FID exploitation, connector abuse, web interface testing, to configuration review—you can comprehensively assess RadiantOne IDM v8.1 for privilege escalation and unauthorized directory access. Always reference official documentation to distinguish designed behavior from configuration flaws.
