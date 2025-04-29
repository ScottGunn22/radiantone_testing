# RadiantOne v8.1 Penetration Testing Methodology

A comprehensive, end-to-end penetration testing methodology for RadiantOne Identity Management (IDM) v8.1. This repository contains step-by-step guidance, use cases, and command examples using Kali Linux and Burp Suite Pro for network reconnaissance, LDAP/FID exploitation, connector abuse, web interface testing, configuration review, and post-exploitation.

## Overview

RadiantOne Identity Management (IDM) is an identity virtualization platform that aggregates multiple identity stores into a single logical directory. This methodology guides penetration testers through discovering all exposed services, testing default and misconfigured security controls, and exploiting weaknesses to achieve privilege escalation and unauthorized LDAP access.

## Requirements

- Kali Linux (or any Linux distribution with standard pentest toolset)
- Burp Suite Pro
- `nmap`, `ldapsearch`, `hydra`, `ldapmodify`, `mitmproxy`
- `curl`, `openssl`, `keytool`
- Valid network access to the target RadiantOne environment
