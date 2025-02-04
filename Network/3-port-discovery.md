# **Port Scanning Guide: Investigating a Live Host (x.x.x.8)**

This guide provides a step-by-step process for scanning open ports and identifying services running on a live host.

---

## **Step-by-Step Table for Port Scanning**

| **Step** | **Command** | **Purpose** | **Description** | **Example Output** |
|------|---------|---------|--------------|----------------|
| **1** | `ping -c 3 x.x.x.8` | Verify if the host is reachable | Sends ICMP echo requests to check if the target is online. | `64 bytes from x.x.x.8: icmp_seq=1 ttl=52 time=20.1 ms` |
| **2** | `nmap -Pn x.x.x.8` | Perform a basic scan | Checks for open ports on the target without pinging (useful if ICMP is blocked). | `Not shown: 990 filtered ports` <br> `22/tcp open ssh` |
| **3** | `nmap -p 1-1000 x.x.x.8` | Scan common ports | Scans the first 1000 ports for open services. | `80/tcp open http` <br> `443/tcp open https` |
| **4** | `nmap -p- x.x.x.8` | Perform a full port scan | Scans all **65,535** ports to discover less common services. | `3306/tcp open mysql` <br> `8080/tcp open http-proxy` |
| **5** | `nmap -sV x.x.x.8` | Detect service versions | Identifies the software version running on open ports. | `22/tcp open ssh OpenSSH 8.4p1` <br> `80/tcp open http Apache 2.4.41` |
| **6** | `nmap -O x.x.x.8` | Detect operating system | Tries to determine the target's OS based on response behavior. | `OS: Linux 4.15 - 5.6` |
| **7** | `nmap --script banner x.x.x.8` | Grab service banners | Extracts additional information from running services. | `220 Mail Server ESMTP` |
| **8** | `nmap -sC x.x.x.8` | Run default NSE scripts | Uses common scripts to check for vulnerabilities and misconfigurations. | `OpenSSH 7.6p1 (protocol 2.0)` |
| **9** | `nmap -sU -p 53,161 x.x.x.8` | Scan UDP ports | Checks for open UDP services like DNS and SNMP. | `53/udp open domain` |
| **10** | `nmap -p 443 --script ssl-cert x.x.x.8` | Check SSL certificate details | Retrieves SSL certificate information if HTTPS is enabled. | `Subject: CN=example.com` |
| **11** | `nmap --script vuln x.x.x.8` | Scan for known vulnerabilities | Runs vulnerability checks against detected services. | `CVE-2021-34527: VULNERABLE` |
| **12** | `netcat -zv x.x.x.8 22-443` | Quick port connectivity check | Tests if specific ports are open by attempting connections. | `Connection to x.x.x.8 22 port [tcp/ssh] succeeded!` |
| **13** | `curl -I http://x.x.x.8` | Retrieve HTTP headers | Checks web server response headers if a web port is open. | `Server: nginx` <br> `X-Powered-By: PHP/7.4` |
| **14** | `whatweb x.x.x.8` | Identify web technologies | Detects web server details and technologies in use. | `WordPress 5.8, Apache 2.4.41, jQuery 3.5.1` |

---

## **How to Use This Table**
1. **Start with a basic reachability test** (`ping`).
2. **Check for open ports** (`nmap -Pn` or `nmap -p 1-1000`).
3. **Perform a full port scan** (`nmap -p-`).
4. **Identify service versions** (`nmap -sV`).
5. **Run OS detection and vulnerability scans** (`nmap -O`, `nmap --script vuln`).
6. **Check web services** if HTTP/HTTPS is detected (`curl -I`, `whatweb`).

---

## **Next Steps**
- If critical services like **SSH, MySQL, or RDP** are open, investigate security risks.
- If a web server is running, check for **web-based vulnerabilities**.
- If the system is hosting **SSL services**, analyze the certificate for **misconfigurations**.
- If sensitive services are **exposed to the internet**, consider **security best practices**.

---

Would you like additional steps for **web application scanning** or **network vulnerability assessment**?