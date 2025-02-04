# **Summary of Manual Network Discovery Process**

This table summarizes the key steps in manually investigating an IP E.G. **x.x.x.8** and related assets.

| **Step** | **Command** | **Purpose** | **Description** | **Example Output** |
|------|---------|---------|--------------|----------------|
| **1** | `whois x.x.x.8` | Find ownership & subnet info | Retrieves details about who owns the IP and what range it belongs to. | `NetRange: 13.24.0.0 - 13.59.255.255` |
| **2** | `fping -g x.x.x.0/24 2>/dev/null` | Discover live hosts | Scans the subnet for active IPs responding to ICMP (ping). | `x.x.x.8 is alive` <br> `x.x.x.18 is alive` |
| **3** | `dig -x <IP>` or `host <IP>` | Reverse DNS lookup | Checks if the IP has an associated domain name. | `8.33.56.13.in-addr.arpa domain name pointer example.com.` |
| **4** | `whois <IP>` | Find organization details | Extracts the company, ISP, or hosting provider that owns the IP. | `OrgName: Amazon AWS` |
| **5** | **Use ViewDNS or SecurityTrails** | Reverse IP lookup | Finds **all domains** that share the same IP. | `example.com` <br> `another-example.com` |
| **6** | `traceroute <IP>` or `mtr <IP>` | Map network path | Shows the route taken to reach the target IP. | `Hop 1: 192.168.1.1` <br> `Hop 5: aws-datacenter.com` |
| **7** | `nmap -Pn -p 22,80,443 <IP>` | Scan open ports | Identifies open services on the IP. | `22/tcp open ssh` <br> `80/tcp open http` |
| **8** | `curl -I https://<IP>` | Check web headers | Retrieves HTTP response headers for web servers. | `Server: nginx` <br> `X-Powered-By: PHP` |
| **9** | **Visit [crt.sh](https://crt.sh/?q=<IP>)** | Find SSL-related domains | Lists domains that share an SSL certificate. | `common-name: app.example.com` |
| **10** | `subfinder -d <domain>` | Find subdomains | Finds subdomains of a discovered domain. | `api.example.com` <br> `dev.example.com` |

---

## **How to Use This Table**
1. Follow each **step in order**.
2. If **a domain name is found**, use **step 10** to find subdomains.
3. If **no related domains appear**, it's likely a **hosting provider**.
4. If **ports are open**, check what services are running.
5. If **you want a deeper scan**, try **all ports**:  
   ```bash
   nmap -Pn -p- <IP>