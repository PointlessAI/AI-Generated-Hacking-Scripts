# **Domain Name Investigation Guide**

This guide helps in gathering **public information** about a domain name using various manual techniques.

---

## **Step-by-Step Table for Domain Reconnaissance**

| **Step** | **Command** | **Purpose** | **Description** | **Example Output** |
|------|---------|---------|--------------|----------------|
| **1** | `whois example.com` | Find ownership & registrar details | Retrieves the domain's registration info, including owner (if not private), registrar, and creation/expiry dates. | `Registrar: Namecheap` <br> `Creation Date: 2021-01-10` |
| **2** | `nslookup example.com` or `dig example.com` | Find the IP address of the domain | Resolves the domain name to its assigned IP address(es). | `Non-authoritative answer: x.x.x.8` |
| **3** | `host example.com` | Perform DNS lookup | Checks domain-to-IP mappings and mail server records. | `example.com has address x.x.x.8` |
| **4** | `dig ANY example.com` | Retrieve all DNS records | Fetches all available DNS records (A, MX, TXT, CNAME, etc.). | `A record: x.x.x.8` <br> `MX record: mail.example.com` |
| **5** | `dig example.com NS` | Find name servers | Shows the authoritative name servers for the domain. | `ns1.hosting.com` <br> `ns2.hosting.com` |
| **6** | `dig example.com MX` | Find email servers | Reveals which servers handle email for the domain. | `10 mail.example.com` |
| **7** | `dig example.com TXT` | Find additional domain info | Extracts TXT records, including SPF (email security), DKIM, or other domain metadata. | `v=spf1 include:_spf.google.com ~all` |
| **8** | `traceroute example.com` or `mtr example.com` | Map network path | Traces the route from your machine to the domain’s server. | `Hop 5: aws-datacenter.com` |
| **9** | `nmap -Pn -p 1-1000 example.com` | Scan open ports on the domain’s server | Checks for exposed services on the domain’s IP. | `22/tcp open ssh` <br> `443/tcp open https` |
| **10** | `curl -I https://example.com` | Retrieve website headers | Shows the HTTP response headers, which may reveal tech stack details. | `Server: Apache` <br> `X-Powered-By: PHP` |
| **11** | `subfinder -d example.com` or `amass enum -d example.com` | Discover subdomains | Finds subdomains associated with the domain. | `api.example.com` <br> `blog.example.com` |
| **12** | **Visit [crt.sh](https://crt.sh/?q=example.com)** | Find SSL certificate-related domains | Lists domains and subdomains associated with SSL certificates. | `common-name: secure.example.com` |
| **13** | **Use [ViewDNS](https://viewdns.info/reverseip/)** | Check other domains on the same server | Finds other domains sharing the same IP. | `another-example.com` |
| **14** | **Visit [Wayback Machine](https://web.archive.org/web/*/example.com)** | View historical snapshots of the website | Shows past versions of the website using archived pages. | `Screenshot from 2015-06-01` |
| **15** | **Use [SecurityTrails](https://securitytrails.com/domain/example.com)** | Get domain history & related assets | Provides domain records, past IPs, and infrastructure details. | `Previous IP: 34.112.45.22` |

---

## **How to Use This Table**
1. **Start with basic domain info** (`whois`, `nslookup`, `dig`).
2. **Check DNS records** (`A`, `MX`, `TXT`, `NS`).
3. **Analyze the network path & open ports** (`traceroute`, `nmap`).
4. **Look for additional assets** (`subfinder`, `crt.sh`, `ViewDNS`).
5. **Explore historical data** (Wayback Machine, SecurityTrails).

---

## **Next Steps**
If the **IP address is known**, investigate it using the **IP discovery table**.  
If a **subdomain is found**, repeat steps **2-15** for subdomains.  
If you find **shared hosting**, multiple unrelated domains may appear.

---

Would you like a **version with extended examples** for each command? 🚀