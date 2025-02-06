import time
import requests
import os
import logging
import threading
import concurrent.futures
import json
from openai import OpenAI
from dotenv import load_dotenv

# -----------------------------
# Load environment variables
# -----------------------------
# Load environment variables from the .env file
load_dotenv()

# Initialize OpenAI client with the API key from environment variables
client = OpenAI(
    api_key=os.getenv("OPENAI_API_KEY"),
)

# -----------------------------
# Configuration
# -----------------------------
URL = "https://pointlessai.com"  # Target domain for the test
BLOCKED_STATUS_CODES = {429, 403}  # Status codes considered "blocked"

# Test speeds and concurrency
BURST_RPS = 20           # ~20 requests per second during burst
SLOW_RPS = 1             # 1 request per second in slow test
BURST_THREADS = 50       # Thread pool size for burst test
WAIT_BETWEEN_BURST_CHECKS = 0.05

# Timeouts (in seconds)
BURST_TEST_TIMEOUT = 120     # Max time to run burst test before stopping
UNBLOCK_TEST_TIMEOUT = 120   # Max time to wait for block to lift

RESULTS_FILE = "rate_limit_results.json"

# -----------------------------
# Logging configuration
# -----------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

# -----------------------------
# Data collection
# -----------------------------
test_results = {
    "total_requests": 0,
    "blocked_requests": 0,
    "block_timestamps": [],
    "unblock_timestamps": [],
    "rate_limit_recovery_time": None,
    "test_phases": []
}

# Thread-safe lock
lock = threading.Lock()

# -----------------------------
# Helper functions
# -----------------------------
def send_request():
    """
    Send a GET request to the target URL and return the status code (or None on error).
    """
    try:
        response = requests.get(URL)
        with lock:
            test_results["total_requests"] += 1
        return response.status_code
    except requests.RequestException as e:
        logging.error(f"Request failed: {e}")
        return None

def record_block():
    """
    Record block event (timestamp, increment count).
    """
    with lock:
        test_results["blocked_requests"] += 1
        test_results["block_timestamps"].append(time.time())

def record_unblock():
    """
    Record unblock event (timestamp).
    """
    with lock:
        test_results["unblock_timestamps"].append(time.time())

def save_results():
    """
    Save test_results to a JSON file for future reference.
    """
    with open(RESULTS_FILE, "w") as f:
        json.dump(test_results, f, indent=4)
    logging.info(f"Results saved to {RESULTS_FILE}")

def chatgpt_report(scan_results):
    """
    Generate report using ChatGPT API
    """
    try:
        # you may need openai.api_key = OPENAI_API_KEY
        response = client.chat.completions.create(
            model="gpt-4",  # or "gpt-3.5-turbo"
            messages=[
                {
                    "role": "system",
                    "content": "Best guess of both rate limit nad burst limit with limit timeout length based on available data."
                },
                {
                    "role": "user",
                    "content": scan_results
                }
            ]
        )
        return response.choices[0].message.content
    except Exception as e:
        logging.error(f"OpenAI API request failed: {str(e)}")
        return f"Error from OpenAI API: {str(e)}"

# -----------------------------
# Test phases
# -----------------------------
def burst_test():
    """
    1) Perform high-frequency concurrent requests (~20 RPS) until a block is detected OR timeout.
    """
    logging.info("=== Starting Burst Test (~20 req/sec) ===")

    start_time = time.time()
    test_phase = {
        "phase": "burst_test",
        "start_time": start_time,
        "blocked": False
    }

    with concurrent.futures.ThreadPoolExecutor(max_workers=BURST_THREADS) as executor:
        futures = set()

        def process_result(future):
            try:
                status_code = future.result()
                if status_code in BLOCKED_STATUS_CODES:
                    logging.info(f"Rate limit hit with status code {status_code}.")
                    record_block()
                    test_phase["blocked"] = True
                    return True  # indicates we should stop
            except Exception as e:
                logging.error(f"Error processing request: {e}")
            return False

        while True:
            # Check if we've hit the timeout
            if time.time() - start_time > BURST_TEST_TIMEOUT:
                logging.warning("Burst test timed out without detecting a block.")
                test_phase["end_time"] = time.time()
                test_results["test_phases"].append(test_phase)
                break

            # Keep enough futures to maintain ~20 RPS
            while len(futures) < BURST_RPS:
                future = executor.submit(send_request)
                futures.add(future)

            done, futures = concurrent.futures.wait(futures, timeout=1, return_when=concurrent.futures.FIRST_COMPLETED)

            # Check completed futures for block
            for future in done:
                if process_result(future):
                    test_phase["end_time"] = time.time()
                    test_results["test_phases"].append(test_phase)
                    return  # block detected -> stop the burst

            # Maintain ~20 RPS
            time.sleep(WAIT_BETWEEN_BURST_CHECKS)

def unblock_test():
    """
    2) After a block, send a request every 3 seconds until block is lifted OR timeout.
       Record how long it took. If it exceeds 65 seconds, prompt user to change IP.
       If we time out entirely, prompt the user to change IP.
    """
    logging.info("=== Checking if the block is lifted (1 req/3 sec) ===")
    test_phase = {
        "phase": "unblock_test",
        "start_time": time.time(),
        "unblocked": False,
        "time_to_unblock": None
    }

    start_time = time.time()

    while True:
        # Check if we've hit the unblock test timeout
        if time.time() - start_time > UNBLOCK_TEST_TIMEOUT:
            logging.warning("Unblock test timed out. The block has not been lifted within allotted time.")
            test_phase["end_time"] = time.time()
            test_phase["time_to_unblock"] = None
            test_results["test_phases"].append(test_phase)

            # Prompt user to change IP because we never unblocked
            logging.info("The block was never lifted. Please consider changing your IP address.")
            input("Press Enter after changing your IP to continue...")

            break

        time.sleep(3)
        status_code = send_request()

        if status_code and (status_code not in BLOCKED_STATUS_CODES):
            # Block is lifted
            unblock_time = time.time()
            record_unblock()

            test_phase["unblocked"] = True
            test_phase["end_time"] = unblock_time
            test_phase["time_to_unblock"] = unblock_time - start_time
            test_results["test_phases"].append(test_phase)

            logging.info("Block is lifted.")
            logging.info(f"Time to unblock: {test_phase['time_to_unblock']:.2f} seconds")

            # If block was lifted after > 65 seconds, suggest IP change
            if test_phase["time_to_unblock"] > 65:
                logging.info("Unblock took longer than 65 seconds. Please consider changing your IP address.")
                input("Press Enter after changing your IP to continue...")

            break

def slow_test():
    """
    3) Send 1 request per second for a fixed number of requests (20).
       Record any new block events if they occur.
       (No timeout needed since it's already bounded by 20 requests.)
    """
    logging.info("=== Starting Slow Test (1 req/sec) ===")
    test_phase = {
        "phase": "slow_test",
        "start_time": time.time(),
        "blocked_during_test": False
    }

    num_requests = 20  # Modify as needed
    for i in range(num_requests):
        status_code = send_request()
        if status_code in BLOCKED_STATUS_CODES:
            logging.warning(f"Blocked again with status code {status_code} after {i+1} requests in slow test.")
            record_block()
            test_phase["blocked_during_test"] = True
            break
        logging.info(f"Slow test request #{i+1} -> Status code: {status_code}")
        time.sleep(1)  # 1 request per second

    test_phase["end_time"] = time.time()
    test_results["test_phases"].append(test_phase)

def analyze_results():
    """
    4) Calculate and display final results, then send to ChatGPT.
    """
    logging.info("=== Analyzing Results ===")

    # Calculate rate-limit recovery time (if we have at least one block/unblock)
    if test_results["block_timestamps"] and test_results["unblock_timestamps"]:
        test_results["rate_limit_recovery_time"] = (
            test_results["unblock_timestamps"][0] - test_results["block_timestamps"][0]
        )

    summary_lines = [
        f"Total Requests Sent: {test_results['total_requests']}",
        f"Blocked Requests: {test_results['blocked_requests']}"
    ]

    if test_results["block_timestamps"]:
        first_block_time = test_results["block_timestamps"][0]
        summary_lines.append(f"First Block Timestamp: {first_block_time}")
    else:
        summary_lines.append("First Block Timestamp: N/A")

    if test_results["unblock_timestamps"]:
        first_unblock_time = test_results["unblock_timestamps"][0]
        summary_lines.append(f"First Unblock Timestamp: {first_unblock_time}")
    else:
        summary_lines.append("First Unblock Timestamp: N/A")

    if test_results["rate_limit_recovery_time"]:
        summary_lines.append(
            f"Rate Limit Recovery Time: {test_results['rate_limit_recovery_time']:.2f} seconds"
        )
    else:
        summary_lines.append("Rate Limit Recovery Time: N/A")

    final_summary = "\n".join(summary_lines)
    logging.info("\n===== Final Test Results Summary =====\n" + final_summary)

    # Send final summary to ChatGPT for an analysis
    gpt_analysis = chatgpt_report(final_summary)
    logging.info("\n===== ChatGPT Analysis =====\n" + gpt_analysis)

    return final_summary, gpt_analysis

# -----------------------------
# Main
# -----------------------------
if __name__ == "__main__":
    # 1) Burst test ~20 requests/sec (with timeout)
    burst_test()

    # 2) If we have a block timestamp, attempt to unblock (with timeout)
    if test_results["block_timestamps"]:
        unblock_test()

    # 3) Slow test (bounded by 20 requests)
    slow_test()

    # 4) Analyze and save results
    summary, gpt_analysis = analyze_results()
    save_results()