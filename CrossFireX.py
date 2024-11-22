import os
import time
import sys
import logging
import requests
from urllib.parse import urlsplit, parse_qs, urlencode, urlunsplit
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, UnexpectedAlertPresentException
from webdriver_manager.chrome import ChromeDriverManager
from prompt_toolkit import prompt
from prompt_toolkit.completion import PathCompleter
from colorama import Fore
from rich.console import Console
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.panel import Panel

# Load the current version from the file
with open('version.txt', 'r') as f:
    CURRENT_VERSION = f.read().strip()

UPDATE_CHECK_URL = "https://raw.githubusercontent.com/VulnsecHB/CrossFireX/main/version.txt"
SCRIPT_URL = "https://raw.githubusercontent.com/VulnsecHB/CrossFireX/main/CrossFireX.py"


logging.getLogger('urllib3').setLevel(logging.CRITICAL)
logging.getLogger('selenium.webdriver.remote.remote_connection').setLevel(logging.CRITICAL)
logging.getLogger('selenium.webdriver.chrome.service').setLevel(logging.CRITICAL)
logging.getLogger('socket').setLevel(logging.CRITICAL)


def check_for_updates(current_version):
    try:
        print(Fore.YELLOW + "[🌐] Checking for updates...")
        response = requests.get(UPDATE_CHECK_URL, timeout=20)
        if response.status_code == 200:
            latest_version = response.text.strip()
            if latest_version > current_version:
                print(Fore.CYAN + f"[🔄] A new version ({latest_version}) is available! You're using {current_version}.")
                update_now = input(Fore.YELLOW + "[➡️] Do you want to update now? (y/N): ").strip().lower()
                if update_now == 'y':
                    download_and_replace_code()
            else:
                print(Fore.GREEN + "[✅] You're using the latest version.")
        else:
            print(Fore.RED + "[❌] Unable to fetch the latest version info.")
    except Exception as e:
        print(Fore.RED + f"[❌] Update check failed: {e}")

def download_and_replace_code():
    try:
        print(Fore.YELLOW + "[⬇️] Downloading the latest version...")
        print(Fore.CYAN + f"[ℹ️] Attempting to download script from: {SCRIPT_URL}")  # Debug print
        
        response = requests.get(SCRIPT_URL, timeout=60)
        
        print(Fore.CYAN + f"[ℹ️] HTTP Response Status: {response.status_code}")  # Debug print
        
        if response.status_code == 200:
            script_content = response.text
            # Save the updated script in the user's home directory
            home_dir = os.path.expanduser("~")
            script_path = os.path.join(home_dir, "CrossFireX.py")
            with open(script_path, 'w', encoding='utf-8') as script_file:
                script_file.write(script_content)
            print(Fore.GREEN + f"[✅] Update completed! Updated script saved at: {script_path}")
            print(Fore.CYAN + f"[💡] To run the updated version: python {script_path}")
        else:
            # Additional debug print for response details in case of failure
            print(Fore.RED + f"[❌] Failed to download the latest script. HTTP status code: {response.status_code}")
            print(Fore.RED + f"[❌] Response Content: {response.text}")  # Debug print for failure
    except Exception as e:
        print(Fore.RED + f"[❌] Update failed: {e}")

sys.stderr = open(os.devnull, 'w')

chromedriver_path = ChromeDriverManager().install()

options = webdriver.ChromeOptions()
options.add_argument("--headless")
options.add_argument("--no-sandbox")
options.add_argument("--disable-dev-shm-usage")
options.add_argument("--log-level=3")
options.add_argument("--disable-logging")


def check_internet_connection():
    try:
        console = Console()
        console.print(Panel("[🌐] Checking internet connection...", style="cyan"))
        response = requests.get("http://www.google.com", timeout=5)
        if response.status_code == 200:
            print(Fore.GREEN + "[✅] Internet connection is active.")
            return True
    except requests.ConnectionError:
        print(Fore.RED + "[❌] No internet connection.")
        return False
    except requests.Timeout:
        print(Fore.RED + "[❌] Internet connection timeout.")
        return False


def check_network_quality():
    try:
        print(Fore.YELLOW + "[📡] Measuring network quality...")
        start_time = time.time()
        response = requests.get("http://www.google.com", timeout=5)
        if response.status_code == 200:
            latency = (time.time() - start_time) * 1000  # Convert seconds to milliseconds
            if latency < 100:
                print(Fore.GREEN + f"[✅] {Fore.CYAN}Network latency:{Fore.RESET} {Fore.GREEN}{latency:.2f} ms (Excellent).\n")
            elif latency < 300:
                print(Fore.YELLOW + f"[⚠️ ] {Fore.CYAN}Network latency:{Fore.RESET} {Fore.GREEN}{latency:.2f} ms (Moderate).\n")
            else:
                print(Fore.RED + f"[❌] {Fore.CYAN}Network latency:{Fore.RESET} {Fore.GREEN}{latency:.2f} ms (Poor).\n")
            return True
    except requests.ConnectionError:
        print(Fore.RED + "[❌] Unable to measure network quality. Connection error.")
        return False
    except requests.Timeout:
        print(Fore.RED + "[❌] Network quality check timeout.")
        return False


def initiate_xss_tool():
    logging.basicConfig(level=logging.ERROR)
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    logging.getLogger('WDM').setLevel(logging.ERROR)

    def retrieve_payloads(file_path):
        try:
            with open(file_path, "r", encoding="utf-8") as file:
                return [line.strip() for line in file if line.strip()]
        except Exception as e:
            print(Fore.RED + f"[💥] Error loading payloads: {e}")
            sys.exit(0)

    def initiate_scan(input_urls, payload_filepath, max_concurrency):
        payload_list = retrieve_payloads(payload_filepath)
        discovered_vulnerabilities = []
        vulnerable_payloads = {}
        scan_count = [0]
        start_time = time.time()

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        try:
            with ThreadPoolExecutor(max_workers=max_concurrency) as executor:
                future_to_url = {
                    executor.submit(
                        assess_for_vulnerability,
                        url,
                        payload_list,
                        discovered_vulnerabilities,
                        vulnerable_payloads,
                        scan_count,
                        options,
                        chromedriver_path
                    ): url for url in input_urls
                }
                for future in as_completed(future_to_url):
                    url = future_to_url[future]
                    try:
                        future.result()
                    except Exception as e:
                        print(Fore.RED + f"[💥] Error scanning {url}: {e}")
        except KeyboardInterrupt:
            print(Fore.RED + "\n[❌] Scan interrupted by user.\n")

        return discovered_vulnerabilities, vulnerable_payloads, scan_count[0], start_time

    def assemble_attack_urls(target_url, injection_payload):
        urls_to_test = []
        scheme, netloc, path, query_string, fragment = urlsplit(target_url)
        if not scheme:
            scheme = 'http'
        query_params = parse_qs(query_string, keep_blank_values=True)
        for key in query_params.keys():
            modified_params = query_params.copy()
            modified_params[key] = [injection_payload]
            modified_query_string = urlencode(modified_params, doseq=True)
            modified_url = urlunsplit((scheme, netloc, path, modified_query_string, fragment))
            urls_to_test.append(modified_url)
        return urls_to_test

    def assess_for_vulnerability(test_url, payload_list, vulnerable_entries, vulnerable_payloads, scan_count, options, chromedriver_path):
        driver_service = Service(chromedriver_path)
        driver_instance = webdriver.Chrome(service=driver_service, options=options)

        try:
            for injection in payload_list:
                potential_urls = assemble_attack_urls(test_url, injection)
                if not potential_urls:
                    continue
                for target in potential_urls:
                    print(Fore.YELLOW + f"[⏳] Testing URL: {target} with payload: {injection}")
                    retries = 1
                    while retries > 0:
                        try:
                            driver_instance.get(target)
                            scan_count[0] += 1

                            try:
                                WebDriverWait(driver_instance, 2).until(EC.alert_is_present())
                                alert_box = driver_instance.switch_to.alert
                                alert_content = alert_box.text

                                if alert_content:
                                    result_message = Fore.GREEN + f"[🚨] Vulnerable: {target} - Alert Content: {alert_content}"
                                    print(result_message)
                                    vulnerable_entries.append(target)
                                    vulnerable_payloads[target] = injection
                                else:
                                    result_message = Fore.RED + f"[❌] Not Vulnerable: {target}"
                                    print(result_message)

                                alert_box.accept()
                                break
                            except TimeoutException:
                                retries -= 1
                                if retries == 0:
                                    print(Fore.RED + f"[❌] Not Vulnerable: {target}")
                        except UnexpectedAlertPresentException:
                            continue
        finally:
            driver_instance.quit()

    def display_scan_results(total_found, vulnerable_payloads, scans_completed, time_started):
        summary = [
            "[✅] Scan Completed.",
            f"{Fore.MAGENTA}================📜 Summary 📜================\n"
            f"🟢 {Fore.CYAN}Total vulnerabilities found:{Fore.RESET} {Fore.GREEN}{total_found}",
            f"🟢 {Fore.CYAN}Total URLs scanned:{Fore.RESET} {Fore.GREEN}{scans_completed}",
            f"🟢 {Fore.CYAN}Total time taken:{Fore.RESET} {Fore.GREEN}{int(time.time() - time_started)} seconds"
        ]
        for line in summary:
            print(Fore.YELLOW + line)
        if total_found > 0:
            print(Fore.CYAN + "\n[🚨] Detected Vulnerable URLs and Payloads:")
            for url, payload in vulnerable_payloads.items():
                print(Fore.GREEN + f"    ➡️ URL: {url}")
                print(Fore.GREEN + f"       Payload: {payload}\n")

    def reset_console():
        os.system('cls' if os.name == 'nt' else 'clear')

    def obtain_filepath(prompt_text):
        path_completer = PathCompleter()
        return prompt(prompt_text, completer=path_completer).strip()

    def prompt_for_urls():
        while True:
            try:
                url_path = obtain_filepath("[➡️ ] Enter the path to the file containing URLs (or press Enter for a single URL): ")
                if url_path:
                    if not os.path.isfile(url_path):
                        raise FileNotFoundError(f"\n[🔴] File not found: {url_path}")
                    with open(url_path) as file:
                        url_entries = [line.strip() for line in file if line.strip()]
                    return url_entries, 'file'
                else:
                    single_url = input(Fore.MAGENTA + "[➡️ ] Enter a single URL to scan: nlabla ").strip()
                    if single_url:
                        return [single_url], 'single'
                    else:
                        print(Fore.RED + "[💥] You must provide a file with URLs or a single URL.")
                        input(Fore.YELLOW + "\n[💥] Press Enter to try again...")
                        reset_console()
            except Exception as e:
                print(Fore.RED + f"[💥] Error with input file. Exception: {str(e)}")
                input(Fore.YELLOW + "[💥] Press Enter to retry...")
                reset_console()

    def prompt_for_payload_file():
        while True:
            file_path = obtain_filepath("[➡️ ] Enter the path to the payload file: ").strip()
            if os.path.isfile(file_path):
                return file_path
            else:
                print(Fore.RED + "[💥] Invalid file path.")
                input(Fore.YELLOW + "[💥] Press Enter to retry...")
                reset_console()

    def display_name():
        name = """
        ▄████▄   ██▀███   ▒█████    ██████   ██████   █████▒██▓ ██▀███  ▓█████ ▒██   ██▒
        ▒██▀ ▀█  ▓██ ▒ ██▒▒██▒  ██▒▒██    ▒ ▒██    ▒ ▓██   ▒▓██▒▓██ ▒ ██▒▓█   ▀ ▒▒ █ █ ▒░
        ▒▓█    ▄ ▓██ ░▄█ ▒▒██░  ██▒░ ▓██▄   ░ ▓██▄   ▒████ ░▒██▒▓██ ░▄█ ▒▒███   ░░  █   ░
        ▒▓▓▄ ▄██▒▒██▀▀█▄  ▒██   ██░  ▒   ██▒  ▒   ██▒░▓█▒  ░░██░▒██▀▀█▄  ▒▓█  ▄  ░ █ █ ▒ 
        ▒ ▓███▀ ░░██▓ ▒██▒░ ████▓▒░▒██████▒▒▒██████▒▒░▒█░   ░██░░██▓ ▒██▒░▒████▒▒██▒ ▒██▒
        ░ ░▒ ▒  ░░ ▒▓ ░▒▓░░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░▒ ▒▓▒ ▒ ░ ▒ ░   ░▓  ░ ▒▓ ░▒▓░░░ ▒░ ░▒▒ ░ ░▓ ░
          ░  ▒     ░▒ ░ ▒░  ░ ▒ ▒░ ░ ░▒  ░ ░░ ░▒  ░ ░ ░      ▒ ░  ░▒ ░ ▒░ ░ ░  ░░░   ░▒ ░
        ░          ░░   ░ ░ ░ ░ ▒  ░  ░  ░  ░  ░  ░   ░ ░    ▒ ░  ░░   ░    ░    ░    ░  
        ░ ░         ░         ░ ░        ░        ░          ░     ░        ░  ░ ░    ░  
        ░                                                                                
                            Enhanced XSS Vulnerability Scanner
                                    Created by Vulnsec
        """
        print(Fore.CYAN + name)

    def main_tool():
        reset_console()

        display_name()

        print(35*" " + f"current version: {CURRENT_VERSION}")

        check_for_updates(CURRENT_VERSION) 

        if not check_internet_connection():
            print(Fore.RED + "[💥] Internet connection required for the scan.")
            sys.exit(1)

        if not check_network_quality():
            print(Fore.RED + "[💥] Poor network quality may affect scan performance.")
            proceed = input(Fore.YELLOW + "[➡️] Proceed with the scan? (y/N): ").strip().lower()
            if proceed != 'y':
                sys.exit(1)

        url_list, url_source = prompt_for_urls()
        payload_filepath = prompt_for_payload_file()

        reset_console()

        scan_start_time = time.time()

        all_vulnerable_urls = []
        total_scanned_count = [0]
        vulnerable_payloads = {}

        try:
            print(Fore.CYAN + "\n[⏳] ================== Initiating scan =========================\n")
            all_vulnerabilities, vulnerable_payloads, scanned_count, _ = initiate_scan(url_list, payload_filepath, max_concurrency=10)
            all_vulnerable_urls.extend(all_vulnerabilities)
            total_scanned_count = scanned_count

        except KeyboardInterrupt:
            print(Fore.RED + "\nScan interrupted by user.\n")

        display_scan_results(len(all_vulnerable_urls), vulnerable_payloads, total_scanned_count, scan_start_time)

    main_tool()


initiate_xss_tool()
