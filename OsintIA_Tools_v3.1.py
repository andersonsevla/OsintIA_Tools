import os
import sys
import requests
import subprocess
import re
import time
from urllib.parse import urlparse
from bs4 import BeautifulSoup

def print_header():
    header = r"""
*******************************************************************
*     ___      _       _   ___    _      _____           _        *
*    / _ \ ___(_)_ __ | |_|_ _|  / \    |_   _|__   ___ | |___    *
*   | | | / __| | '_ \| __|| |  / _ \     | |/ _ \ / _ \| / __|   *
*   | |_| \__ \ | | | | |_ | | / ___ \    | | (_) | (_) | \__ \   *
*    \___/|___/_|_| |_|\__|___/_/   \_\   |_|\___/ \___/|_|___/   *
*                                                                 *
* OsintIA_Tools 1.0.3                                             *
* Coded by Anderson Alves                                         *
* Cybersecurity Research                                          *
* anderson_alves@live.com                                         *
*******************************************************************
"""
    print(header)

# Set your API keys for OpenAI and Shodan
OPENAI_API_KEY = "sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx_xxxxxxxxxxxxxxxxxxxxxxxxxxxxx_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
SHODAN_API_KEY = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# List of required dependencies
DEPENDENCIES = [
    "dig", "whois", "nmap", "wget", "poppler-utils", "exiftool", "amass", "sublist3r",
    "whatweb", "theHarvester", "dnsenum", "python3", "photon", "metagoofil"
]

# Function to check and install dependencies
def check_and_install_dependencies():
    print("[+] Checking dependencies...")
    missing = []
    for dep in DEPENDENCIES:
        if subprocess.run(f"which {dep}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode != 0:
            missing.append(dep)
    
    if missing:  # Only install if there are missing dependencies
        print(f"[!] Missing dependencies: {', '.join(missing)}")
        if os.geteuid() != 0:
            print("[!] Administrator privileges are required to install dependencies. Run the script as root or with sudo.")
            sys.exit(1)
        print("[+] Installing dependencies...")
        
        # Redirect stdout and stderr to a log file
        install_command = f"sudo apt update >> install.log 2>&1 && sudo apt install -y {' '.join(missing)} >> install.log 2>&1"
        if subprocess.run(install_command, shell=True).returncode != 0:
            print("[!] Failed to install dependencies. Check your connection or try again. See 'install.log' for details.")
            sys.exit(1)
        print("[+] All dependencies were installed successfully.")
    else:
        print("[+] All dependencies are already installed.")

# Function to call the OpenAI API
def call_chatgpt(prompt):
    url = "https://api.openai.com/v1/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {OPENAI_API_KEY}"
    }
    payload = {
        "model": "gpt-3.5-turbo",
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 2000,
        "temperature": 0.5
    }

    for attempt in range(3):  # Attempt up to 3 times
        try:
            response = requests.post(url, headers=headers, json=payload, timeout=10)
            response.raise_for_status()
            return response.json()["choices"][0]["message"]["content"].strip()
        except requests.exceptions.RequestException as e:
            print(f"[!] Attempt {attempt + 1} failed: {e}")
            time.sleep(2 ** attempt)  # Exponential backoff: 2s, 4s, 8s
            if attempt == 2:  # Last attempt
                return "Error: Unable to connect to the OpenAI API."
    return "Error: Failed to connect to the OpenAI API after multiple attempts."

# Function to execute a command in the terminal
def run_command(command):
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)
    return result.stdout.strip()

# Function to remove ANSI codes for color formatting in terminal output.
def remove_ansi_escape_sequences(text):
    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)

# Function to format AI analysis text by splitting it into clear HTML paragraphs.
def format_analysis_text(text):
    paragraphs = text.split('\n')
    return ''.join(f'<p>{paragraph.strip()}</p>' for paragraph in paragraphs if paragraph.strip())

# Function to generate an HTML index based on report sections.
def generate_html_index(sections):
    index_html = "<h2>Index</h2><ul>"
    for section_id, section_name in sections.items():
        index_html += f"<li><a href='#{section_id}'>{section_name}</a></li>"
    index_html += "</ul>"
    return index_html

# Function to write a section in the HTML report
def write_section(html_file, section_id, title, content):
    html_file.write(f"<h2 id='{section_id}'>{title}</h2>{content}")

# Main function
def main(domain):
    print_header()  # Display the header in the terminal
    if not domain:
        print("Usage: python osint_tools.py <domain>")
        sys.exit(1)

    # Verify and install dependencies
    check_and_install_dependencies()

    # Prepare domain and output files (Extract domain only, removing "http://" or "https://")
    parsed_domain = urlparse(domain).netloc if "http" in domain else domain

    output_txt = "OsintIA_report.txt"
    output_html = "OsintIA_report.html"

    # Define sections and titles for the index
    sections = {
        "ip-resolution": "IP Resolution",
        "ip-analysis": "IP Analysis with AI",
        "shodan-data": "Shodan Data",
        "shodan-analysis": "Shodan Analysis with AI",
        "whois-info": "WHOIS Information",
        "whois-analysis": "WHOIS Analysis with AI",
        "port-scan": "Port Scanning with NMAP",
        "nmap-analysis": "Nmap Analysis with AI",
        "indexed-links": "Indexed Links with Google Dorks and Photon",
        "links-analysis": "Links Analysis with AI",
        "extracted-metadata": "Extracted Metadata with Metagoofil",
        "metadata-analysis": "Metadata Analysis with AI",
        "found-subdomains": "Found Subdomains with Sublist3r",
        "sublist3r-analysis": "Sublist3r Analysis with AI",
        "detected-technologies": "Detected Technologies",
        "whatweb-analysis": "WhatWeb Analysis with AI",
        "collected-data": "Collected Data with TheHarvester",
        "theharvester-analysis": "TheHarvester Analysis with AI",
        "dnsenum-results": "DNSEnum Results",
        "dnsenum-analysis": "DNSEnum Analysis with AI",
        "final-conclusion": "Final Conclusion",
    }

    with open(output_txt, "w") as txt_file, open(output_html, "w") as html_file:
        html_file.write(f"<html><body><h1>OsintIA_Tools Report for {parsed_domain}</h1>")

        # Add index to the HTML
        html_file.write(generate_html_index(sections))

        # Step 0. IP Resolution with additional checks
        print("[+] Resolving the domain's IP...")
        ip = "Error resolving IP"
        try:
            ip = run_command(f"dig +short {parsed_domain}")
            if not ip:
                ip = run_command(f"ping -c 1 {parsed_domain} | grep 'PING' | awk '{{print $3}}' | tr -d '()'")
            if not ip:
                ip = "IP not resolved"
        except Exception as e:
            print(f"[!] Error resolving IP: {e}")
            ip = "Error resolving IP"

        txt_file.write(f"IP: {ip}\n")
        write_section(html_file, "ip-resolution", "IP Resolution", f"<p>IP: {ip}</p>")

        # AI-based IP Analysis
        print("[+] Analyzing the resolved IP with AI...")
        ip_analysis = call_chatgpt(
            f"Analyze the obtained IP address ({ip}) from a cybersecurity perspective. Identify potential risks."
        )
        formatted_ip_analysis = format_analysis_text(ip_analysis)
        txt_file.write(f"\nAI IP Analysis:\n{ip_analysis}\n")
        write_section(html_file, "ip-analysis", "IP Analysis with AI", formatted_ip_analysis)

        # Step 1. Shodan Query
        if ip != "Error resolving IP" and ip != "IP not resolved":
            print("[+] Querying Shodan data for the IP...")
            try:
                # Adding the 'minify=true' parameter for a lighter response
                shodan_response = requests.get(
                    f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}&minify=true", timeout=10
                )
                if shodan_response.status_code == 200:
                    shodan_result = shodan_response.json()

                    # Save full Shodan response to a JSON file for future reference
                    json_filename = f"shodan_{ip.replace('.', '_')}.json"
                    with open(json_filename, "w") as json_file:
                        json.dump(shodan_result, json_file, indent=4)
                    print(f"[+] Full Shodan data saved to {json_filename}")

                    # Extract and format useful data
                    extracted_data = []
                    extracted_data.append(f"IP: {shodan_result.get('ip_str', 'N/A')}")
                    extracted_data.append(f"Organization: {shodan_result.get('org', 'N/A')}")
                    extracted_data.append(f"ISP: {shodan_result.get('isp', 'N/A')}")
                    extracted_data.append(f"Operating System: {shodan_result.get('os', 'N/A')}")

                    if 'data' in shodan_result:
                        extracted_data.append("\n--- Open Ports and Services ---")
                        for service in shodan_result['data']:
                            port = service.get('port', 'Unknown')
                            product = service.get('product', 'Unknown')
                            version = service.get('version', '')
                            banner = service.get('banner', 'No banner')
                            extracted_data.append(f"Port {port}: {product} {version}\n{banner}")

                    if 'vulns' in shodan_result:
                        extracted_data.append("\n--- Vulnerabilities ---")
                        for vuln in shodan_result['vulns']:
                            extracted_data.append(f"Vulnerability: {vuln}")

                    shodan_result = "\n".join(extracted_data)

                else:
                    shodan_result = f"Shodan returned no results for the IP: {ip}"
            except Exception as e:
                print(f"[!] Error querying Shodan: {e}")
                shodan_result = "Error retrieving Shodan data."
        else:
            shodan_result = "Cannot query Shodan due to IP resolution issues."

        txt_file.write(f"\nShodan Data for IP:\n{shodan_result}\n")
        write_section(html_file, "shodan-data", "Shodan Data", f"<pre>{shodan_result}</pre>")

        # Shodan Analysis with AI
        print("[+] Analyzing Shodan data with AI...")  # Added message for AI analysis
        if "Open Ports and Services" in shodan_result or "Vulnerabilities" in shodan_result:  # Check if there's relevant data
            shodan_analysis = call_chatgpt(
                f"Analyze the following Shodan data for IP {ip} from a cybersecurity perspective:\n{shodan_result}"
            )
            formatted_shodan_analysis = format_analysis_text(shodan_analysis)
        else:
            shodan_analysis = "No relevant data found for Shodan analysis."
            formatted_shodan_analysis = f"<p>{shodan_analysis}</p>"

        txt_file.write(f"\nAI Shodan Analysis:\n{shodan_analysis}\n")
        write_section(html_file, "shodan-analysis", "Shodan Analysis with AI", formatted_shodan_analysis)

        # Step 2. WHOIS with fallback to Amass
        print("[+] Retrieving WHOIS information...")
        whois_info = "WHOIS information not available"
        try:
            whois_info = run_command(f"whois {parsed_domain}")
            if "No match for" in whois_info or not whois_info.strip():
                print("[!] WHOIS returned no results. Trying with Amass...")
                whois_info = run_command(f"amass enum -d {parsed_domain} --timeout 60")
        except Exception as e:
            print(f"[!] Error retrieving WHOIS: {e}")
            whois_info = "Error retrieving WHOIS information."
        
        txt_file.write(f"\nWHOIS Information:\n{whois_info}\n")
        write_section(html_file, "whois-info", "WHOIS Information", f"<pre>{whois_info}</pre>")

        # WHOIS Analysis with AI
        print("[+] Analyzing WHOIS information with AI...")
        whois_analysis = call_chatgpt(
            f"Analyze the WHOIS information from a cybersecurity perspective. Identify vulnerabilities or sensitive data:\n{whois_info}"
        )
        formatted_whois_analysis = format_analysis_text(whois_analysis)
        txt_file.write(f"\nAI WHOIS Analysis:\n{whois_analysis}\n")
        write_section(html_file, "whois-analysis", "WHOIS Analysis with AI", formatted_whois_analysis)

        # Step 3. Port Scanning with Nmap
        print("[+] Scanning open ports with NMAP...")
        try:
            nmap_result = run_command(f"nmap -F {parsed_domain}")
            if not nmap_result.strip():
                nmap_result = "No active hosts found. Check if the domain is online."
        except Exception as e:
            print(f"[!] Error running Nmap: {e}")
            nmap_result = "Error performing port scan."

        txt_file.write(f"\nPort Scan:\n{nmap_result}\n")
        write_section(html_file, "port-scan", "Port Scanning", f"<pre>{nmap_result}</pre>")

        # AI-based Nmap Analysis
        print("[+] Analyzing Nmap results with AI...")
        try:
            nmap_analysis = call_chatgpt(
                f"Analyze the following Nmap results from a cybersecurity perspective:\n{nmap_result}"
            )
            formatted_nmap_analysis = format_analysis_text(nmap_analysis)
        except Exception as e:
            nmap_analysis = f"[!] Error analyzing Nmap results with AI: {e}"
            formatted_nmap_analysis = f"<p>{nmap_analysis}</p>"

        txt_file.write(f"\nAI Nmap Analysis:\n{nmap_analysis}\n")
        write_section(html_file, "nmap-analysis", "Nmap Analysis with AI", formatted_nmap_analysis)

        # Step 4. Indexed Links with Google Dorks and Photon
        print("[+] Retrieving indexed links with Google Dorks and Photon...")
        dorks = [
            f"site:{parsed_domain}",
            f"site:{parsed_domain} filetype:pdf",
            f"site:{parsed_domain} filetype:doc",
            f"site:{parsed_domain} filetype:xls",
            f"site:{parsed_domain} filetype:xlsx",
            f"site:{parsed_domain} filetype:log",
            f"site:{parsed_domain} filetype:bak",
            f"site:{parsed_domain} filetype:conf",
            f"site:{parsed_domain} filetype:env",
            f"site:{parsed_domain} filetype:sql",
            f"site:{parsed_domain} filetype:php",
            f"site:{parsed_domain} filetype:xml",
            f"site:{parsed_domain} filetype:json",
            f"site:{parsed_domain} inurl:login",
            f"site:{parsed_domain} inurl:config",
            f"site:{parsed_domain} inurl:ftp",
            f"site:{parsed_domain} inurl:backup",
            f"site:{parsed_domain} inurl:database",
            f"site:{parsed_domain} \"password\"",
            f"site:{parsed_domain} \"API key\"",
            f"site:{parsed_domain} \"auth_token\"",
            f"site:{parsed_domain} \"aws_access_key_id\"",
            f"site:{parsed_domain} \"private key\"",
            f"site:{parsed_domain} \"error\"",
            f"site:{parsed_domain} \"debug\"",
            f"site:{parsed_domain} \"fatal error\"",
            f"site:{parsed_domain} \"stack trace\"",
            f"site:{parsed_domain} intitle:index.of",
            f"site:{parsed_domain} intitle:\"index of /admin\"",
            f"site:{parsed_domain} intitle:\"index of /private\""
        ]
        all_links = []

        for dork in dorks:
            print(f"[+] Executing Google Dork: {dork}")
            try:
                google_search_url = f"https://www.google.com/search?q={dork}"
                google_response = requests.get(google_search_url, timeout=10)
                soup = BeautifulSoup(google_response.text, "html.parser")
                links = [a["href"] for a in soup.find_all("a", href=True) if "http" in a["href"]]
                all_links.extend(links)
            except Exception as e:
                print(f"[!] Error executing dork {dork}: {e}")

        print("[+] Executing Photon for additional link collection...")
        try:
            photon_command = f"python3 Photon/photon.py -u {parsed_domain} -o photon_output"
            photon_result = run_command(photon_command)
            photon_links = []
            photon_output_path = f"photon_output/{parsed_domain}"
            if os.path.exists(photon_output_path):
                with open(f"{photon_output_path}/urls.txt", "r") as file:
                    photon_links = file.readlines()
                all_links.extend([link.strip() for link in photon_links])
        except Exception as e:
            print(f"[!] Error executing Photon: {e}")

        txt_file.write("\nIndexed Links with Google Dorks and Photon:\n")
        write_section(html_file, "indexed-links", "Indexed Links with Google Dorks and Photon", "<ul>")
        for link in set(all_links):  # Remove duplicates
            txt_file.write(f"{link}\n")
            html_file.write(f"<li><a href='{link}'>{link}</a></li>")
        html_file.write("</ul>")

        # AI-based Links Analysis
        print("[+] Analyzing links and files with AI...")
        links_analysis_input = "\n".join(all_links)
        links_analysis = call_chatgpt(
            f"Analyze the indexed links and their contents to identify vulnerabilities, risks, or sensitive data:\n{links_analysis_input}"
        )
        formatted_links_analysis = format_analysis_text(links_analysis)
        txt_file.write(f"\nAI Links Analysis:\n{links_analysis}\n")
        write_section(html_file, "links-analysis", "Links Analysis with AI", formatted_links_analysis)

# Step 5. Metadata Extraction with Metagoofil
        print("[+] Extracting metadata with Metagoofil...")
        file_types = ["pdf", "txt", "xls", "xlsx", "doc", "docx", "zip"]  # Define file types to search
        metagoofil_results = []

        for file_type in file_types:
            try:
                # Run Metagoofil for each file type separately with a delay
                print(f"[+] Searching for {file_type} files...")
                metagoofil_command = f"metagoofil -d {parsed_domain} -t {file_type} -l 10 -o metagoofil_output"
                #print(f"[DEBUG] Running Metagoofil with command: {metagoofil_command}")

                # Execute the command
                result = run_command(metagoofil_command)
                if not result.strip():  # Check for empty results
                    result = f"[!] No {file_type} metadata found. Try adjusting the parameters or verifying the domain."
                metagoofil_results.append(f"Results for {file_type}:\n{result}")

                # Introduce a delay between searches
                print("[+] Waiting 10 seconds before the next search...")
                time.sleep(10)

            except Exception as e:
                print(f"[!] Error executing Metagoofil for {file_type}: {e}")
                metagoofil_results.append(f"[!] Error retrieving metadata for {file_type} files.")

        # Combine all results
        metagoofil_result = "\n\n".join(metagoofil_results)

        # Write results to report
        txt_file.write(f"\nExtracted Metadata with Metagoofil:\n{metagoofil_result}\n")
        write_section(html_file, "extracted-metadata", "Extracted Metadata with Metagoofil", f"<pre>{metagoofil_result}</pre>")

        # Metadata Analysis with AI
        print("[+] Analyzing metadata with AI...")
        metadatos_analysis = call_chatgpt(
            f"Analyze the metadata extracted by Metagoofil from a cybersecurity perspective:\n{metagoofil_result}"
        )
        formatted_metadatos_analysis = format_analysis_text(metadatos_analysis)
        txt_file.write(f"\nAI Metadata Analysis:\n{metadatos_analysis}\n")
        write_section(html_file, "metadata-analysis", "Metadata Analysis with AI", formatted_metadatos_analysis)

        # Step 6. Sublist3r
        print("[+] Running Sublist3r for subdomains...")
        try:
            sublist3r_result = run_command(f"sublist3r -d {parsed_domain}")
            cleaned_sublist3r_result = remove_ansi_escape_sequences(sublist3r_result)
        except Exception as e:
            cleaned_sublist3r_result = f"[!] Error running Sublist3r: {e}"

        txt_file.write(f"\nFound Subdomains (Sublist3r):\n{cleaned_sublist3r_result}\n")
        write_section(html_file, "found-subdomains", "Found Subdomains with Sublist3r", f"<pre>{cleaned_sublist3r_result}</pre>")

        # Sublist3r Analysis with AI
        print("[+] Analyzing subdomains with AI...")
        sublist3r_analysis = call_chatgpt(
            f"Analyze the subdomains found by Sublist3r from a cybersecurity perspective. Identify potential risks:\n{cleaned_sublist3r_result}"
        )
        formatted_sublist3r_analysis = format_analysis_text(sublist3r_analysis)
        txt_file.write(f"\nAI Sublist3r Analysis:\n{sublist3r_analysis}\n")
        write_section(html_file, "sublist3r-analysis", "Sublist3r Analysis with AI", formatted_sublist3r_analysis)

        # Step 7. WhatWeb
        print("[+] Detecting technologies with WhatWeb...")
        try:
            whatweb_result = run_command(f"whatweb {parsed_domain}")
            cleaned_whatweb_result = remove_ansi_escape_sequences(whatweb_result)
        except Exception as e:
            cleaned_whatweb_result = f"[!] Error running WhatWeb: {e}"
        
        txt_file.write(f"\nDetected Technologies:\n{cleaned_whatweb_result}\n")
        write_section(html_file, "detected-technologies", "Detected Technologies", f"<pre>{cleaned_whatweb_result}</pre>")

        # WhatWeb Analysis with AI
        print("[+] Analyzing detected technologies with AI...")
        whatweb_analysis = call_chatgpt(
            f"Analyze the technologies detected by WhatWeb from a cybersecurity perspective. Identify potential vulnerabilities:\n{cleaned_whatweb_result}"
        )
        formatted_whatweb_analysis = format_analysis_text(whatweb_analysis)
        txt_file.write(f"\nAI WhatWeb Analysis:\n{whatweb_analysis}\n")
        write_section(html_file, "whatweb-analysis", "WhatWeb Analysis with AI", formatted_whatweb_analysis)

        # Step 8. TheHarvester
        print("[+] Collecting data with TheHarvester...")
        try:
            theharvester_command = f"theHarvester -d {parsed_domain} -b bing,crtsh,certspotter,duckduckgo"
            theharvester_result = run_command(theharvester_command)

            # Verify if no results were found
            if not theharvester_result.strip():
                theharvester_result = "[!] No data found with TheHarvester. Check the domain or sources."

        except Exception as e:
            theharvester_result = f"[!] Error running TheHarvester: {e}"

        # Clean ANSI characters for better readability
        cleaned_theharvester_result = remove_ansi_escape_sequences(theharvester_result)

        # Save results in reports
        txt_file.write(f"\nCollected Data (TheHarvester):\n{cleaned_theharvester_result}\n")
        write_section(html_file, "collected-data", "Collected Data with TheHarvester", f"<pre>{cleaned_theharvester_result}</pre>")

        # TheHarvester Analysis with AI
        print("[+] Analyzing data collected by TheHarvester with AI...")
        try:
            theharvester_analysis = call_chatgpt(
                f"Analyze the data collected by TheHarvester from a cybersecurity perspective. Identify risks or sensitive data:\n{cleaned_theharvester_result}"
            )
            formatted_theharvester_analysis = format_analysis_text(theharvester_analysis)
        except Exception as e:
            theharvester_analysis = f"[!] Error analyzing data collected by TheHarvester with AI: {e}"
            formatted_theharvester_analysis = f"<p>{theharvester_analysis}</p>"

        # Save analysis in reports
        txt_file.write(f"\nAI TheHarvester Analysis:\n{theharvester_analysis}\n")
        write_section(html_file, "theharvester-analysis", "TheHarvester Analysis with AI", formatted_theharvester_analysis)

        # Step 9. DNSEnum
        print("[+] Running DNSEnum...")
        try:
            dnsenum_command = (
                f"dnsenum --dnsserver 8.8.8.8 --dnsserver 1.1.1.1 "
                f"--timeout 3 --threads 15 {parsed_domain}"
            )

            dnsenum_result = run_command(dnsenum_command)
            cleaned_dnsenum_result = remove_ansi_escape_sequences(dnsenum_result)
        except Exception as e:
            cleaned_dnsenum_result = f"[!] Error running DNSEnum: {e}"

        txt_file.write(f"\nCollected Data (DNSEnum):\n{cleaned_dnsenum_result}\n")
        write_section(html_file, "dnsenum-results", "DNSEnum Results", f"<pre>{cleaned_dnsenum_result}</pre>")

        # DNSEnum Analysis with AI
        print("[+] Analyzing data collected by DNSEnum with AI...")
        dnsenum_analysis = call_chatgpt(
            f"Analyze the data collected by DNSEnum from a cybersecurity perspective. Identify potential vulnerabilities:\n{cleaned_dnsenum_result}"
        )
        formatted_dnsenum_analysis = format_analysis_text(dnsenum_analysis)

        txt_file.write(f"\nAI DNSEnum Analysis:\n{dnsenum_analysis}\n")
        write_section(html_file, "dnsenum-analysis", "DNSEnum Analysis with AI", formatted_dnsenum_analysis)

        # Final Conclusion
        print("[+] Generating final conclusion with AI...")
        with open(output_txt, "r") as report_file:
            full_report = report_file.read()

        # Detailed prompt to include summary and recommendations
        conclusion_prompt = (
            "Based on the full report of the tools used in the cybersecurity analysis, perform the following:\n\n"
            "1. Summarize the key findings of each tool used:\n"
            "   - IP resolution\n"
            "   - Shodan\n"
            "   - WHOIS\n"
            "   - Nmap\n"
            "   - Dork\n"
            "   - Metagoofil\n"
            "   - Sublist3r\n"
            "   - WhatWeb\n"
            "   - TheHarvester\n"
            "   - DNSEnum\n"
            "2. Identify the most critical risks found and explain how they could affect the analyzed domain.\n"
            "3. Provide specific recommendations to mitigate each identified risk.\n"
            "4. Organize recommendations by priority (high, medium, low) based on impact and likelihood.\n"
            "5. Suggest best practices and specific tools to strengthen the domain's security.\n\n"
            "6. Generate a conceptual and conclusive text about everything found by the tools, highlighting the importance of having this information and how it can help in website security analysis.\n\n"
            f"Full report:\n{full_report}"
        )

        # Call API to generate the conclusion
        try:
            conclusion = call_chatgpt(conclusion_prompt)
            # Clean characters like "**" before formatting
            clean_conclusion = conclusion.replace("**", "")
            formatted_conclusion = format_analysis_text(clean_conclusion)
        except Exception as e:
            conclusion = f"[!] Error generating final conclusion with AI: {e}"
            formatted_conclusion = f"<p>{conclusion}</p>"

        # Save conclusion in reports
        txt_file.write(f"\nFinal Conclusion:\n{conclusion}\n")
        write_section(html_file, "final-conclusion", "Final Conclusion", formatted_conclusion)

        print(f"Reports saved in {output_txt} and {output_html}")

if __name__ == "__main__":
    domain = sys.argv[1] if len(sys.argv) > 1 else None
    main(domain)
