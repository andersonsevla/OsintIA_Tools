#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
OsintIA_Tools v4.3 - Authorized OSINT, Web Security and Adaptive Auth Testing Assistant

Uso recomendado:
  export OPENAI_API_KEY="sua_chave"
  export SHODAN_API_KEY="sua_chave"

  python3 OsintIA_Tools_v4_3.py example.com --mode passive
  python3 OsintIA_Tools_v4_3.py example.com --mode active --i-have-authorization
  python3 OsintIA_Tools_v4_3.py example.com --mode aggressive --i-have-authorization --scheme https

Novidades v4.3:
  - Mantém todos os recursos da v4.2.
  - Adiciona relatório profissional em Markdown (.md).
  - Melhora a análise final com IA em formato consultivo.
  - Adiciona --load-engine none|siege|k6|both.
  - Melhora Siege com múltiplas URLs, perfis progressivos e parsing de métricas.
  - Adiciona k6 como teste avançado com script JS gerado automaticamente, thresholds e múltiplos endpoints.
  - Adiciona módulo adaptativo de autenticação:
      * Descobre páginas comuns de login.
      * Detecta formulários HTML com campos de senha.
      * Identifica campos prováveis de usuário/e-mail e senha.
      * Executa teste controlado de credenciais fracas apenas com lista pequena.
      * Detecta sinais básicos de rate limit, lockout e diferença de respostas.
      * Executa SQLMap direcionado ao login quando um formulário é encontrado.
      * Pula o módulo sem quebrar caso não exista login.
  - Mantém SQLMap sem dump/exfiltração por padrão.
  - Mantém Siege controlado e opcional pelo modo aggressive.

Aviso:
  Use active/aggressive somente em ambientes próprios ou formalmente autorizados.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, UTC
from pathlib import Path
from urllib.parse import quote_plus, urljoin, urlparse

import requests
from bs4 import BeautifulSoup


VERSION = "4.3"

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
OPENAI_URL = "https://api.openai.com/v1/responses"

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0 Safari/537.36"
)

COMMAND_DEPENDENCIES = [
    "dig",
    "whois",
    "nmap",
    "wget",
    "exiftool",
    "amass",
    "sublist3r",
    "whatweb",
    "theHarvester",
    "dnsenum",
    "python3",
    "metagoofil",
    "ffuf",
    "nikto",
    "sqlmap",
    "siege",
    "k6",
]

APT_PACKAGE_MAP = {
    "dig": "dnsutils",
    "whois": "whois",
    "nmap": "nmap",
    "wget": "wget",
    "exiftool": "libimage-exiftool-perl",
    "amass": "amass",
    "sublist3r": "sublist3r",
    "whatweb": "whatweb",
    "theHarvester": "theharvester",
    "dnsenum": "dnsenum",
    "python3": "python3",
    "metagoofil": "metagoofil",
    "ffuf": "ffuf",
    "nikto": "nikto",
    "sqlmap": "sqlmap",
    "siege": "siege",
    "k6": "k6",
}


def print_header():
    header = rf"""
*******************************************************************
*     ___      _       _   ___    _      _____           _        *
*    / _ \ ___(_)_ __ | |_|_ _|  / \    |_   _|__   ___ | |___    *
*   | | | / __| | '_ \| __|| |  / _ \     | |/ _ \ / _ \| / __|   *
*   | |_| \__ \ | | | | |_ | | / ___ \    | | (_) | (_) | \__ \   *
*    \___/|___/_|_| |_|\__|___/_/   \_\   |_|\___/ \___/|_|___/   *
*                                                                 *
* OsintIA_Tools {VERSION:<48}*
* Coded by Anderson Alves                                         *
* Cybersecurity Research                                          *
*******************************************************************
"""
    print(header)


def sanitize_domain(value: str) -> str:
    parsed = urlparse(value if "://" in value else f"https://{value}")
    hostname = parsed.hostname or value
    hostname = hostname.strip().lower()

    if not re.fullmatch(r"[a-zA-Z0-9.-]+", hostname):
        raise ValueError(f"Invalid domain/hostname: {hostname}")

    if hostname.startswith("-") or ".." in hostname:
        raise ValueError(f"Suspicious domain/hostname: {hostname}")

    return hostname


def ensure_dir(path: Path):
    path.mkdir(parents=True, exist_ok=True)


def run_command(command, timeout=300, cwd=None):
    started = time.time()
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            cwd=cwd,
        )
        elapsed = round(time.time() - started, 2)

        output = result.stdout.strip()
        error = result.stderr.strip()

        combined = []
        combined.append(f"$ {' '.join(command)}")
        combined.append(f"[exit_code={result.returncode}] [elapsed={elapsed}s]")
        if output:
            combined.append(output)
        if error:
            combined.append("\n[stderr]\n" + error)
        return "\n".join(combined).strip()

    except subprocess.TimeoutExpired:
        return f"$ {' '.join(command)}\n[!] Command timed out after {timeout}s"
    except FileNotFoundError:
        return f"$ {' '.join(command)}\n[!] Command not found: {command[0]}"
    except Exception as exc:
        return f"$ {' '.join(command)}\n[!] Error executing command: {exc}"


def check_and_install_dependencies(auto_install=False):
    print("[+] Checking dependencies...")
    missing = [dep for dep in COMMAND_DEPENDENCIES if shutil.which(dep) is None]

    photon_path = Path("Photon/photon.py")
    if not photon_path.exists():
        missing.append("Photon/photon.py")

    if not missing:
        print("[+] All required dependencies appear to be available.")
        return

    print(f"[!] Missing dependencies: {', '.join(missing)}")

    if "Photon/photon.py" in missing:
        print("[!] Photon is missing. Install it with:")
        print("    git clone https://github.com/s0md3v/Photon.git")

    if not auto_install:
        print("[!] Auto-install disabled. Use --install-deps to install APT packages.")
        return

    if os.geteuid() != 0:
        print("[!] Root privileges are required to install dependencies. Re-run with sudo or install manually.")
        sys.exit(1)

    apt_packages = sorted({
        APT_PACKAGE_MAP[dep] for dep in missing if dep in APT_PACKAGE_MAP
    })

    if apt_packages:
        print("[+] Installing missing APT packages...")
        install_log = Path("install.log")
        with install_log.open("a", encoding="utf-8") as log:
            subprocess.run(["apt", "update"], stdout=log, stderr=log, text=True)
            subprocess.run(["apt", "install", "-y", *apt_packages], stdout=log, stderr=log, text=True)
        print(f"[+] Installation attempted. Check {install_log} if something failed.")


def remove_ansi_escape_sequences(text):
    ansi_escape = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
    return ansi_escape.sub("", text or "")


def html_escape(text):
    return (
        (text or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def format_analysis_text(text):
    paragraphs = (text or "").split("\n")
    return "".join(
        f"<p>{html_escape(paragraph.strip())}</p>"
        for paragraph in paragraphs
        if paragraph.strip()
    )


def generate_html_index(sections):
    index_html = "<h2>Index</h2><ul>"
    for section_id, section_name in sections.items():
        index_html += f"<li><a href='#{section_id}'>{html_escape(section_name)}</a></li>"
    index_html += "</ul>"
    return index_html


def write_section(html_file, section_id, title, content):
    html_file.write(f"<h2 id='{section_id}'>{html_escape(title)}</h2>{content}\n")


def write_pre_section(html_file, section_id, title, content):
    write_section(html_file, section_id, title, f"<pre>{html_escape(content)}</pre>")


def write_text_block(txt_file, title, content):
    txt_file.write(f"\n\n{'=' * 80}\n{title}\n{'=' * 80}\n{content}\n")


def call_chatgpt(prompt, timeout=60, max_output_tokens=2500):
    if not OPENAI_API_KEY:
        return "AI analysis skipped: OPENAI_API_KEY environment variable is not set."

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {OPENAI_API_KEY}",
    }

    payload = {
        "model": OPENAI_MODEL,
        "input": prompt,
        "max_output_tokens": max_output_tokens,
    }

    for attempt in range(1, 4):
        try:
            time.sleep(2)
            response = requests.post(
                OPENAI_URL,
                headers=headers,
                json=payload,
                timeout=timeout,
            )
            response.raise_for_status()
            data = response.json()
            return data["output"][0]["content"][0]["text"].strip()

        except requests.exceptions.HTTPError as exc:
            body = ""
            try:
                body = response.text[:800]
            except Exception:
                pass
            print(f"[!] OpenAI HTTP error attempt {attempt}: {exc} {body}")
            if attempt == 3:
                return f"AI analysis failed: {exc}. Response: {body}"

        except requests.exceptions.RequestException as exc:
            print(f"[!] OpenAI request error attempt {attempt}: {exc}")
            if attempt == 3:
                return f"AI analysis failed: {exc}"

        except Exception as exc:
            print(f"[!] OpenAI parsing error attempt {attempt}: {exc}")
            if attempt == 3:
                return f"AI analysis failed while parsing response: {exc}"

        time.sleep(2 ** attempt)

    return "AI analysis failed after multiple attempts."


def summarize_with_ai(title, raw_text, max_chars=12000):
    trimmed = (raw_text or "")[:max_chars]
    prompt = f"""
You are a cybersecurity analyst. Analyze the following results from {title}.

Return:
1. Key findings.
2. Potential security risks.
3. False positive considerations.
4. Recommended remediation actions.
5. Priority: High, Medium, or Low.

Results:
{trimmed}
"""
    return call_chatgpt(prompt)


def make_session():
    session = requests.Session()
    session.headers.update({"User-Agent": DEFAULT_USER_AGENT})
    return session


def resolve_ip(domain):
    print("[+] Resolving domain IP...")
    result = run_command(["dig", "+short", domain], timeout=30)
    ips = []
    for line in result.splitlines():
        line = line.strip()
        if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", line) or ":" in line:
            if not line.startswith("$") and not line.startswith("["):
                ips.append(line)

    if ips:
        return "\n".join(ips), result

    ping_result = run_command(["ping", "-c", "1", domain], timeout=15)
    match = re.search(r"\(([^)]+)\)", ping_result)
    if match:
        return match.group(1), result + "\n\n" + ping_result

    return "IP not resolved", result + "\n\n" + ping_result


def query_shodan(ip):
    if not SHODAN_API_KEY:
        return "Shodan query skipped: SHODAN_API_KEY environment variable is not set."

    first_ip = ip.splitlines()[0].strip()
    if not re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", first_ip):
        return f"Shodan query skipped: invalid or unresolved IPv4 address: {first_ip}"

    print("[+] Querying Shodan...")
    try:
        response = requests.get(
            f"https://api.shodan.io/shodan/host/{first_ip}",
            params={"key": SHODAN_API_KEY},
            timeout=30,
        )

        if response.status_code == 403:
            return (
                "[!] Shodan returned HTTP 403: your current Shodan plan/API key "
                "does not allow this host lookup or requires Membership+. "
                "Continuing with local recon tools such as Nmap, WhatWeb, FFUF and Nikto."
            )

        if response.status_code == 401:
            return (
                "[!] Shodan returned HTTP 401: invalid or unauthorized API key. "
                "Check SHODAN_API_KEY."
            )

        if response.status_code == 429:
            return (
                "[!] Shodan returned HTTP 429: API rate limit exceeded. "
                "Try again later or reduce Shodan usage."
            )

        if response.status_code != 200:
            return f"Shodan returned HTTP {response.status_code}: {response.text[:500]}"

        data = response.json()

        json_filename = f"shodan_{first_ip.replace('.', '_')}.json"
        with open(json_filename, "w", encoding="utf-8") as json_file:
            json.dump(data, json_file, indent=2)
        print(f"[+] Full Shodan data saved to {json_filename}")

        extracted = [
            f"IP: {data.get('ip_str', first_ip)}",
            f"Organization: {data.get('org', 'N/A')}",
            f"ISP: {data.get('isp', 'N/A')}",
            f"Operating System: {data.get('os', 'N/A')}",
            f"Country: {data.get('country_name', 'N/A')}",
            f"City: {data.get('city', 'N/A')}",
        ]

        # Free/limited accounts may return reduced or no service data.
        services = data.get("data", [])
        if services:
            extracted.append("\n--- Open Ports and Services ---")
            for service in services[:20]:
                port = service.get("port", "Unknown")
                product = service.get("product", "Unknown")
                version = service.get("version", "")
                transport = service.get("transport", "")
                banner = service.get("data", service.get("banner", "No banner"))
                banner = str(banner)[:1000]
                extracted.append(f"Port {port}/{transport}: {product} {version}\n{banner}")
        else:
            extracted.append(
                "\n--- Open Ports and Services ---\n"
                "No detailed service data returned by Shodan. "
                "This may be normal for a limited/free API plan."
            )

        vulns = data.get("vulns", [])
        if vulns:
            extracted.append("\n--- Vulnerabilities ---")
            for vuln in list(vulns)[:30]:
                extracted.append(f"Vulnerability: {vuln}")
        else:
            extracted.append(
                "\n--- Vulnerabilities ---\n"
                "No vulnerability data returned by Shodan."
            )

        return "\n".join(extracted)

    except requests.exceptions.RequestException as exc:
        return f"Error retrieving Shodan data: {exc}"
    except Exception as exc:
        return f"Error processing Shodan data: {exc}"


def run_whois(domain):
    print("[+] Retrieving WHOIS information...")
    whois_info = run_command(["whois", domain], timeout=90)
    if "No match for" in whois_info or not whois_info.strip():
        print("[!] WHOIS returned no clear results. Trying Amass passive enum...")
        amass_info = run_command(["amass", "enum", "-passive", "-d", domain, "-timeout", "60"], timeout=120)
        return whois_info + "\n\n--- Amass passive fallback ---\n" + amass_info
    return whois_info


def build_nmap_command(domain, mode):
    if mode == "passive":
        return ["nmap", "-Pn", "-sV", "--top-ports", "100", "--open", "-T2", domain]

    if mode == "active":
        return [
            "nmap", "-Pn", "-sV", "-sC", "--top-ports", "1000",
            "--open", "--reason", "-T3", domain
        ]

    return [
        "nmap", "-Pn", "-sS", "-sV", "-sC", "-O", "-A",
        "--top-ports", "3000", "--open", "--reason",
        "--traceroute", "-T4", "-oA", f"nmap_{domain}", domain
    ]


def run_nmap(domain, mode):
    print(f"[+] Running Nmap scan [{mode}]...")
    timeout = 300 if mode == "passive" else 900 if mode == "active" else 1800
    return run_command(build_nmap_command(domain, mode), timeout=timeout)


def run_google_dorks(domain):
    print("[+] Running Google dorks collection...")
    dorks = [
        f"site:{domain}",
        f"site:{domain} filetype:pdf",
        f"site:{domain} filetype:doc",
        f"site:{domain} filetype:xls",
        f"site:{domain} filetype:xlsx",
        f"site:{domain} filetype:log",
        f"site:{domain} filetype:bak",
        f"site:{domain} filetype:conf",
        f"site:{domain} filetype:env",
        f"site:{domain} filetype:sql",
        f"site:{domain} filetype:php",
        f"site:{domain} filetype:xml",
        f"site:{domain} filetype:json",
        f"site:{domain} inurl:login",
        f"site:{domain} inurl:signin",
        f"site:{domain} inurl:auth",
        f"site:{domain} inurl:config",
        f"site:{domain} inurl:ftp",
        f"site:{domain} inurl:backup",
        f"site:{domain} inurl:database",
        f"site:{domain} \"password\"",
        f"site:{domain} \"API key\"",
        f"site:{domain} \"auth_token\"",
        f"site:{domain} \"aws_access_key_id\"",
        f"site:{domain} \"private key\"",
        f"site:{domain} \"error\"",
        f"site:{domain} \"debug\"",
        f"site:{domain} \"fatal error\"",
        f"site:{domain} \"stack trace\"",
        f"site:{domain} intitle:index.of",
        f"site:{domain} intitle:\"index of /admin\"",
        f"site:{domain} intitle:\"index of /private\"",
    ]

    all_links = []
    session = make_session()

    for dork in dorks:
        print(f"[+] Dork: {dork}")
        try:
            url = f"https://www.google.com/search?q={quote_plus(dork)}"
            response = session.get(url, timeout=15)
            soup = BeautifulSoup(response.text, "html.parser")
            links = [
                a.get("href")
                for a in soup.find_all("a", href=True)
                if "http" in a.get("href", "")
            ]
            all_links.extend(links)
            time.sleep(2)
        except Exception as exc:
            all_links.append(f"[!] Error executing dork {dork}: {exc}")

    unique_links = sorted(set(all_links))
    return "\n".join(unique_links)


def run_photon(domain, scheme="https"):
    print("[+] Running Photon...")
    photon_script = Path("Photon/photon.py")
    if not photon_script.exists():
        return "Photon skipped: Photon/photon.py not found. Run: git clone https://github.com/s0md3v/Photon.git"

    target_url = f"{scheme}://{domain}"
    output_dir = Path("photon_output")

    result = run_command(
        [
            "python3",
            str(photon_script),
            "-u",
            target_url,
            "-o",
            str(output_dir),
            "-l",
            "3",
            "-t",
            "10",
        ],
        timeout=900,
    )

    urls_file_candidates = [
        output_dir / domain / "urls.txt",
        output_dir / target_url.replace("://", "_").replace("/", "_") / "urls.txt",
    ]

    for urls_file in urls_file_candidates:
        if urls_file.exists():
            urls = urls_file.read_text(encoding="utf-8", errors="ignore")
            return result + "\n\n--- Photon URLs ---\n" + urls

    return remove_ansi_escape_sequences(result)


def run_metagoofil(domain):
    print("[+] Extracting metadata with Metagoofil...")

    # Ordem otimizada: começa pelos formatos mais prováveis/úteis
    file_types = ["pdf", "docx", "xlsx", "doc", "xls"]

    results = []
    output_dir = "metagoofil_output"

    for index, file_type in enumerate(file_types, start=1):
        print(f"[+] Metagoofil filetype: {file_type}")

        command = [
            "metagoofil",
            "-d", domain,
            "-t", file_type,
            "-l", "3",
            "-w",
            "-o", output_dir,
        ]

        result = run_command(command, timeout=180)

        results.append(f"--- Results for {file_type} ---\n{result}")

        if "HTTP Error 429" in result or "Too Many Requests" in result:
            results.append(
                "\n[!] Metagoofil stopped early: Google returned HTTP 429 Too Many Requests.\n"
                "[!] Recommendation: wait and retry later, reduce file types, or run Metagoofil separately."
            )
            break

        # Delay maior entre buscas para reduzir chance de bloqueio
        if index < len(file_types):
            print("[+] Waiting 60 seconds before next Metagoofil search...")
            time.sleep(60)

    return "\n\n".join(results)


def run_sublist3r(domain):
    print("[+] Running Sublist3r...")

    command = [
        "sublist3r",
        "-d", domain,
        "-e", "baidu,yahoo,bing,ask,netcraft,ssl,passivedns",
    ]

    result = run_command(command, timeout=600)
    clean_result = remove_ansi_escape_sequences(result)

    error_indicators = [
        "DNSdumpster",
        "Virustotal probably now is blocking",
        "Google probably now is blocking",
        "IndexError: list index out of range",
        "Traceback",
    ]

    if any(error in clean_result for error in error_indicators):
        print("[!] Sublist3r had source errors. Running Amass passive fallback...")
        amass_result = run_command(
            ["amass", "enum", "-passive", "-d", domain, "-timeout", "120"],
            timeout=180,
        )

        clean_result += (
            "\n\n[!] Sublist3r warning: some sources failed or blocked requests."
            "\n\n--- Amass Passive Fallback ---\n"
            + remove_ansi_escape_sequences(amass_result)
        )

    return clean_result


def run_whatweb(domain, scheme):
    print("[+] Running WhatWeb...")
    result = run_command(["whatweb", f"{scheme}://{domain}"], timeout=180)
    return remove_ansi_escape_sequences(result)


def run_theharvester(domain):
    print("[+] Running theHarvester...")
    return remove_ansi_escape_sequences(
        run_command(
            ["theHarvester", "-d", domain, "-b", "bing,crtsh,certspotter,duckduckgo"],
            timeout=600,
        )
    )


def run_dnsenum(domain):
    print("[+] Running DNSEnum...")
    command = [
        "dnsenum",
        "--dnsserver", "8.8.8.8",
        "--dnsserver", "1.1.1.1",
        "--timeout", "3",
        "--threads", "15",
        domain,
    ]
    return remove_ansi_escape_sequences(run_command(command, timeout=900))


def run_ffuf(domain, scheme, rate, threads, wordlist):
    print("[+] Running FFUF content discovery...")
    if not Path(wordlist).exists():
        return f"FFUF skipped: wordlist not found: {wordlist}"

    target_url = f"{scheme}://{domain}/FUZZ"
    output_file = f"ffuf_{domain}.json"

    command = [
        "ffuf",
        "-u", target_url,
        "-w", wordlist,
        "-mc", "200,204,301,302,307,308,401,403",
        "-rate", str(rate),
        "-t", str(threads),
        "-of", "json",
        "-o", output_file,
    ]
    result = run_command(command, timeout=1200)

    if Path(output_file).exists():
        try:
            data = json.loads(Path(output_file).read_text(encoding="utf-8", errors="ignore"))
            findings = data.get("results", [])
            lines = [f"FFUF JSON output saved to {output_file}", f"Findings: {len(findings)}"]
            for item in findings[:200]:
                lines.append(
                    f"{item.get('status')} {item.get('length')} bytes "
                    f"{item.get('url')}"
                )
            return result + "\n\n--- Parsed FFUF findings ---\n" + "\n".join(lines)
        except Exception:
            return result + f"\n\nFFUF JSON output saved to {output_file}"

    return result


def run_nikto(domain, scheme):
    print("[+] Running Nikto web scan...")
    target = f"{scheme}://{domain}"

    command = [
    	"nikto",
    	"-h", target,
    	"-nointeractive",
    	"-Tuning", "1234567890abc",
    	"-timeout", "20",
    	"-maxtime", "60m",
    	"-useragent", DEFAULT_USER_AGENT,
    	"-no404",
    ]

    result = run_command(command, timeout=3600)
    
    if "Error limit" in result and "item(s) reported" in result:
        return (
            result
            + "\n\n[!] Nikto note: scan stopped after reaching Nikto's internal error limit, "
              "but findings were reported before termination. Treat as a partial successful scan. "
              "This commonly occurs behind CDN/WAF services such as Cloudflare."
        )

    if "SSL negotiation failed" in result:
        return (
            result
            + "\n\n[!] Nikto note: SSL negotiation failures were observed. "
              "This may be caused by CDN/WAF behavior, HTTP/3 advertisement, TLS policy, "
              "or multiple resolved IPs behind the target hostname."
        )

    if "Command timed out" in result:
        return (
            result
            + "\n\n[!] Nikto timed out at the Python script level. "
              "Increase run_command timeout if you need a full scan."
        )

    return result


def run_sqlmap_controlled(domain, scheme, crawl_depth):
    print("[+] Running SQLMap controlled scan...")
    target = f"{scheme}://{domain}/"
    command = [
        "sqlmap",
        "-u", target,
        "--batch",
        "--crawl=2",
        "--level=2",
        "--risk=1",
        "--random-agent",
        "--forms",
        "--smart",
        "--threads=3",
        "--answers=threads=3,sitemap=N",
        "--output-dir=sqlmap_output",
    ]
    
    result = run_command(command, timeout=600)

    if "no usable links found" in result:
        return (
            result +
            "\n\n[!] SQLMap note: No injectable parameters or forms were discovered. "
            "This is common in modern applications (SPA / authenticated apps). "
            "Consider authenticated testing or manual request injection."
        )

    return result


def run_sqlmap_login_form(login_url, crawl_depth=1):
    print("[+] Running SQLMap against detected login form in controlled mode...")

    command = [
        "sqlmap",
        "-u", login_url,
        "--batch",
        f"--crawl={crawl_depth}",
        "--level=2",
        "--risk=1",
        "--random-agent",
        "--forms",
        "--smart",
        "--threads=3",
        "--answers=threads=3,sitemap=N",
        "--output-dir=sqlmap_login_output",
    ]

    result = run_command(command, timeout=600)

    if "no usable forms found" in result or "no usable links found" in result:
        return (
            result +
            "\n\n[!] SQLMap note: No injectable forms detected at the login endpoint. "
            "This is expected in modern applications using APIs or protected authentication flows."
        )

    if "heuristic (basic) test shows that" in result and "might not be injectable" in result:
        result += (
            "\n\n[!] SQLMap note: Parameters were tested but no injection vectors were confirmed. "
            "False positives are unlikely."
        )

    return result


def normalize_url_for_target(url, domain, scheme):
    """
    Keep only same-domain URLs and normalize relative paths.
    """
    if not url:
        return None

    url = url.strip()
    if not url or url.startswith("[!]") or url.startswith("$"):
        return None

    if url.startswith("/"):
        return f"{scheme}://{domain}{url}"

    if url.startswith("http://") or url.startswith("https://"):
        parsed = urlparse(url)
        if parsed.hostname and parsed.hostname.lower() == domain.lower():
            return url.split("#")[0]
        return None

    return None


def extract_candidate_urls(domain, scheme, *sources, max_urls=30):
    """
    Extract target URLs from tool outputs. Falls back to common paths.
    """
    urls = {f"{scheme}://{domain}/"}

    common_paths = [
        "/login",
        "/signin",
        "/auth/login",
        "/admin",
        "/api",
        "/health",
        "/status",
    ]

    for path in common_paths:
        urls.add(f"{scheme}://{domain}{path}")

    url_regex = re.compile(r"https?://[^\s\"\'<>]+")
    for source in sources:
        for match in url_regex.findall(source or ""):
            normalized = normalize_url_for_target(match, domain, scheme)
            if normalized:
                urls.add(normalized)

    clean_urls = []
    for url in sorted(urls):
        if re.search(r"\.(png|jpg|jpeg|gif|svg|css|js|ico|woff|woff2|ttf|map)(\?|$)", url, re.I):
            continue
        clean_urls.append(url)

    return clean_urls[:max_urls]


def write_urls_file(report_dir, urls, filename="load_test_urls.txt"):
    path = report_dir / filename
    path.write_text("\n".join(urls) + "\n", encoding="utf-8")
    return path


def parse_siege_metrics(output):
    metrics = {}
    patterns = {
        "transactions": r"Transactions:\s+([\d.]+)",
        "availability": r"Availability:\s+([\d.]+)\s*%",
        "elapsed_time": r"Elapsed time:\s+([\d.]+)\s*secs",
        "data_transferred": r"Data transferred:\s+([\d.]+)\s*MB",
        "response_time": r"Response time:\s+([\d.]+)\s*secs",
        "transaction_rate": r"Transaction rate:\s+([\d.]+)\s*trans/sec",
        "throughput": r"Throughput:\s+([\d.]+)\s*MB/sec",
        "concurrency": r"Concurrency:\s+([\d.]+)",
        "successful_transactions": r"Successful transactions:\s+([\d.]+)",
        "failed_transactions": r"Failed transactions:\s+([\d.]+)",
        "longest_transaction": r"Longest transaction:\s+([\d.]+)",
        "shortest_transaction": r"Shortest transaction:\s+([\d.]+)",
    }

    for key, pattern in patterns.items():
        match = re.search(pattern, output or "", re.I)
        if match:
            metrics[key] = match.group(1)

    if not metrics:
        return "No Siege metrics parsed."

    lines = ["--- Parsed Siege Metrics ---"]
    for key, value in metrics.items():
        lines.append(f"{key}: {value}")
    return "\n".join(lines)


def run_siege_profile(urls_file, concurrency, duration, delay=1):
    command = [
        "siege",
        f"-c{concurrency}",
        f"-t{duration}",
        f"-d{delay}",
        "-f",
        str(urls_file),
    ]
    output = run_command(command, timeout=900)
    return output + "\n\n" + parse_siege_metrics(output)


def run_siege_advanced(domain, scheme, report_dir, urls, max_profile="medium"):
    print("[+] Running improved controlled Siege load test...")

    if not urls:
        urls = [f"{scheme}://{domain}/"]

    urls_file = write_urls_file(report_dir, urls, "siege_urls.txt")

    profiles = [
        {"name": "light", "concurrency": 5, "duration": "30S", "delay": 1},
        {"name": "medium", "concurrency": 10, "duration": "1M", "delay": 1},
        {"name": "high", "concurrency": 20, "duration": "2M", "delay": 1},
    ]

    allowed = []
    for profile in profiles:
        allowed.append(profile)
        if profile["name"] == max_profile:
            break

    results = [
        f"Siege URLs file: {urls_file}",
        f"URLs tested: {len(urls)}",
        "\n".join(f"- {url}" for url in urls),
    ]

    for profile in allowed:
        results.append(
            f"\n\n=== Siege profile: {profile['name']} "
            f"(c={profile['concurrency']}, t={profile['duration']}, d={profile['delay']}) ==="
        )
        results.append(
            run_siege_profile(
                urls_file=urls_file,
                concurrency=profile["concurrency"],
                duration=profile["duration"],
                delay=profile["delay"],
            )
        )

    return "\n".join(results)


def generate_k6_script(domain, scheme, report_dir, urls, vus=10, duration="1m"):
    print("[+] Generating k6 advanced load test script...")

    if not urls:
        urls = [f"{scheme}://{domain}/"]

    urls_js = json.dumps(urls[:30], indent=2)

    script = """import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  vus: __VUS__,
  duration: '__DURATION__',
  thresholds: {
    http_req_failed: ['rate<0.05'],
    http_req_duration: ['p(95)<1500'],
  },
};

const urls = __URLS__;

export default function () {
  for (const url of urls) {
    const res = http.get(url, {
      headers: {
        'User-Agent': 'OsintIA-Tools-k6/__VERSION__',
      },
      timeout: '30s',
    });

    check(res, {
      'status is not 5xx': (r) => r.status < 500,
      'response time < 1500ms': (r) => r.timings.duration < 1500,
    });

    sleep(1);
  }
}
"""
    script = (
        script
        .replace("__VUS__", str(vus))
        .replace("__DURATION__", str(duration))
        .replace("__URLS__", urls_js)
        .replace("__VERSION__", VERSION)
    )

    script_path = report_dir / "k6_load_test.js"
    script_path.write_text(script, encoding="utf-8")
    return script_path


def run_k6_advanced(domain, scheme, report_dir, urls, vus=10, duration="1m"):
    print("[+] Running k6 advanced load test...")

    script_path = generate_k6_script(
        domain=domain,
        scheme=scheme,
        report_dir=report_dir,
        urls=urls,
        vus=vus,
        duration=duration,
    )

    if shutil.which("k6") is None:
        return (
            f"k6 script generated but k6 is not installed: {script_path}\n"
            "Install k6 and run manually:\n"
            f"k6 run {script_path}\n"
            "Kali/Debian install option may require the official k6 repository."
        )

    output = run_command(["k6", "run", str(script_path)], timeout=1800)
    return f"k6 script: {script_path}\n\n{output}"


# --------------------------------------------------------------------
# Adaptive authentication testing module
# --------------------------------------------------------------------

LOGIN_PATH_CANDIDATES = [
    "/",
    "/login",
    "/signin",
    "/sign-in",
    "/auth",
    "/auth/login",
    "/auth/signin",
    "/user/login",
    "/users/sign_in",
    "/account/login",
    "/accounts/login",
    "/admin/login",
    "/admin",
    "/wp-login.php",
    "/session/new",
    "/sessions/new",

    # Common API auth endpoints
    "/api/auth/login",
    "/api/login",
    "/api/session",
    "/api/sessions",
    "/rest/login",
    "/rest/logout",
    "/rest/login?redirect=%2F",
]

USER_FIELD_HINTS = [
    "email", "user", "username", "login", "identifier", "account", "mail"
]

PASSWORD_FIELD_HINTS = [
    "password", "passwd", "pass", "pwd"
]

CONTROLLED_CREDENTIAL_CANDIDATES = [
    # E-mail based defaults
    ("admin@example.com", "admin"),
    ("admin@example.com", "password"),
    ("admin@example.com", "admin123"),
    ("admin@example.com", "123456"),
    ("admin@example.com", "changeme"),

    # Admin padrões
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("admin", "123456"),
    ("admin", "12345678"),
    ("admin", "qwerty"),
    ("admin", "changeme"),
    ("admin", "welcome"),

    # Variações comuns
    ("administrator", "administrator"),
    ("administrator", "admin"),
    ("root", "root"),
    ("root", "toor"),

    # Contas genéricas
    ("user", "user"),
    ("user", "password"),
    ("test", "test"),
    ("demo", "demo"),
    ("guest", "guest"),

    # Ambientes locais/dev (muito comuns!)
    ("admin@localhost", "admin"),
    ("admin@localhost", "password"),
    ("admin@local", "admin"),

    # Padrões modernos fracos
    ("admin", "Pass@123"),
    ("admin", "Admin@123"),
]


def form_to_summary(form, base_url):
    method = (form.get("method") or "get").lower()
    action = form.get("action") or base_url
    action_url = urljoin(base_url, action)
    inputs = []

    for inp in form.find_all(["input", "button", "textarea", "select"]):
        name = inp.get("name") or ""
        input_type = inp.get("type") or inp.name
        value = inp.get("value") or ""
        placeholder = inp.get("placeholder") or ""
        autocomplete = inp.get("autocomplete") or ""
        inputs.append({
            "name": name,
            "type": input_type.lower(),
            "value": value,
            "placeholder": placeholder,
            "autocomplete": autocomplete,
        })

    return {
        "method": method,
        "action_url": action_url,
        "inputs": inputs,
        "has_password": any(i["type"] == "password" for i in inputs),
    }


def guess_field(form_summary, hints, fallback_type=None):
    inputs = form_summary.get("inputs", [])

    for inp in inputs:
        haystack = " ".join([
            inp.get("name", ""),
            inp.get("type", ""),
            inp.get("placeholder", ""),
            inp.get("autocomplete", ""),
        ]).lower()
        if any(hint in haystack for hint in hints) and inp.get("name"):
            return inp["name"]

    if fallback_type:
        for inp in inputs:
            if inp.get("type") == fallback_type and inp.get("name"):
                return inp["name"]

    return None


def detect_login_pages(domain, scheme, extra_paths=None, timeout=12):
    print("[+] Detecting login interfaces adaptively...")
    session = make_session()
    candidates = list(LOGIN_PATH_CANDIDATES)

    if extra_paths:
        for p in extra_paths:
            if p and p not in candidates:
                candidates.append(p)

    base = f"{scheme}://{domain}"
    detected = []
    visited = set()

    urls = [urljoin(base, path) for path in candidates]

    for url in urls:
        if url in visited:
            continue
        visited.add(url)

        try:
            response = session.get(url, timeout=timeout, allow_redirects=True, verify=True)
            final_url = response.url
            text_lower = response.text.lower()
            soup = BeautifulSoup(response.text, "html.parser")
            forms = [form_to_summary(form, final_url) for form in soup.find_all("form")]

            has_password_form = any(f["has_password"] for f in forms)

            has_login_keywords = any(
                kw in text_lower for kw in [
                    "password", "sign in", "signin", "login", "log in", "forgot",
                    "email", "username", "entrar", "acessar", "authentication",
                    "credentials", "session"
                ]
            )

            is_spa_login_like = (
                response.status_code in [200, 301, 302, 401, 403, 405]
                and any(
                    kw in text_lower for kw in [
                        "n8n",
                        "app-root",
                        "root",
                        "assets/",
                        "index-",
                        "vite",
                        "webpack",
                    ]
                )
                and any(
                    kw in text_lower for kw in [
                        "signin",
                        "login",
                        "password",
                        "auth",
                        "session",
                    ]
                )
            )

            is_auth_endpoint = any(
                path in url.lower()
                for path in [
                    "/rest/login",
                    "/api/login",
                    "/api/auth/login",
                    "/api/session",
                    "/api/sessions",
                ]
            )

            if response.status_code in [200, 301, 302, 401, 403, 405] and (
                has_password_form or has_login_keywords or is_spa_login_like or is_auth_endpoint
            ):
                detected.append({
                    "url": url,
                    "final_url": final_url,
                    "status_code": response.status_code,
                    "content_length": len(response.text),
                    "forms": forms,
                    "has_password_form": has_password_form,
                    "has_login_keywords": has_login_keywords,
                    "is_spa_login_like": is_spa_login_like,
                    "is_auth_endpoint": is_auth_endpoint,
                })

        except requests.exceptions.SSLError as exc:
            detected.append({
                "url": url,
                "final_url": url,
                "status_code": "SSL_ERROR",
                "content_length": 0,
                "forms": [],
                "has_password_form": False,
                "has_login_keywords": False,
                "is_spa_login_like": False,
                "is_auth_endpoint": False,
                "error": str(exc),
            })
        except Exception:
            continue

        time.sleep(0.5)

    dedup = {}
    for item in detected:
        dedup[item["final_url"]] = item

    return list(dedup.values())


def select_best_login_candidate(candidates):
    if not candidates:
        return None

    candidates_sorted = sorted(
        candidates,
        key=lambda c: (
            not c.get("has_password_form", False),
            not c.get("has_login_keywords", False),
            len(c.get("forms", [])) == 0,
        )
    )
    return candidates_sorted[0]


def response_fingerprint(response):
    body = response.text or ""
    normalized = re.sub(r"\s+", " ", body.lower())[:5000]

    indicators = []
    for keyword in [
        "invalid", "incorrect", "wrong", "failed", "error", "unauthorized",
        "forbidden", "locked", "too many", "rate limit", "captcha",
        "mfa", "2fa", "verification", "forgot"
    ]:
        if keyword in normalized:
            indicators.append(keyword)

    return {
        "status_code": response.status_code,
        "length": len(body),
        "final_url": response.url,
        "keywords": indicators,
    }


def submit_login_attempt(session, form_summary, username_field, password_field, username, password, timeout=15):
    method = form_summary.get("method", "get").lower()
    action_url = form_summary.get("action_url")

    data = {}
    for inp in form_summary.get("inputs", []):
        name = inp.get("name")
        if not name:
            continue
        data[name] = inp.get("value", "")

    data[username_field] = username
    data[password_field] = password

    if method == "post":
        return session.post(action_url, data=data, timeout=timeout, allow_redirects=True)
    return session.get(action_url, params=data, timeout=timeout, allow_redirects=True)


def run_controlled_auth_attempts(login_candidate, max_attempts=6, delay=2):
    if not login_candidate:
        return "Authentication testing skipped: no login candidate detected."

    forms = login_candidate.get("forms", [])
    password_forms = [f for f in forms if f.get("has_password")]

    if not password_forms:
        if login_candidate.get("is_auth_endpoint") or login_candidate.get("is_spa_login_like"):
            return (
                "Login/authentication interface detected, but no classic HTML password form was found.\n"
                f"Detected URL: {login_candidate.get('final_url')}\n"
                "Likely SPA/API-based authentication. Controlled credential attempts were skipped.\n"
                "Recommended next step: capture the login request with browser DevTools or Burp/ZAP "
                "and test the raw request safely."
            )

        return (
            "Authentication testing skipped: login-like page found, "
            "but no HTML password form was detected."
        )


    session = make_session()
    results = []
    results.append(f"Login URL: {login_candidate.get('final_url')}")
    results.append(f"Form action: {form.get('action_url')}")
    results.append(f"Method: {form.get('method')}")
    results.append(f"Username field: {username_field}")
    results.append(f"Password field: {password_field}")
    results.append(f"Max controlled attempts: {max_attempts}")
    results.append("")

    observed = []
    attempts = CONTROLLED_CREDENTIAL_CANDIDATES[:max_attempts]

    for index, (username, password) in enumerate(attempts, start=1):
        try:
            response = submit_login_attempt(
                session=session,
                form_summary=form,
                username_field=username_field,
                password_field=password_field,
                username=username,
                password=password,
            )
            fp = response_fingerprint(response)
            observed.append(fp)

            results.append(
                f"[attempt {index}] user={username!r} password={password!r} "
                f"status={fp['status_code']} length={fp['length']} "
                f"final_url={fp['final_url']} keywords={','.join(fp['keywords']) or 'none'}"
            )

            # Stop if signs of lockout/rate limit appear
            if any(k in fp["keywords"] for k in ["locked", "too many", "rate limit", "captcha"]):
                results.append("[!] Stopping controlled attempts: lockout/rate-limit/captcha signal detected.")
                break

            time.sleep(delay)

        except Exception as exc:
            results.append(f"[attempt {index}] error: {exc}")

    # Basic differential analysis
    if observed:
        status_set = sorted(set(str(o["status_code"]) for o in observed))
        length_set = sorted(set(o["length"] for o in observed))
        keyword_sets = [tuple(o["keywords"]) for o in observed]
        results.append("")
        results.append("--- Differential response observations ---")
        results.append(f"Observed status codes: {', '.join(status_set)}")
        results.append(f"Observed response lengths: {length_set[:10]}")
        if len(set(keyword_sets)) > 1:
            results.append("[!] Different keyword patterns observed. Check for user enumeration or response discrepancy.")
        else:
            results.append("[+] Similar keyword patterns observed across attempts.")

        if len(length_set) > 1 and max(length_set) - min(length_set) > 100:
            results.append("[!] Response length varies significantly. Check for enumeration or state-based differences.")

    return "\n".join(results)


def run_adaptive_auth_tests(domain, scheme, mode, auth_max_attempts, auth_delay):
    """
    Detect login and run safe, adaptive tests.
    Returns a dict with detection, controlled attempts and optional SQLMap results.
    """
    results = {}

    detected = detect_login_pages(domain, scheme)
    if not detected:
        results["summary"] = (
            "No login interface detected in common paths. "
            "Authentication testing skipped without errors."
        )
        results["detected_logins"] = []
        results["controlled_attempts"] = "Skipped."
        results["sqlmap_login"] = "Skipped."
        return results

    best = select_best_login_candidate(detected)
    detection_lines = []
    detection_lines.append(f"Detected login-like interfaces: {len(detected)}")
    for item in detected:
        detection_lines.append(
            f"- url={item.get('url')} final={item.get('final_url')} "
            f"status={item.get('status_code')} "
            f"forms={len(item.get('forms', []))} "
            f"password_form={item.get('has_password_form')} "
            f"keywords={item.get('has_login_keywords')}"
        )

    detection_lines.append("")
    detection_lines.append(f"Selected candidate: {best.get('final_url') if best else 'None'}")
    results["summary"] = "\n".join(detection_lines)
    results["detected_logins"] = detected

    if mode in ("active", "aggressive"):
        results["controlled_attempts"] = run_controlled_auth_attempts(
            best,
            max_attempts=auth_max_attempts,
            delay=auth_delay,
        )
    else:
        results["controlled_attempts"] = "Skipped: controlled auth attempts require active or aggressive mode."

    if mode == "aggressive" and best and best.get("has_password_form"):
        results["sqlmap_login"] = run_sqlmap_login_form(best.get("final_url"), crawl_depth=1)
    else:
        results["sqlmap_login"] = (
            "Skipped: login SQLMap requires aggressive mode and a detected HTML password form."
        )

    return results


def auth_results_to_text(results):
    return "\n\n".join([
        "=== Login Detection ===",
        results.get("summary", ""),
        "=== Controlled Authentication Attempts ===",
        results.get("controlled_attempts", ""),
        "=== SQLMap Login Form Test ===",
        results.get("sqlmap_login", ""),
    ])


# --------------------------------------------------------------------
# Professional Markdown reporting
# --------------------------------------------------------------------

def markdown_escape_table(value):
    return str(value or "").replace("|", "\\|").replace("\n", " ").strip()


def classify_overall_risk_from_outputs(report_chunks):
    joined = "\n".join(content for _, content in report_chunks).lower()

    high_indicators = [
        "sql injection",
        "remote code execution",
        "authentication bypass",
        "default credentials worked",
        "successful login",
        "critical",
    ]

    medium_indicators = [
        "x-frame-options header is not present",
        "strict-transport-security http header is not defined",
        "x-content-type-options header is not set",
        "missing",
        "rate limit",
        "too many requests",
        "failed transactions:",
    ]

    if any(ind in joined for ind in high_indicators):
        return "High"
    if any(ind in joined for ind in medium_indicators):
        return "Medium"
    return "Low"


def extract_structured_findings(report_chunks):
    findings = []
    chunks = {title: content for title, content in report_chunks}

    def add(severity, category, title, source, evidence, recommendation):
        findings.append({
            "severity": severity,
            "category": category,
            "title": title,
            "source": source,
            "evidence": evidence,
            "recommendation": recommendation,
        })

    nikto = chunks.get("Nikto", "") + "\n" + chunks.get("Nikto Results", "")
    if "X-Frame-Options header is not present" in nikto:
        add(
            "Medium",
            "Security Headers",
            "Missing X-Frame-Options Header",
            "Nikto",
            "Nikto reported that the X-Frame-Options header is not present.",
            'Add X-Frame-Options "SAMEORIGIN" or define CSP frame-ancestors.'
        )

    if "Strict-Transport-Security HTTP header is not defined" in nikto:
        add(
            "Medium",
            "Transport Security",
            "Missing HTTP Strict Transport Security",
            "Nikto",
            "Nikto reported that the Strict-Transport-Security header is not defined.",
            "Enable HSTS with an appropriate max-age after validating HTTPS coverage."
        )

    if "X-Content-Type-Options header is not set" in nikto:
        add(
            "Low",
            "Security Headers",
            "Missing X-Content-Type-Options Header",
            "Nikto",
            "Nikto reported that X-Content-Type-Options is not set.",
            'Add X-Content-Type-Options "nosniff".'
        )

    if "Content-Encoding header is set to" in nikto and "BREACH" in nikto:
        add(
            "Informational",
            "Compression",
            "Potential BREACH Exposure Indicator",
            "Nikto",
            "Nikto observed HTTP compression and flagged a potential BREACH-related condition.",
            "Review whether sensitive reflected content is compressed. Disable compression selectively where needed."
        )

    shodan = chunks.get("Shodan", "")
    if "HTTP 403" in shodan or "requires Membership+" in shodan:
        add(
            "Informational",
            "Tool Limitation",
            "Shodan Data Limited by API Plan",
            "Shodan",
            "Shodan returned limited data or an HTTP 403 response.",
            "Treat Shodan enrichment as optional and rely on local validation tools such as Nmap and WhatWeb."
        )

    metagoofil = chunks.get("Metagoofil", "")
    if "HTTP Error 429" in metagoofil or "Too Many Requests" in metagoofil:
        add(
            "Informational",
            "Tool Limitation",
            "Metagoofil Blocked by Google Rate Limiting",
            "Metagoofil",
            "Metagoofil received HTTP 429 Too Many Requests.",
            "Retry later with lower volume or run metadata collection separately with longer delays."
        )

    sqlmap = chunks.get("SQLMap", "")
    if "no usable links found" in sqlmap or "No injectable parameters or forms were discovered" in sqlmap:
        add(
            "Informational",
            "SQL Injection Testing",
            "No Public SQL Injection Test Points Identified",
            "SQLMap",
            "SQLMap did not identify usable GET parameters or forms in the public unauthenticated surface.",
            "For SPA/API applications, capture authenticated API requests and test them explicitly."
        )

    auth = chunks.get("Adaptive Authentication Testing", "")
    if "Login/authentication interface detected" in auth and "no classic HTML password form" in auth:
        add(
            "Informational",
            "Authentication",
            "SPA/API Authentication Flow Detected",
            "Adaptive Authentication Testing",
            "The tool detected an authentication interface but no classic HTML password form.",
            "Capture the login request with DevTools, Burp, or ZAP for authenticated testing."
        )

    load = chunks.get("Load Testing", "")
    if "Failed transactions:" in load:
        match = re.search(r"Failed transactions:\s+([\d.]+)", load)
        if match and float(match.group(1)) == 0:
            add(
                "Informational",
                "Load Testing",
                "No Failed Transactions in Controlled Load Test",
                "Siege/k6",
                "The controlled load test reported zero failed transactions.",
                "Increase realism with authenticated flows and business-critical API endpoints."
            )

    if not findings:
        add(
            "Informational",
            "Assessment Summary",
            "No Automatically Extracted Findings",
            "OsintIA",
            "The local finding extractor did not identify predefined finding patterns.",
            "Review the AI analysis and raw evidence for manual validation."
        )

    return findings


def generate_professional_ai_markdown_analysis(domain, scheme, mode, report_chunks, findings, no_ai=False):
    if no_ai:
        return (
            "AI-based executive analysis was skipped because --no-ai was used.\n\n"
            "Manual review is required to validate findings, determine business impact, "
            "and prioritize remediation actions."
        )

    full_context = "\n\n".join(
        f"## {title}\n{content[:9000]}"
        for title, content in report_chunks
    )

    findings_context = json.dumps(findings, indent=2, ensure_ascii=False)

    prompt = f"""
You are a senior application security consultant preparing a professional security assessment report.

Target: {scheme}://{domain}
Mode: {mode}

Produce a polished Markdown report section with the following exact structure:

## Executive Summary
Explain the overall security posture in clear consulting language.

## Overall Risk Rating
Choose one: Low, Medium, High, or Critical. Justify the rating.

## Attack Surface Overview
Summarize exposed infrastructure, web application surface, technologies, and relevant limitations.

## Key Findings
List confirmed findings first, then potential risks. Do not exaggerate.

## Authentication Security Assessment
Discuss whether login/authentication was detected, whether testing was possible, and what manual validation is required.

## Web Security Assessment
Discuss headers, web misconfigurations, content discovery, Nikto/WhatWeb/FFUF observations, and SQLMap limitations.

## Infrastructure and Network Exposure
Discuss IP resolution, Nmap, Shodan limitations, DNS/subdomain observations, and exposed services.

## Load Testing Interpretation
Discuss Siege/k6 results if available. Separate availability, latency, failed transactions, and limitations.

## Prioritized Remediation Plan
Create High, Medium, and Low priority sections with actionable remediation.

## False Positives and Manual Validation Required
Clearly state what needs manual verification.

## Final Consultant Conclusion
Close with a concise professional conclusion.

Rules:
- Do not claim exploitation if the tool only performed detection.
- Clearly separate confirmed evidence from potential risk.
- Mention when tools were blocked, rate-limited, incomplete, or skipped.
- Avoid generic filler; be specific to the evidence.
- Keep the tone professional and suitable for a client-facing report.

Automatically extracted finding hints:
{findings_context}

Raw evidence:
{full_context}
"""
    return call_chatgpt(prompt, timeout=150, max_output_tokens=5500)


def generate_markdown_report(report_dir, domain, scheme, mode, report_chunks, final_conclusion, no_ai=False):
    print("[+] Generating professional Markdown report...")

    output_md = report_dir / "OsintIA_report.md"
    findings = extract_structured_findings(report_chunks)
    overall_risk_hint = classify_overall_risk_from_outputs(report_chunks)
    ai_assessment = generate_professional_ai_markdown_analysis(
        domain=domain,
        scheme=scheme,
        mode=mode,
        report_chunks=report_chunks,
        findings=findings,
        no_ai=no_ai,
    )

    with output_md.open("w", encoding="utf-8") as md:
        md.write("# OsintIA Security Assessment Report\n\n")
        md.write("## Report Metadata\n\n")
        md.write(f"- **Target:** `{scheme}://{domain}`\n")
        md.write(f"- **Execution mode:** `{mode}`\n")
        md.write(f"- **Generated at:** `{datetime.now(UTC).isoformat()}`\n")
        md.write(f"- **Tool version:** `OsintIA_Tools {VERSION}`\n")
        md.write(f"- **Local overall risk hint:** `{overall_risk_hint}`\n\n")

        md.write("---\n\n")
        md.write(ai_assessment.strip() + "\n\n")

        md.write("---\n\n")
        md.write("## Structured Findings Index\n\n")
        md.write("| ID | Severity | Category | Finding | Source |\n")
        md.write("|---|---|---|---|---|\n")
        for idx, finding in enumerate(findings, start=1):
            md.write(
                f"| F-{idx:03d} | {markdown_escape_table(finding['severity'])} "
                f"| {markdown_escape_table(finding['category'])} "
                f"| {markdown_escape_table(finding['title'])} "
                f"| {markdown_escape_table(finding['source'])} |\n"
            )

        md.write("\n## Detailed Structured Findings\n\n")
        for idx, finding in enumerate(findings, start=1):
            md.write(f"### F-{idx:03d} — {finding['title']}\n\n")
            md.write(f"- **Severity:** {finding['severity']}\n")
            md.write(f"- **Category:** {finding['category']}\n")
            md.write(f"- **Source:** {finding['source']}\n\n")
            md.write("**Evidence**\n\n")
            md.write(f"```text\n{finding['evidence']}\n```\n\n")
            md.write("**Recommendation**\n\n")
            md.write(f"{finding['recommendation']}\n\n")

        md.write("---\n\n")
        md.write("## Final AI Conclusion From Legacy Report Flow\n\n")
        md.write((final_conclusion or "Not available.").strip() + "\n\n")

        md.write("---\n\n")
        md.write("## Appendix — Raw Evidence by Tool\n\n")
        for title, content in report_chunks:
            md.write(f"### {title}\n\n")
            safe_content = (content or "").strip()
            if len(safe_content) > 50000:
                safe_content = safe_content[:50000] + "\n\n[... output truncated in Markdown report ...]"
            md.write(f"```text\n{safe_content}\n```\n\n")

    print(f"[+] Markdown report saved: {output_md}")
    return output_md

def build_sections(mode):
    sections = {
        "ip-resolution": "IP Resolution",
        "ip-analysis": "IP Analysis with AI",
        "shodan-data": "Shodan Data",
        "shodan-analysis": "Shodan Analysis with AI",
        "whois-info": "WHOIS Information",
        "whois-analysis": "WHOIS Analysis with AI",
        "nmap-results": "Nmap Results",
        "nmap-analysis": "Nmap Analysis with AI",
        "indexed-links": "Indexed Links with Google Dorks",
        "photon-results": "Photon Results",
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
        "auth-results": "Adaptive Authentication Testing",
        "auth-analysis": "Authentication Analysis with AI",
    }

    if mode in ("active", "aggressive"):
        sections.update({
            "ffuf-results": "FFUF Content Discovery",
            "ffuf-analysis": "FFUF Analysis with AI",
            "nikto-results": "Nikto Web Scan",
            "nikto-analysis": "Nikto Analysis with AI",
        })

    if mode == "aggressive":
        sections.update({
            "sqlmap-results": "SQLMap Controlled Scan",
            "sqlmap-analysis": "SQLMap Analysis with AI",
            "load-results": "Load Testing Results",
            "load-analysis": "Load Testing Analysis with AI",
        })

    sections["final-conclusion"] = "Final Conclusion"
    return sections


def main(
    domain,
    mode="passive",
    scheme="https",
    rate=20,
    threads=10,
    wordlist="/usr/share/wordlists/dirb/common.txt",
    install_deps=False,
    no_ai=False,
    sqlmap_crawl_depth=2,
    siege_concurrency=5,
    siege_duration="30S",
    load_engine="siege",
    siege_profile="medium",
    k6_vus=10,
    k6_duration="1m",
    load_max_urls=30,
    auth_max_attempts=20,
    auth_delay=2,
):
    print_header()
    parsed_domain = sanitize_domain(domain)

    check_and_install_dependencies(auto_install=install_deps)

    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    report_dir = Path(f"OsintIA_report_{parsed_domain}_{timestamp}")
    ensure_dir(report_dir)

    output_txt = report_dir / "OsintIA_report.txt"
    output_html = report_dir / "OsintIA_report.html"

    sections = build_sections(mode)
    report_chunks = []

    with output_txt.open("w", encoding="utf-8") as txt_file, output_html.open("w", encoding="utf-8") as html_file:
        html_file.write(
            "<html><head><meta charset='utf-8'>"
            "<style>"
            "body{font-family:Arial,sans-serif;margin:30px;line-height:1.5;}"
            "pre{background:#f4f4f4;padding:12px;border-radius:8px;overflow:auto;}"
            "h1,h2{color:#222;} a{color:#0645ad;}"
            "</style></head><body>"
            f"<h1>OsintIA_Tools Report for {html_escape(parsed_domain)}</h1>"
            f"<p><strong>Mode:</strong> {html_escape(mode)} | "
            f"<strong>Scheme:</strong> {html_escape(scheme)} | "
            f"<strong>Generated:</strong> {html_escape(timestamp)} UTC</p>"
        )
        html_file.write(generate_html_index(sections))

        ip, ip_raw = resolve_ip(parsed_domain)
        write_text_block(txt_file, "IP Resolution", ip_raw)
        write_pre_section(html_file, "ip-resolution", "IP Resolution", ip_raw)
        report_chunks.append(("IP Resolution", ip_raw))

        if not no_ai:
            ip_analysis = summarize_with_ai("IP Resolution", f"Resolved IP(s):\n{ip}\n\nRaw:\n{ip_raw}")
            write_text_block(txt_file, "AI IP Analysis", ip_analysis)
            write_section(html_file, "ip-analysis", "IP Analysis with AI", format_analysis_text(ip_analysis))

        shodan_result = query_shodan(ip)
        write_text_block(txt_file, "Shodan Data", shodan_result)
        write_pre_section(html_file, "shodan-data", "Shodan Data", shodan_result)
        report_chunks.append(("Shodan", shodan_result))

        if not no_ai:
            shodan_analysis = summarize_with_ai("Shodan", shodan_result)
            write_text_block(txt_file, "AI Shodan Analysis", shodan_analysis)
            write_section(html_file, "shodan-analysis", "Shodan Analysis with AI", format_analysis_text(shodan_analysis))

        whois_info = run_whois(parsed_domain)
        write_text_block(txt_file, "WHOIS Information", whois_info)
        write_pre_section(html_file, "whois-info", "WHOIS Information", whois_info)
        report_chunks.append(("WHOIS", whois_info))

        if not no_ai:
            whois_analysis = summarize_with_ai("WHOIS", whois_info)
            write_text_block(txt_file, "AI WHOIS Analysis", whois_analysis)
            write_section(html_file, "whois-analysis", "WHOIS Analysis with AI", format_analysis_text(whois_analysis))

        nmap_result = run_nmap(parsed_domain, mode)
        write_text_block(txt_file, "Nmap Results", nmap_result)
        write_pre_section(html_file, "nmap-results", "Nmap Results", nmap_result)
        report_chunks.append(("Nmap", nmap_result))

        if not no_ai:
            nmap_analysis = summarize_with_ai("Nmap", nmap_result)
            write_text_block(txt_file, "AI Nmap Analysis", nmap_analysis)
            write_section(html_file, "nmap-analysis", "Nmap Analysis with AI", format_analysis_text(nmap_analysis))

        dorks_result = run_google_dorks(parsed_domain)
        write_text_block(txt_file, "Indexed Links with Google Dorks", dorks_result)
        write_pre_section(html_file, "indexed-links", "Indexed Links with Google Dorks", dorks_result)
        report_chunks.append(("Google Dorks", dorks_result))

        photon_result = run_photon(parsed_domain, scheme)
        write_text_block(txt_file, "Photon Results", photon_result)
        write_pre_section(html_file, "photon-results", "Photon Results", photon_result)
        report_chunks.append(("Photon", photon_result))

        if not no_ai:
            links_analysis = summarize_with_ai("Google Dorks and Photon", dorks_result + "\n\n" + photon_result)
            write_text_block(txt_file, "AI Links Analysis", links_analysis)
            write_section(html_file, "links-analysis", "Links Analysis with AI", format_analysis_text(links_analysis))

        metagoofil_result = run_metagoofil(parsed_domain)

        write_text_block(txt_file, "Extracted Metadata with Metagoofil", metagoofil_result)
        write_pre_section(html_file, "extracted-metadata", "Extracted Metadata with Metagoofil", metagoofil_result)
        report_chunks.append(("Metagoofil", metagoofil_result))

        if not no_ai:
            if "HTTP Error 429" in metagoofil_result or "Too Many Requests" in metagoofil_result:
                metadata_analysis = (
                    "Metagoofil analysis skipped due to Google rate limiting (HTTP 429). "
                    "No reliable metadata could be extracted. Consider retrying later "
                    "or running Metagoofil manually with longer delays."
                )
            else:
                metadata_analysis = summarize_with_ai("Metagoofil Metadata", metagoofil_result)
        
            write_text_block(txt_file, "AI Metadata Analysis", metadata_analysis)
            write_section(
                html_file,
                "metadata-analysis",
                "Metadata Analysis with AI",
                format_analysis_text(metadata_analysis),
            )

        sublist3r_result = run_sublist3r(parsed_domain)
        write_text_block(txt_file, "Found Subdomains with Sublist3r", sublist3r_result)
        write_pre_section(html_file, "found-subdomains", "Found Subdomains with Sublist3r", sublist3r_result)
        report_chunks.append(("Sublist3r", sublist3r_result))

        if not no_ai:
            sublist3r_analysis = summarize_with_ai("Sublist3r", sublist3r_result)
            write_text_block(txt_file, "AI Sublist3r Analysis", sublist3r_analysis)
            write_section(html_file, "sublist3r-analysis", "Sublist3r Analysis with AI", format_analysis_text(sublist3r_analysis))

        whatweb_result = run_whatweb(parsed_domain, scheme)
        write_text_block(txt_file, "Detected Technologies with WhatWeb", whatweb_result)
        write_pre_section(html_file, "detected-technologies", "Detected Technologies", whatweb_result)
        report_chunks.append(("WhatWeb", whatweb_result))

        if not no_ai:
            whatweb_analysis = summarize_with_ai("WhatWeb", whatweb_result)
            write_text_block(txt_file, "AI WhatWeb Analysis", whatweb_analysis)
            write_section(html_file, "whatweb-analysis", "WhatWeb Analysis with AI", format_analysis_text(whatweb_analysis))

        harvester_result = run_theharvester(parsed_domain)
        write_text_block(txt_file, "Collected Data with TheHarvester", harvester_result)
        write_pre_section(html_file, "collected-data", "Collected Data with TheHarvester", harvester_result)
        report_chunks.append(("TheHarvester", harvester_result))

        if not no_ai:
            harvester_analysis = summarize_with_ai("TheHarvester", harvester_result)
            write_text_block(txt_file, "AI TheHarvester Analysis", harvester_analysis)
            write_section(html_file, "theharvester-analysis", "TheHarvester Analysis with AI", format_analysis_text(harvester_analysis))

        dnsenum_result = run_dnsenum(parsed_domain)
        write_text_block(txt_file, "DNSEnum Results", dnsenum_result)
        write_pre_section(html_file, "dnsenum-results", "DNSEnum Results", dnsenum_result)
        report_chunks.append(("DNSEnum", dnsenum_result))

        if not no_ai:
            dnsenum_analysis = summarize_with_ai("DNSEnum", dnsenum_result)
            write_text_block(txt_file, "AI DNSEnum Analysis", dnsenum_analysis)
            write_section(html_file, "dnsenum-analysis", "DNSEnum Analysis with AI", format_analysis_text(dnsenum_analysis))

        # Adaptive authentication testing
        auth_results = run_adaptive_auth_tests(
            parsed_domain,
            scheme,
            mode,
            auth_max_attempts=auth_max_attempts,
            auth_delay=auth_delay,
        )
        auth_text = auth_results_to_text(auth_results)
        write_text_block(txt_file, "Adaptive Authentication Testing", auth_text)
        write_pre_section(html_file, "auth-results", "Adaptive Authentication Testing", auth_text)
        report_chunks.append(("Adaptive Authentication Testing", auth_text))

        if not no_ai:
            auth_analysis = summarize_with_ai("Adaptive Authentication Testing", auth_text)
            write_text_block(txt_file, "AI Authentication Analysis", auth_analysis)
            write_section(html_file, "auth-analysis", "Authentication Analysis with AI", format_analysis_text(auth_analysis))

        if mode in ("active", "aggressive"):
            ffuf_result = run_ffuf(parsed_domain, scheme, rate, threads, wordlist)
            write_text_block(txt_file, "FFUF Results", ffuf_result)
            write_pre_section(html_file, "ffuf-results", "FFUF Content Discovery", ffuf_result)
            report_chunks.append(("FFUF", ffuf_result))

            if not no_ai:
                ffuf_analysis = summarize_with_ai("FFUF Content Discovery", ffuf_result)
                write_text_block(txt_file, "AI FFUF Analysis", ffuf_analysis)
                write_section(html_file, "ffuf-analysis", "FFUF Analysis with AI", format_analysis_text(ffuf_analysis))

            nikto_result = run_nikto(parsed_domain, scheme)
            write_text_block(txt_file, "Nikto Results", nikto_result)
            write_pre_section(html_file, "nikto-results", "Nikto Web Scan", nikto_result)
            report_chunks.append(("Nikto", nikto_result))

            if not no_ai:
                nikto_analysis = summarize_with_ai("Nikto", nikto_result)
                write_text_block(txt_file, "AI Nikto Analysis", nikto_analysis)
                write_section(html_file, "nikto-analysis", "Nikto Analysis with AI", format_analysis_text(nikto_analysis))

        if mode == "aggressive":
            sqlmap_result = run_sqlmap_controlled(parsed_domain, scheme, sqlmap_crawl_depth)
            write_text_block(txt_file, "SQLMap Controlled Scan", sqlmap_result)
            write_pre_section(html_file, "sqlmap-results", "SQLMap Controlled Scan", sqlmap_result)
            report_chunks.append(("SQLMap", sqlmap_result))

            if not no_ai:
                sqlmap_analysis = summarize_with_ai("SQLMap Controlled Scan", sqlmap_result)
                write_text_block(txt_file, "AI SQLMap Analysis", sqlmap_analysis)
                write_section(html_file, "sqlmap-analysis", "SQLMap Analysis with AI", format_analysis_text(sqlmap_analysis))

            load_results = []
            load_urls = extract_candidate_urls(
                parsed_domain,
                scheme,
                dorks_result,
                photon_result,
                ffuf_result,
                max_urls=load_max_urls,
            )

            if load_engine in ("siege", "both"):
                siege_result = run_siege_advanced(
                    parsed_domain,
                    scheme,
                    report_dir,
                    load_urls,
                    max_profile=siege_profile,
                )
                load_results.append("=== Siege Improved Load Test ===\n" + siege_result)

            if load_engine in ("k6", "both"):
                k6_result = run_k6_advanced(
                    parsed_domain,
                    scheme,
                    report_dir,
                    load_urls,
                    vus=k6_vus,
                    duration=k6_duration,
                )
                load_results.append("=== k6 Advanced Load Test ===\n" + k6_result)

            if load_engine == "none":
                load_results.append("Load testing skipped because --load-engine none was selected.")

            combined_load_result = "\n\n".join(load_results)
            write_text_block(txt_file, "Load Testing Results", combined_load_result)
            write_pre_section(html_file, "load-results", "Load Testing Results", combined_load_result)
            report_chunks.append(("Load Testing", combined_load_result))

            if not no_ai:
                load_analysis = summarize_with_ai("Load Testing", combined_load_result)
                write_text_block(txt_file, "AI Load Testing Analysis", load_analysis)
                write_section(html_file, "load-analysis", "Load Testing Analysis with AI", format_analysis_text(load_analysis))

        print("[+] Generating final conclusion...")
        full_report_for_ai = "\n\n".join(
            f"## {title}\n{content[:8000]}" for title, content in report_chunks
        )

        if no_ai:
            conclusion = "Final AI conclusion skipped because --no-ai was used."
        else:
            conclusion_prompt = f"""
You are a senior application security consultant.

Based on the following authorized security assessment evidence, produce a concise but professional final conclusion with:

1. Executive summary.
2. Overall risk rating and rationale.
3. Attack surface overview.
4. Authentication security observations.
5. Web and infrastructure security observations.
6. Most critical confirmed findings.
7. Potential risks requiring manual validation.
8. Prioritized remediation plan: High, Medium, Low.
9. Monitoring, hardening, and next validation steps.

Rules:
- Do not exaggerate.
- Do not claim exploitation where only detection was performed.
- Separate confirmed findings from potential risks.
- Mention tool limitations, skipped tests, rate limits, and incomplete results when relevant.

Report:
{full_report_for_ai}
"""
            conclusion = call_chatgpt(conclusion_prompt, timeout=90, max_output_tokens=3500)

        write_text_block(txt_file, "Final Conclusion", conclusion)
        write_section(html_file, "final-conclusion", "Final Conclusion", format_analysis_text(conclusion))

        generate_markdown_report(
            report_dir=report_dir,
            domain=parsed_domain,
            scheme=scheme,
            mode=mode,
            report_chunks=report_chunks,
            final_conclusion=conclusion,
            no_ai=no_ai,
        )

        html_file.write("</body></html>")

    print(f"[+] Reports saved:")
    print(f"    TXT : {output_txt}")
    print(f"    HTML: {output_html}")
    print(f"    MD  : {report_dir / 'OsintIA_report.md'}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="OsintIA Tools - Authorized OSINT, Web Security and Adaptive Auth Scanner"
    )
    parser.add_argument("domain", help="Target domain, e.g. example.com")
    parser.add_argument(
        "--mode",
        choices=["passive", "active", "aggressive"],
        default="passive",
        help="Execution mode",
    )
    parser.add_argument(
        "--i-have-authorization",
        action="store_true",
        help="Required for active/aggressive scans",
    )
    parser.add_argument(
        "--scheme",
        choices=["http", "https"],
        default="https",
        help="Target web scheme",
    )
    parser.add_argument(
        "--rate",
        type=int,
        default=20,
        help="FFUF rate limit",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=10,
        help="FFUF thread count",
    )
    parser.add_argument(
        "--wordlist",
        default="/usr/share/wordlists/dirb/common.txt",
        help="Wordlist for FFUF",
    )
    parser.add_argument(
        "--install-deps",
        action="store_true",
        help="Attempt to install missing APT dependencies",
    )
    parser.add_argument(
        "--no-ai",
        action="store_true",
        help="Run tools but skip AI analysis",
    )
    parser.add_argument(
        "--sqlmap-crawl-depth",
        type=int,
        default=2,
        help="SQLMap crawl depth for aggressive mode",
    )
    parser.add_argument(
        "--siege-concurrency",
        type=int,
        default=5,
        help="Siege concurrent users for aggressive mode",
    )
    parser.add_argument(
        "--siege-duration",
        default="30S",
        help="Legacy Siege duration kept for compatibility. Advanced Siege uses --siege-profile.",
    )
    parser.add_argument(
        "--load-engine",
        choices=["none", "siege", "k6", "both"],
        default="siege",
        help="Load testing engine for aggressive mode.",
    )
    parser.add_argument(
        "--siege-profile",
        choices=["light", "medium", "high"],
        default="medium",
        help="Maximum Siege profile to run: light, medium, or high.",
    )
    parser.add_argument(
        "--k6-vus",
        type=int,
        default=10,
        help="k6 virtual users.",
    )
    parser.add_argument(
        "--k6-duration",
        default="1m",
        help="k6 test duration, e.g. 30s, 1m, 5m.",
    )
    parser.add_argument(
        "--load-max-urls",
        type=int,
        default=30,
        help="Maximum URLs used by Siege/k6.",
    )
    parser.add_argument(
        "--auth-max-attempts",
        type=int,
        default=6,
        help="Maximum controlled login attempts. Keep low.",
    )
    parser.add_argument(
        "--auth-delay",
        type=float,
        default=2.0,
        help="Delay between controlled login attempts in seconds.",
    )

    args = parser.parse_args()

    if args.mode in ("active", "aggressive") and not args.i_have_authorization:
        print("[!] Active/aggressive scans require --i-have-authorization")
        sys.exit(1)

    if args.auth_max_attempts > 20:
        print("[!] --auth-max-attempts is intentionally capped at 20.")
        args.auth_max_attempts = 20

    if args.mode == "aggressive":
        print("[!] Aggressive mode enabled. Confirmed authorization flag received.")

    main(
        domain=args.domain,
        mode=args.mode,
        scheme=args.scheme,
        rate=args.rate,
        threads=args.threads,
        wordlist=args.wordlist,
        install_deps=args.install_deps,
        no_ai=args.no_ai,
        sqlmap_crawl_depth=args.sqlmap_crawl_depth,
        siege_concurrency=args.siege_concurrency,
        siege_duration=args.siege_duration,
        load_engine=args.load_engine,
        siege_profile=args.siege_profile,
        k6_vus=args.k6_vus,
        k6_duration=args.k6_duration,
        load_max_urls=args.load_max_urls,
        auth_max_attempts=args.auth_max_attempts,
        auth_delay=args.auth_delay,
    )
