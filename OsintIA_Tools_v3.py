import os
import sys
import requests
import subprocess
from urllib.parse import urlparse
from bs4 import BeautifulSoup

# Configura tus claves de API de OpenAI y Shodan
OPENAI_API_KEY = "sk-proj-sdhiashfsdfhifhidhfdhfihidhdsifhdshfdsifhdfdsihfidshfid_YNg4df5h4dfg5g4dfhdf6gd4f64fgdf1gf564dsf6dsg145g6rd2gdf_9XC3i13ne9v3965f4ds6f4sd56f4dsg4dfg5fd4gdf5g4f"
SHODAN_API_KEY = "tdf4ds58fdfs4dfgf4gdf45gf64gfdgdfgfd5g4fEl"

# Lista de dependencias necesarias
DEPENDENCIES = [
    "dig", "whois", "nmap", "wget", "pdfinfo", "exiftool", "amass", "sublist3r",
    "whatweb", "theHarvester", "dnsenum", "python3", "photon", "metagoofil"
]

# Función para verificar e instalar dependencias
def check_and_install_dependencies():
    print("[+] Verificando dependencias...")
    missing = []
    for dep in DEPENDENCIES:
        if subprocess.run(f"which {dep}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode != 0:
            missing.append(dep)
    
    if missing:
        print(f"[!] Dependencias faltantes: {', '.join(missing)}")
        if os.geteuid() != 0:
            print("[!] Se requieren permisos de administrador para instalar las dependencias. Ejecuta el script como root o con sudo.")
            sys.exit(1)
        print("[+] Instalando dependencias...")
        install_command = f"sudo apt update && sudo apt install -y {' '.join(missing)}"
        if subprocess.run(install_command, shell=True).returncode != 0:
            print("[!] Fallo al instalar dependencias. Verifica tu conexión o intenta nuevamente.")
            sys.exit(1)
        print("[+] Todas las dependencias se instalaron correctamente.")
    else:
        print("[+] Todas las dependencias están instaladas.")

# Función para llamar a la API de OpenAI
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

    for attempt in range(3):  # Tentar até 3 vezes
        try:
            response = requests.post(url, headers=headers, json=payload, timeout=10)
            response.raise_for_status()
            return response.json()["choices"][0]["message"]["content"].strip()
        except requests.exceptions.RequestException as e:
            print(f"[!] Tentativa {attempt + 1} falhou: {e}")
            if attempt == 2:  # Última tentativa
                return "Erro: Não foi possível conectar à API de OpenAI."
    return "Erro: Falha ao tentar conectar à API de OpenAI após várias tentativas."

# Función para ejecutar un comando en la terminal
def run_command(command):
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)
    return result.stdout.strip()

# Función principal
def main(domain):
    if not domain:
        print("Uso: python osint_tools_es.py <dominio>")
        sys.exit(1)

    # Verificar e instalar dependencias
    check_and_install_dependencies()

    # Extraer solo el dominio, eliminando "http://" o "https://"
    parsed_domain = urlparse(domain).netloc if "http" in domain else domain

    output_txt = "OsintIA_report.txt"
    output_html = "OsintIA_report.html"

    with open(output_txt, "w") as txt_file, open(output_html, "w") as html_file:
        html_file.write(f"<html><body><h1>Informe de OSINT para {parsed_domain}</h1>")

        # Paso 1. Resolución de IP con verificaciones adicionales y Shodan
        print("[+] Resolviendo la IP del dominio...")
        ip = "Error al resolver la IP"
        try:
            ip = run_command(f"dig +short {parsed_domain}")
            if not ip:
                ip = run_command(f"ping -c 1 {parsed_domain} | grep 'PING' | awk '{{print $3}}' | tr -d '()'")
            if not ip:
                ip = "IP no resuelta"
        except Exception as e:
            print(f"[!] Error resolviendo la IP: {e}")
            ip = "Error al resolver la IP"

        txt_file.write(f"IP: {ip}\n")
        html_file.write(f"<h2>Resolución de IP</h2><p>IP: {ip}</p>")

        # Consultar Shodan
        if ip != "Error al resolver la IP" and ip != "IP no resuelta":
            print("[+] Consultando datos de Shodan para el IP...")
            try:
                shodan_response = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}", timeout=10)
                if shodan_response.status_code == 200:
                    shodan_result = shodan_response.json()
                else:
                    shodan_result = f"Shodan no devolvió resultados para el IP: {ip}"
            except Exception as e:
                print(f"[!] Error al consultar Shodan: {e}")
                shodan_result = "Error al obtener datos de Shodan."
        else:
            shodan_result = "No se puede consultar Shodan debido a un problema al resolver la IP."

        txt_file.write(f"\nDatos de Shodan para el IP:\n{shodan_result}\n")
        html_file.write(f"<h2>Datos de Shodan</h2><pre>{shodan_result}</pre>")

        # Análisis de Shodan con IA
        if isinstance(shodan_result, dict):  # Verifica se o resultado de Shodan é válido
            shodan_analysis = call_chatgpt(
                f"Analiza los datos de Shodan para la IP {ip} desde una perspectiva de ciberseguridad:\n{shodan_result}"
            )
        else:
            shodan_analysis = "No se encontraron datos relevantes para analizar en Shodan."

        txt_file.write(f"\nAnálisis de Shodan con IA:\n{shodan_analysis}\n")
        html_file.write(f"<h2>Análisis de Shodan con IA</h2><p>{shodan_analysis}</p>")

        # Paso 2. WHOIS con fallback para Amass
        print("[+] Obteniendo información WHOIS...")
        whois_info = "Información WHOIS no disponible"
        try:
            whois_info = run_command(f"whois {parsed_domain}")
            if "No match for" in whois_info or not whois_info.strip():
                print("[!] WHOIS no encontró resultados. Intentando con Amass...")
                whois_info = run_command(f"amass enum -d {parsed_domain} --timeout 60")
        except Exception as e:
            print(f"[!] Error obteniendo WHOIS: {e}")
            whois_info = "Error al obtener información WHOIS."
        txt_file.write(f"\nInformación WHOIS:\n{whois_info}\n")
        html_file.write(f"<h2>Información WHOIS</h2><pre>{whois_info}</pre>")

        # Análisis de WHOIS con IA
        print("[+] Analizando la información WHOIS con IA...")
        whois_analysis = call_chatgpt(
            f"Analiza la información WHOIS desde una perspectiva de ciberseguridad. Identifica vulnerabilidades o datos sensibles:\n{whois_info}"
        )
        txt_file.write(f"\nAnálisis WHOIS con IA:\n{whois_analysis}\n")
        html_file.write(f"<h2>Análisis WHOIS con IA</h2><p>{whois_analysis}</p>")
		
		# Paso 3. Escaneo de Puertos con Nmap
        print("[+] Escaneando puertos abiertos...")
        try:
            nmap_result = run_command(f"nmap -F {parsed_domain}")
            if not nmap_result.strip():
                nmap_result = "No se encontraron hosts activos. Verifica si el dominio está en línea."
        except Exception as e:
            print(f"[!] Error ejecutando Nmap: {e}")
            nmap_result = "Error al realizar el escaneo de puertos."
        txt_file.write(f"\nEscaneo de Puertos:\n{nmap_result}\n")
        html_file.write(f"<h2>Escaneo de Puertos</h2><pre>{nmap_result}</pre>")

        # Análisis de Nmap con IA
        print("[+] Analizando resultados de Nmap con IA...")
        nmap_analysis = call_chatgpt(
            f"Analiza los resultados de Nmap a continuación desde una perspectiva de ciberseguridad:\n{nmap_result}"
        )
        txt_file.write(f"\nAnálisis de Nmap con IA:\n{nmap_analysis}\n")
        html_file.write(f"<h2>Análisis de Nmap con IA</h2><p>{nmap_analysis}</p>")

        # Paso 4. Links indexados con Google Dorks y Photon
        print("[+] Obteniendo enlaces indexados...")
        dorks = [
            f"site:{parsed_domain}",
            f"site:{parsed_domain} filetype:pdf",
            f"site:{parsed_domain} inurl:login",
            f"site:{parsed_domain} intitle:index.of",
            f"site:{parsed_domain} inurl:config",
            f"site:{parsed_domain} \"password\"",
            f"site:*.{parsed_domain}",
            f"site:{parsed_domain} filetype:doc",
            f"site:{parsed_domain} filetype:xls",
            f"site:{parsed_domain} \"API key\"",
            f"site:{parsed_domain} \"error\"",
            f"site:{parsed_domain} \"debug\""
        ]
        all_links = []

        for dork in dorks:
            print(f"[+] Ejecutando Google Dork: {dork}")
            try:
                google_search_url = f"https://www.google.com/search?q={dork}"
                google_response = requests.get(google_search_url, timeout=10)
                soup = BeautifulSoup(google_response.text, "html.parser")
                links = [a["href"] for a in soup.find_all("a", href=True) if "http" in a["href"]]
                all_links.extend(links)
            except Exception as e:
                print(f"[!] Error ejecutando el dork {dork}: {e}")

        print("[+] Ejecutando Photon para recolección adicional de enlaces...")
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
            print(f"[!] Error ejecutando Photon: {e}")

        txt_file.write("\nEnlaces indexados:\n")
        html_file.write("<h2>Enlaces Indexados</h2><ul>")
        for link in set(all_links):  # Eliminar duplicados
            txt_file.write(f"{link}\n")
            html_file.write(f"<li><a href='{link}'>{link}</a></li>")
        html_file.write("</ul>")

        # Análisis de Enlaces con IA
        print("[+] Analizando enlaces y archivos con IA...")
        links_analysis_input = "\n".join(all_links)
        links_analysis = call_chatgpt(
            f"Analiza los enlaces y los contenidos indexados para identificar vulnerabilidades, riesgos o datos sensibles:\n{links_analysis_input}"
        )
        txt_file.write(f"\nAnálisis de Enlaces con IA:\n{links_analysis}\n")
        html_file.write(f"<h2>Análisis de Enlaces con IA</h2><p>{links_analysis}</p>")

        # Paso 5. Extracción de Metadatos con Metagoofil
        print("[+] Extrayendo metadatos con Metagoofil...")
        try:
            metagoofil_command = f"metagoofil -d {parsed_domain} -t pdf,txt -l 20 -o metagoofil_output"
            metagoofil_result = run_command(metagoofil_command)
        except Exception as e:
            print(f"[!] Error ejecutando Metagoofil: {e}")
            metagoofil_result = "Error al ejecutar Metagoofil."
        txt_file.write(f"\nMetadatos extraídos:\n{metagoofil_result}\n")
        html_file.write(f"<h2>Metadatos Extraídos</h2><pre>{metagoofil_result}</pre>")

        # Análisis de Metadatos con IA
        print("[+] Analizando metadatos con IA...")
        metadatos_analysis = call_chatgpt(
            f"Analiza los metadatos extraídos por Metagoofil desde una perspectiva de ciberseguridad:\n{metagoofil_result}"
        )
        txt_file.write(f"\nAnálisis de Metadatos con IA:\n{metadatos_analysis}\n")
        html_file.write(f"<h2>Análisis de Metadatos con IA</h2><p>{metadatos_analysis}</p>")

        # Paso 6. Sublist3r
        print("[+] Ejecutando Sublist3r para subdominios...")
        try:
            sublist3r_result = run_command(f"sublist3r -d {parsed_domain}")
        except Exception as e:
            sublist3r_result = f"[!] Error ejecutando Sublist3r: {e}"
        txt_file.write(f"\nSubdominios encontrados (Sublist3r):\n{sublist3r_result}\n")
        html_file.write(f"<h2>Subdominios encontrados</h2><pre>{sublist3r_result}</pre>")

        # Análisis de Sublist3r con IA
        print("[+] Analizando subdominios con IA...")
        sublist3r_analysis = call_chatgpt(
            f"Analiza los subdominios encontrados por Sublist3r desde una perspectiva de ciberseguridad. Identifica posibles riesgos:\n{sublist3r_result}"
        )
        txt_file.write(f"\nAnálisis de Sublist3r con IA:\n{sublist3r_analysis}\n")
        html_file.write(f"<h2>Análisis de Sublist3r con IA</h2><p>{sublist3r_analysis}</p>")

        # Paso 7. WhatWeb
        print("[+] Detectando tecnologías con WhatWeb...")
        try:
            whatweb_result = run_command(f"whatweb {parsed_domain}")
        except Exception as e:
            whatweb_result = f"[!] Error ejecutando WhatWeb: {e}"
        txt_file.write(f"\nTecnologías detectadas:\n{whatweb_result}\n")
        html_file.write(f"<h2>Tecnologías detectadas</h2><pre>{whatweb_result}</pre>")

        # Análisis de WhatWeb con IA
        print("[+] Analizando tecnologías detectadas con IA...")
        whatweb_analysis = call_chatgpt(
            f"Analiza las tecnologías detectadas por WhatWeb desde una perspectiva de ciberseguridad. Identifica vulnerabilidades potenciales:\n{whatweb_result}"
        )
        txt_file.write(f"\nAnálisis de WhatWeb con IA:\n{whatweb_analysis}\n")
        html_file.write(f"<h2>Análisis de WhatWeb con IA</h2><p>{whatweb_analysis}</p>")

        # Paso 8. TheHarvester
        print("[+] Recolectando datos con TheHarvester...")
        try:
            # Definimos múltiples fuentes para asegurar resultados
            theharvester_command = f"theHarvester -d {parsed_domain} -b bing,crtsh,certspotter,duckduckgo"
            theharvester_result = run_command(theharvester_command)

            # Verifica si no hay resultados
            if not theharvester_result.strip():
                theharvester_result = "[!] No se encontraron datos con TheHarvester. Revisa el dominio o las fuentes."

        except Exception as e:
            theharvester_result = f"[!] Error ejecutando TheHarvester: {e}"

        # Guardamos los resultados en los informes
        txt_file.write(f"\nDatos recolectados (TheHarvester):\n{theharvester_result}\n")
        html_file.write(f"<h2>Datos recolectados</h2><pre>{theharvester_result}</pre>")

        # Análisis de TheHarvester con IA
        print("[+] Analizando datos recolectados por TheHarvester con IA...")
        try:
            theharvester_analysis = call_chatgpt(
                f"Analiza los datos recolectados por TheHarvester desde una perspectiva de ciberseguridad. Identifica riesgos o datos sensibles:\n{theharvester_result}"
            )
        except Exception as e:
            theharvester_analysis = f"[!] Error al analizar los datos recolectados por TheHarvester con IA: {e}"

        # Guardamos el análisis en los informes
        txt_file.write(f"\nAnálisis de TheHarvester con IA:\n{theharvester_analysis}\n")
        html_file.write(f"<h2>Análisis de TheHarvester con IA</h2><p>{theharvester_analysis}</p>")

        # Paso 9. DNSEnum
        print("[+] Ejecutando DNSEnum...")
        try:
            dnsenum_result = run_command(f"dnsenum {parsed_domain}")
        except Exception as e:
            dnsenum_result = f"[!] Error ejecutando DNSEnum: {e}"
        txt_file.write(f"\nDatos recolectados (DNSEnum):\n{dnsenum_result}\n")
        html_file.write(f"<h2>Datos recolectados</h2><pre>{dnsenum_result}</pre>")

        # Análisis de DNSEnum con IA
        print("[+] Analizando datos recolectados por DNSEnum con IA...")
        dnsenum_analysis = call_chatgpt(
            f"Analiza los datos recolectados por DNSEnum desde una perspectiva de ciberseguridad. Identifica vulnerabilidades potenciales:\n{dnsenum_result}"
        )
        txt_file.write(f"\nAnálisis de DNSEnum con IA:\n{dnsenum_analysis}\n")
        html_file.write(f"<h2>Análisis de DNSEnum con IA</h2><p>{dnsenum_analysis}</p>")

        # Conclusión Final
        print("[+] Generando conclusión final con IA...")
        full_report = open(output_txt).read()
        conclusion = call_chatgpt(
            f"Basándote en el informe completo, resume los hallazgos clave, los riesgos identificados y sugiere estrategias de mitigación de ciberseguridad:\n{full_report}"
        )
        txt_file.write(f"\nConclusión Final:\n{conclusion}\n")
        html_file.write(f"<h2>Conclusión Final</h2><p>{conclusion}</p>")
        html_file.write("</body></html>")

    print(f"Informes guardados en {output_txt} y {output_html}")

if __name__ == "__main__":
    domain = sys.argv[1] if len(sys.argv) > 1 else None
    main(domain)
