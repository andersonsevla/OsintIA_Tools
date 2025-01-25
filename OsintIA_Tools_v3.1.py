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

# Configura tus claves de API de OpenAI y Shodan
OPENAI_API_KEY = "sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx_xxxxxxxxxxxxxxxxxxxxxxxxxxxxx_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
SHODAN_API_KEY = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

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
            time.sleep(2 ** attempt)  # Retardo exponencial: 2s, 4s, 8s
            if attempt == 2:  # Última tentativa
                return "Erro: Não foi possível conectar à API de OpenAI."
    return "Erro: Falha ao tentar conectar à API de OpenAI após várias tentativas."

# Función para ejecutar un comando en la terminal
def run_command(command):
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)
    return result.stdout.strip()

# Función para eliminar los códigos ANSI para formateo de colores en la salida del terminal.
def remove_ansi_escape_sequences(text):
    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)

# Función para formatar al texto de análisis de IA dividiéndolo en párrafos HTML claros.
def format_analysis_text(text):
    paragraphs = text.split('\n')
    return ''.join(f'<p>{paragraph.strip()}</p>' for paragraph in paragraphs if paragraph.strip())

# Función que genera un índice HTML basado en las secciones del informe.
def generate_html_index(sections):
    index_html = "<h2>Índice</h2><ul>"
    for section_id, section_name in sections.items():
        index_html += f"<li><a href='#{section_id}'>{section_name}</a></li>"
    index_html += "</ul>"
    return index_html

# Función write_section
def write_section(html_file, section_id, title, content):
    html_file.write(f"<h2 id='{section_id}'>{title}</h2>{content}")

# Función principal
def main(domain):
    print_header()  # Exibe o cabeçalho no terminal
    if not domain:
        print("Uso: python osint_tools_es.py <dominio>")
        sys.exit(1)

    # Verificar e instalar dependencias
    check_and_install_dependencies()

    # Preparar dominio y archivos de salida (Extraer solo el dominio, eliminando "http://" o "https://")
    parsed_domain = urlparse(domain).netloc if "http" in domain else domain

    output_txt = "OsintIA_report.txt"
    output_html = "OsintIA_report.html"

            # Definir las secciones y títulos para el índice
    sections = {
        "resolucion-ip": "Resolución de IP",
        "analisis-ip": "Análisis de IP con IA",
        "datos-shodan": "Datos de Shodan",
        "analisis-shodan": "Análisis de Shodan con IA",
        "informacion-whois": "Información WHOIS",
        "analisis-whois": "Análisis WHOIS con IA",
        "escaneo-puertos": "Escaneo de Puertos con NMAP",
        "analisis-nmap": "Análisis de Nmap con IA",
        "enlaces-indexados": "Enlaces Indexados con Google Dorks y Photon",
        "analisis-enlaces": "Análisis de Enlaces con IA",
        "metadatos-extraidos": "Metadatos Extraídos",
        "analisis-metadatos": "Análisis de Metadatos con IA",
        "subdominios-encontrados": "Subdominios encontrados",
        "analisis-sublist3r": "Análisis de Sublist3r con IA",
        "tecnologias-detectadas": "Tecnologías detectadas",
        "analisis-whatweb": "Análisis de WhatWeb con IA",
        "datos-recolectados": "Datos recolectados con TheHarvester",
        "analisis-theharvester": "Análisis de TheHarvester con IA",
        "dnsenum-resultados": "Resultados de DNSEnum",
        "analisis-dnsenum": "Análisis de DNSEnum con IA",
        "conclusion-final": "Conclusión Final",
    }

    with open(output_txt, "w") as txt_file, open(output_html, "w") as html_file:
        html_file.write(f"<html><body><h1>Informe de OsintIA_Tools para {parsed_domain}</h1>")
        
        # Agregar índice al HTML
        html_file.write(generate_html_index(sections))

        # Paso 0. Resolución de IP con verificaciones adicionales
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
        write_section(html_file, "resolucion-ip", "Resolución de IP", f"<p>IP: {ip}</p>")

        # Análisis de IP con IA
        print("[+] Analizando la IP obtenida con IA...")
        ip_analysis = call_chatgpt(
            f"Analiza la dirección IP obtenida ({ip}) desde una perspectiva de ciberseguridad. Identifica posibles riesgos asociados."
        )
        formatted_ip_analysis = format_analysis_text(ip_analysis)
        txt_file.write(f"\nAnálisis de IP con IA:\n{ip_analysis}\n")
        write_section(html_file, "analisis-ip", "Análisis de IP con IA", formatted_ip_analysis)

                # Paso 1. Consultar Shodan
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
        write_section(html_file, "datos-shodan", "Datos de Shodan", f"<pre>{shodan_result}</pre>")

        # Análisis de Shodan con IA
        if isinstance(shodan_result, dict):  # Verifica se o resultado de Shodan es válido
            shodan_analysis = call_chatgpt(
                f"Analiza los datos de Shodan para la IP {ip} desde una perspectiva de ciberseguridad:\n{shodan_result}"
            )
            formatted_shodan_analysis = format_analysis_text(shodan_analysis)
        else:
            shodan_analysis = "No se encontraron datos relevantes para analizar en Shodan."
            formatted_shodan_analysis = f"<p>{shodan_analysis}</p>"

        txt_file.write(f"\nAnálisis de Shodan con IA:\n{shodan_analysis}\n")
        write_section(html_file, "analisis-shodan", "Análisis de Shodan con IA", formatted_shodan_analysis)

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
        write_section(html_file, "informacion-whois", "Información WHOIS", f"<pre>{whois_info}</pre>")

        # Análisis de WHOIS con IA
        print("[+] Analizando la información WHOIS con IA...")
        whois_analysis = call_chatgpt(
            f"Analiza la información WHOIS desde una perspectiva de ciberseguridad. Identifica vulnerabilidades o datos sensibles:\n{whois_info}"
        )
        formatted_whois_analysis = format_analysis_text(whois_analysis)
        txt_file.write(f"\nAnálisis WHOIS con IA:\n{whois_analysis}\n")
        write_section(html_file, "analisis-whois", "Análisis de WHOIS con IA", formatted_whois_analysis)

		        # Paso 3. Escaneo de Puertos con Nmap
        print("[+] Escaneando puertos abiertos con NMAP...")
        try:
            nmap_result = run_command(f"nmap -F {parsed_domain}")
            if not nmap_result.strip():
                nmap_result = "No se encontraron hosts activos. Verifica si el dominio está en línea."
        except Exception as e:
            print(f"[!] Error ejecutando Nmap: {e}")
            nmap_result = "Error al realizar el escaneo de puertos."

        txt_file.write(f"\nEscaneo de Puertos:\n{nmap_result}\n")
        write_section(html_file, "escaneo-puertos", "Escaneo de Puertos", f"<pre>{nmap_result}</pre>")

        # Pausa antes de llamar a la API
        time.sleep(10)  # Pausa de 10 segundos para dar estabilidad a la conexión

        # Análisis de Nmap con IA
        print("[+] Analizando resultados de Nmap con IA...")
        try:
            nmap_analysis = call_chatgpt(
                f"Analiza los resultados de Nmap a continuación desde una perspectiva de ciberseguridad:\n{nmap_result}"
            )
            formatted_nmap_analysis = format_analysis_text(nmap_analysis)
        except Exception as e:
            nmap_analysis = f"[!] Error al analizar resultados de Nmap con IA: {e}"
            formatted_nmap_analysis = f"<p>{nmap_analysis}</p>"

        txt_file.write(f"\nAnálisis de Nmap con IA:\n{nmap_analysis}\n")
        write_section(html_file, "analisis-nmap", "Análisis de Nmap con IA", formatted_nmap_analysis)

                # Paso 4. Links indexados con Google Dorks y Photon
        print("[+] Obteniendo enlaces indexados con Google Dorks y Photon...")
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
        write_section(html_file, "enlaces-indexados", "Enlaces Indexados", "<ul>")
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
        formatted_links_analysis = format_analysis_text(links_analysis)
        txt_file.write(f"\nAnálisis de Enlaces con IA:\n{links_analysis}\n")
        write_section(html_file, "analisis-enlaces", "Análisis de Enlaces con IA", formatted_links_analysis)

                # Paso 5. Extracción de Metadatos con Metagoofil
        print("[+] Extrayendo metadatos con Metagoofil...")
        try:
            metagoofil_command = f"metagoofil -d {parsed_domain} -t pdf,txt -l 20 -o metagoofil_output"
            metagoofil_result = run_command(metagoofil_command)
        except Exception as e:
            print(f"[!] Error ejecutando Metagoofil: {e}")
            metagoofil_result = "Error al ejecutar Metagoofil."
        
        txt_file.write(f"\nMetadatos extraídos:\n{metagoofil_result}\n")
        write_section(html_file, "metadatos-extraidos", "Metadatos Extraídos", f"<pre>{metagoofil_result}</pre>")

        # Análisis de Metadatos con IA
        print("[+] Analizando metadatos con IA...")
        metadatos_analysis = call_chatgpt(
            f"Analiza los metadatos extraídos por Metagoofil desde una perspectiva de ciberseguridad:\n{metagoofil_result}"
        )
        formatted_metadatos_analysis = format_analysis_text(metadatos_analysis)
        txt_file.write(f"\nAnálisis de Metadatos con IA:\n{metadatos_analysis}\n")
        write_section(html_file, "analisis-metadatos", "Análisis de Metadatos con IA", formatted_metadatos_analysis)

                # Paso 6. Sublist3r
        print("[+] Ejecutando Sublist3r para subdominios...")
        try:
            sublist3r_result = run_command(f"sublist3r -d {parsed_domain}")
            cleaned_sublist3r_result = remove_ansi_escape_sequences(sublist3r_result)
        except Exception as e:
            cleaned_sublist3r_result = f"[!] Error ejecutando Sublist3r: {e}"

        txt_file.write(f"\nSubdominios encontrados (Sublist3r):\n{cleaned_sublist3r_result}\n")
        write_section(html_file, "subdominios-encontrados", "Subdominios encontrados", f"<pre>{cleaned_sublist3r_result}</pre>")

        # Análisis de Sublist3r con IA
        print("[+] Analizando subdominios con IA...")
        sublist3r_analysis = call_chatgpt(
            f"Analiza los subdominios encontrados por Sublist3r desde una perspectiva de ciberseguridad. Identifica posibles riesgos:\n{cleaned_sublist3r_result}"
        )
        formatted_sublist3r_analysis = format_analysis_text(sublist3r_analysis)
        txt_file.write(f"\nAnálisis de Sublist3r con IA:\n{sublist3r_analysis}\n")
        write_section(html_file, "analisis-sublist3r", "Análisis de Sublist3r con IA", formatted_sublist3r_analysis)

                # Paso 7. WhatWeb
        print("[+] Detectando tecnologías con WhatWeb...")
        try:
            whatweb_result = run_command(f"whatweb {parsed_domain}")
            cleaned_whatweb_result = remove_ansi_escape_sequences(whatweb_result)
        except Exception as e:
            cleaned_whatweb_result = f"[!] Error ejecutando WhatWeb: {e}"
        
        txt_file.write(f"\nTecnologías detectadas:\n{cleaned_whatweb_result}\n")
        write_section(html_file, "tecnologias-detectadas", "Tecnologías detectadas", f"<pre>{cleaned_whatweb_result}</pre>")

        # Análisis de WhatWeb con IA
        print("[+] Analizando tecnologías detectadas con IA...")
        whatweb_analysis = call_chatgpt(
            f"Analiza las tecnologías detectadas por WhatWeb desde una perspectiva de ciberseguridad. Identifica vulnerabilidades potenciales:\n{cleaned_whatweb_result}"
        )
        formatted_whatweb_analysis = format_analysis_text(whatweb_analysis)
        txt_file.write(f"\nAnálisis de WhatWeb con IA:\n{whatweb_analysis}\n")
        write_section(html_file, "analisis-whatweb", "Análisis de WhatWeb con IA", formatted_whatweb_analysis)

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

        # Limpiamos caracteres ANSI para mejorar la legibilidad
        cleaned_theharvester_result = remove_ansi_escape_sequences(theharvester_result)

        # Guardamos los resultados en los informes
        txt_file.write(f"\nDatos recolectados (TheHarvester):\n{cleaned_theharvester_result}\n")
        write_section(html_file, "datos-recolectados", "Datos recolectados con TheHarvester", f"<pre>{cleaned_theharvester_result}</pre>")

        # Análisis de TheHarvester con IA
        print("[+] Analizando datos recolectados por TheHarvester con IA...")
        try:
            theharvester_analysis = call_chatgpt(
                f"Analiza los datos recolectados por TheHarvester desde una perspectiva de ciberseguridad. Identifica riesgos o datos sensibles:\n{cleaned_theharvester_result}"
            )
            formatted_theharvester_analysis = format_analysis_text(theharvester_analysis)
        except Exception as e:
            theharvester_analysis = f"[!] Error al analizar los datos recolectados por TheHarvester con IA: {e}"
            formatted_theharvester_analysis = f"<p>{theharvester_analysis}</p>"

        # Guardamos el análisis en los informes
        txt_file.write(f"\nAnálisis de TheHarvester con IA:\n{theharvester_analysis}\n")
        write_section(html_file, "analisis-theharvester", "Análisis de TheHarvester con IA", formatted_theharvester_analysis)

                # Paso 9. DNSEnum
        print("[+] Ejecutando DNSEnum...")
        try:
            dnsenum_command = (
            f"dnsenum --dnsserver 8.8.8.8 --dnsserver 1.1.1.1 "
            f"--timeout 3 --threads 15 {parsed_domain}"
            )

            dnsenum_result = run_command(dnsenum_command)
            cleaned_dnsenum_result = remove_ansi_escape_sequences(dnsenum_result)
        except Exception as e:
            cleaned_dnsenum_result = f"[!] Error ejecutando DNSEnum: {e}"

        txt_file.write(f"\nDatos recolectados (DNSEnum):\n{cleaned_dnsenum_result}\n")
        write_section(html_file, "dnsenum-resultados", "Resultados de DNSEnum", f"<pre>{cleaned_dnsenum_result}</pre>")

        # Análisis de DNSEnum con IA
        print("[+] Analizando datos recolectados por DNSEnum con IA...")
        dnsenum_analysis = call_chatgpt(
            f"Analiza los datos recolectados por DNSEnum desde una perspectiva de ciberseguridad. Identifica vulnerabilidades potenciales:\n{cleaned_dnsenum_result}"
        )
        formatted_dnsenum_analysis = format_analysis_text(dnsenum_analysis)

        txt_file.write(f"\nAnálisis de DNSEnum con IA:\n{dnsenum_analysis}\n")
        write_section(html_file, "analisis-dnsenum", "Análisis de DNSEnum con IA", formatted_dnsenum_analysis)

        # Conclusión Final
        print("[+] Generando conclusión final con IA...")
        with open(output_txt, "r") as report_file:
            full_report = report_file.read()

        # Prompt detallado para incluir resumen y recomendaciones
            conclusion_prompt = (
                "Basándote en el informe completo de las herramientas utilizadas en el análisis de ciberseguridad, realiza lo siguiente:\n\n"
                "1. Resume los hallazgos clave de cada herramienta utilizada:\n"
                "   - resolucion-ip\n"
                "   - Shodan\n"
                "   - WHOIS\n"
                "   - Nmap\n"
                "   - Dork\n"
                "   - Metagoofil\n"
                "   - Sublist3r\n"
                "   - WhatWeb\n"
                "   - TheHarvester\n"
                "   - DNSEnum\n"
                "2. Identifica los riesgos más críticos encontrados y explica cómo podrían afectar al dominio analizado.\n"
                "3. Proporciona recomendaciones específicas para mitigar cada riesgo identificado.\n"
                "4. Organiza las recomendaciones según la prioridad (alta, media, baja) basada en el impacto y la probabilidad.\n"
                "5. Sugiere mejores prácticas y herramientas específicas para fortalecer la seguridad del dominio.\n\n"
                "6. Genera un texto conceptual y concluyente sobre todo lo que fue encontrado por las herramientas, destacando la importancia de tener esta información y cómo puede ayudar en el análisis de seguridad de un sitio web.\n\n"
                f"Informe completo:\n{full_report}"
            )

            # Llamar a la API para generar la conclusión
            try:
                conclusion = call_chatgpt(conclusion_prompt)
                # Limpiar caracteres como "**" antes de formatear
                clean_conclusion = conclusion.replace("**", "")
                formatted_conclusion = format_analysis_text(clean_conclusion)
            except Exception as e:
                conclusion = f"[!] Error al generar la conclusión final con IA: {e}"
                formatted_conclusion = f"<p>{conclusion}</p>"

            # Guardar la conclusión en los informes
            txt_file.write(f"\nConclusión Final:\n{conclusion}\n")
            write_section(html_file, "conclusion-final", "Conclusión Final", formatted_conclusion)

            print(f"Informes guardados en {output_txt} y {output_html}")

if __name__ == "__main__":
    domain = sys.argv[1] if len(sys.argv) > 1 else None
    main(domain)

