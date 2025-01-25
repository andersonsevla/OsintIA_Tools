# **OsintIA_Tools.py**

**OsintIA_Tools.py** is an automated tool for collecting and analyzing public information, integrating OSINT (*Open Source Intelligence*) methods and artificial intelligence to enhance the results. This script was developed with a focus on cybersecurity, enabling the identification of potential vulnerabilities and threats in domains or organizations.

The tool utilizes various techniques and integrations with popular tools to perform tasks such as IP resolution, WHOIS lookups, port scanning, subdomain collection, metadata extraction, and much more. Additionally, advanced analyses are performed with AI (*OpenAI API*) to interpret results and suggest actions.

---

## **What’s New in Version 3.1**

The new version of **OsintIA_Tools_v3.1** brings significant improvements to optimize usability, reliability, and the richness of generated reports. Here are the main updates:

### **Code Improvements**
1. **Functional HTML Index Generation**:
   - The HTML report now includes an interactive index, allowing navigation between sections with just one click.

2. **Advanced Report Formatting**:
   - The output of AI-analyzed texts has been improved, presenting clear and organized paragraphs, making them easier to read and interpret.

3. **Removal of ANSI Codes**:
   - ANSI escape characters, such as `[94m`, have been completely removed from the results of tools like *Sublist3r* and *WhatWeb*, ensuring a clean and professional report.

4. **Enhanced Final Conclusion**:
   - The report conclusion now includes:
     - Detailed summary of results from each tool (*Shodan*, *Nmap*, *TheHarvester*, among others).
     - Identification of critical risks and their impact on the domain.
     - Recommendations organized by priority (*high*, *medium*, *low*) to mitigate risks.
     - Best practices and suggested tools to strengthen security.

5. **Improvements in OpenAI API Connection**:
   - Strategic pauses have been added before API calls for greater stability.
   - A retry system with multiple attempts has been implemented in case of temporary failure.

6. **DNSEnum Optimization**:
   - Use of reliable DNS servers (Google, Cloudflare, and Quad9).
   - Adjustments to `timeout` and the number of *threads* to reduce execution time.

7. **Fixes and Stability**:
   - Improved indentation and code organization to prevent errors like *IndentationError*.
   - Reuse of functions such as `write_section`, ensuring more efficiency in development and maintenance.

### **Report Improvements**
1. **Detailed Results by Tool**:
   - Each tool’s results are presented with more clarity and detail:
     - *Shodan*: Detected services and vulnerabilities.
     - *Nmap*: Open ports and associated risks.
     - *TheHarvester*: Exposed subdomains and entry points.
     - *DNSEnum*: Possible DNS configuration flaws.
   - All analyses have been enriched with AI to identify risks and propose practical solutions.

2. **Intuitive Navigation**:
   - The HTML index allows quick and efficient access to each section of the report.

3. **Robust Final Conclusion**:
   - The conclusion includes:
     - Executive summary of key findings.
     - Risks organized by priority.
     - Practical and detailed recommendations.

---

## **Features**

### **Key Functions**
- **IP Resolution with Shodan**:
  - Retrieves detailed IP information using *Shodan*.
  - Includes additional checks with *dig* and *ping* as fallback.

- **WHOIS Lookup with Amass Fallback**:
  - Performs *WHOIS* lookups to obtain domain information.
  - Uses *Amass* as an alternative for more comprehensive queries.

- **Port Scanning with Nmap**:
  - Identifies open ports and running services on the domain.
  - Results are analyzed by AI to identify potential risks.

- **Indexed Links with Google Dorks and Photon**:
  - Conducts advanced searches using Google Dorks.
  - Integrates *Photon* for additional collection of related URLs.
  - Analyzes collected data with AI to identify sensitive information.

- **Metadata Extraction with Metagoofil**:
  - Searches and downloads public files (PDF, DOCX, XLS).
  - Extracts metadata for detailed analysis.
  - Uses AI to assess risks associated with extracted data.

- **Subdomain Discovery with Sublist3r**:
  - Collects subdomains associated with the main domain.
  - AI analyzes the results to identify sensitive or vulnerable subdomains.

- **Technology Detection with WhatWeb**:
  - Identifies technologies and frameworks used on the website.
  - AI evaluates potential vulnerabilities related to the detected technologies.

- **Information Gathering with TheHarvester**:
  - Collects and analyzes data such as emails and hosts using sources like Google, Bing, CertSpotter, among others.
  - Includes AI analysis to identify sensitive data or risks.

- **DNS Enumeration with DNSEnum**:
  - Performs detailed DNS queries using reliable servers.
  - Analyzes the obtained data with AI to identify potential configuration flaws or exposures.

- **Final Conclusion with AI**:
  - Generates a summary of key findings, risks, and identified vulnerabilities.
  - Provides practical mitigation recommendations and best security practices.

---

## **How to Use**

### **Prerequisites**
Ensure the following dependencies are installed on your system:

- **Python 3.10+**
- Python Libraries:
  ```bash
  pip install requests beautifulsoup4 openai
  ```
- Kali Linux Tools:
  - `dig`, `whois`, `nmap`, `wget`, `metagoofil`, `theHarvester`, `Sublist3r`, `WhatWeb`, `Photon`, `dnsenum`.

---

### **Execution**

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/osintia_tools.git
   cd osintia_tools
   ```

2. Run the script:
   ```bash
   python3 OsintIA_Tools.py <domain>
   ```

3. Examples:
   ```bash
   python3 OsintIA_Tools.py example.com
   ```

---

### **Outputs**

- **Text Report**: `osint_report.txt`
- **HTML Report**: `osint_report.html`

---

## **Contributions**

Contributions are welcome! If you want to improve or add features:
1. Fork the project.
2. Create a branch for your feature:
   ```bash
   git checkout -b my-improvement
   ```
3. Submit a Pull Request!

---

## **Attention**

To use OsintIA_Tools.py, you must configure new API keys for integrations with OpenAI and Shodan. See the release notes for details.

---

## **License**

This project is licensed under the MIT License. See the LICENSE file for more details.

---

