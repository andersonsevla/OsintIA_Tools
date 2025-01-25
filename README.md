# **OsintIA_Tools.py**

**OsintIA_Tools.py** é uma ferramenta automatizada de coleta e análise de informações públicas, integrando métodos de OSINT (*Open Source Intelligence*) e inteligência artificial para enriquecer os resultados. Este script foi desenvolvido com foco na cibersegurança, permitindo identificar possíveis vulnerabilidades e ameaças em domínios ou organizações.

A ferramenta utiliza várias técnicas e integrações com ferramentas populares para realizar tarefas como resolução de IP, consultas WHOIS, varreduras de portas, coleta de subdomínios, extração de metadados, e muito mais. Além disso, análises avançadas são realizadas com IA (*OpenAI API*) para interpretar os resultados e sugerir ações.

---

## **O que há de novo na versão 3.1**

A nova versão do **OsintIA_Tools_v3.1** traz importantes melhorias para otimizar a usabilidade, confiabilidade e riqueza dos relatórios gerados. Aqui estão as principais novidades:

### **Melhorias no Código**
1. **Geração de Índice HTML Funcional**:
   - O relatório HTML agora inclui um índice interativo, permitindo navegar entre as seções com apenas um clique.

2. **Formatação Avançada do Relatório**:
   - A saída dos textos analisados com IA foi aprimorada, apresentando parágrafos claros e organizados, facilitando a leitura e interpretação.

3. **Remoção de Códigos ANSI**:
   - Caracteres de escape ANSI, como `[94m`, foram completamente removidos dos resultados das ferramentas, como *Sublist3r* e *WhatWeb*, garantindo um relatório limpo e profissional.

4. **Conclusão Final Enriquecida**:
   - Agora, a conclusão do relatório apresenta:
     - Resumo detalhado dos resultados de cada ferramenta (*Shodan*, *Nmap*, *TheHarvester*, entre outras).
     - Identificação de riscos críticos e seu impacto no domínio.
     - Recomendações organizadas por prioridade (*alta*, *média*, *baixa*) para mitigar os riscos.
     - Melhores práticas e ferramentas sugeridas para fortalecer a segurança.

5. **Melhorias na Conexão com a API da OpenAI**:
   - Adicionadas pausas estratégicas antes das chamadas à API para maior estabilidade.
   - Implementado um sistema de *retry* com múltiplas tentativas em caso de falha temporária.

6. **Otimização do DNSEnum**:
   - Utilização de servidores DNS confiáveis (Google, Cloudflare e Quad9).
   - Ajustes no `timeout` e no número de *threads* para reduzir o tempo de execução.

7. **Correções e Estabilidade**:
   - Melhorias na indentação e organização do código para evitar erros como *IndentationError*.
   - Reutilização de funções como `write_section`, garantindo mais eficiência no desenvolvimento e manutenção.

### **Melhorias no Relatório**
1. **Resultados Detalhados por Ferramenta**:
   - Cada ferramenta tem seus resultados apresentados com mais clareza e detalhamento:
     - *Shodan*: Serviços e vulnerabilidades detectadas.
     - *Nmap*: Portas abertas e riscos associados.
     - *TheHarvester*: Subdomínios e pontos de entrada expostos.
     - *DNSEnum*: Possíveis falhas de configuração DNS.
   - Todas as análises foram enriquecidas com IA para identificar riscos e propor soluções práticas.

2. **Navegação Intuitiva**:
   - O índice HTML permite acessar cada seção do relatório de forma rápida e eficiente.

3. **Conclusão Final Robusta**:
   - A conclusão apresenta:
     - Resumo executivo dos principais achados.
     - Riscos organizados por prioridade.
     - Recomendações práticas e detalhadas.

---

## **Funcionalidades**

### **Principais Funções**
- **Resolução de IP com Shodan**:
  - Obtém informações detalhadas do IP utilizando *Shodan*.
  - Inclui verificações adicionais com *dig* e *ping* como fallback.

- **Consulta WHOIS com Fallback para Amass**:
  - Realiza consultas *WHOIS* para obter informações sobre o domínio.
  - Utiliza o *Amass* como alternativa para consultas mais abrangentes.

- **Escaneamento de Portas com Nmap**:
  - Identifica portas abertas e serviços rodando no domínio.
  - Resultados analisados por IA para identificar potenciais riscos.

- **Links Indexados com Google Dorks e Photon**:
  - Realiza buscas avançadas usando Google Dorks.
  - Integra *Photon* para coleta adicional de URLs relacionadas.
  - Analisa os dados coletados com IA para identificar informações sensíveis.

- **Extração de Metadados com Metagoofil**:
  - Busca e baixa arquivos públicos (PDF, DOCX, XLS).
  - Extrai metadados para análise detalhada.
  - Utiliza IA para avaliar os riscos associados aos dados extraídos.

- **Descoberta de Subdomínios com Sublist3r**:
  - Coleta subdomínios associados ao domínio principal.
  - IA analisa os resultados para identificar subdomínios sensíveis ou vulneráveis.

- **Detecção de Tecnologias com WhatWeb**:
  - Identifica tecnologias e frameworks utilizados no site.
  - IA avalia potenciais vulnerabilidades relacionadas às tecnologias detectadas.

- **Coleta de Informações com TheHarvester**:
  - Recolhe e analisa dados como e-mails e hosts utilizando fontes como Google, Bing, CertSpotter, entre outras.
  - Inclui análise com IA para identificar dados sensíveis ou riscos.

- **Enumeração DNS com DNSEnum**:
  - Realiza consultas DNS detalhadas utilizando servidores confiáveis.
  - Analisa os dados obtidos com IA para identificar potenciais falhas de configuração ou exposições.

- **Conclusão Final com IA**:
  - Gera um resumo dos principais achados, riscos e vulnerabilidades identificados.
  - Fornece recomendações práticas de mitigação e melhores práticas de segurança.

---

## **Como Usar**

### **Pré-requisitos**
Certifique-se de que as seguintes dependências estão instaladas no seu sistema:

- **Python 3.10+**
- Bibliotecas Python:
  ```bash
  pip install requests beautifulsoup4 openai
  ```
- Ferramentas do Kali Linux:
  - `dig`, `whois`, `nmap`, `wget`, `metagoofil`, `theHarvester`, `Sublist3r`, `WhatWeb`, `Photon`, `dnsenum`.

---

### **Execução**

1. Clone o repositório:
   ```bash
   git clone https://github.com/seu-usuario/osintia_tools.git
   cd osintia_tools
   ```

2. Execute o script:
   ```bash
   python3 OsintIA_Tools.py <domínio>
   ```

3. Exemplos:
   ```bash
   python3 OsintIA_Tools.py globo.com
   ```

---

### **Saídas**

- **Relatório em Texto**: `osint_report.txt`
- **Relatório em HTML**: `osint_report.html`

---

## **Contribuições**

Contribuições são bem-vindas! Caso queira melhorar ou adicionar funcionalidades:
1. Faça um fork do projeto.
2. Crie um branch para sua funcionalidade:
   ```bash
   git checkout -b minha-melhoria
   ```
3. Submeta um Pull Request!

---

## **Atenção**

Para utilizar o OsintIA_Tools.py, é necessário configurar novas chaves de API para as integrações com a OpenAI e o Shodan. Consulte o release notes para detalhes.

---

## **Licença**

Este projeto é licenciado sob a licença MIT. Consulte o arquivo LICENSE para mais detalhes.

---
