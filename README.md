# OsintIA_Tools.py

**OsintIA_Tools.py** é uma ferramenta automatizada de coleta e análise de informações públicas, integrando métodos de **OSINT (Open Source Intelligence)** e inteligência artificial para enriquecer os resultados. Este script foi desenvolvido com foco na **cibersegurança**, permitindo identificar possíveis vulnerabilidades e ameaças em domínios ou organizações.

A ferramenta utiliza várias técnicas e integrações com ferramentas populares para realizar tarefas como resolução de IP, consultas WHOIS, varreduras de portas, coleta de subdomínios, extração de metadados, e muito mais. Além disso, análises avançadas são realizadas com IA (OpenAI API) para interpretar os resultados e sugerir ações.

---

## Funcionalidades

1. **Resolução de IP com Shodan**:
   - Obtém informações detalhadas do IP utilizando Shodan.
   - Inclui verificações adicionais com `dig` e `ping` como fallback.

2. **Consulta WHOIS com Fallback para Amass**:
   - Realiza consultas WHOIS para obter informações sobre o domínio.
   - Caso falhe, utiliza o Amass para resultados mais abrangentes.

3. **Escaneamento de Portas com Nmap**:
   - Identifica portas abertas e serviços rodando no domínio.
   - Resultados analisados por IA para identificar potenciais riscos.

4. **Links Indexados com Google Dorks e Photon**:
   - Realiza buscas avançadas usando Google Dorks.
   - Integra Photon para coleta adicional de URLs relacionadas.
   - Analisa os dados coletados com IA para identificar informações sensíveis.

5. **Extração de Metadados com Metagoofil**:
   - Busca e baixa arquivos públicos (PDF, DOCX, XLS).
   - Extrai metadados para análise detalhada.
   - Utiliza IA para avaliar os riscos associados aos dados extraídos.

6. **Descoberta de Subdomínios com Sublist3r**:
   - Coleta subdomínios associados ao domínio principal.
   - IA analisa os resultados para identificar subdomínios sensíveis ou vulneráveis.

7. **Detecção de Tecnologias com WhatWeb**:
   - Identifica tecnologias e frameworks utilizados no site.
   - IA avalia potenciais vulnerabilidades relacionadas às tecnologias detectadas.

8. **Coleta de Informações com TheHarvester**:
   - Recolhe e analisa dados como emails e hosts utilizando fontes como Google, Bing, CertSpotter, entre outras.
   - Inclui análise com IA para identificar dados sensíveis ou riscos.

9. **Enumeração DNS com DNSEnum**:
   - Realiza consultas DNS detalhadas.
   - Analisa os dados obtidos com IA para identificar potenciais falhas de configuração ou exposições.

10. **Conclusão Final com IA**:
    - Gera um resumo dos principais achados, riscos e vulnerabilidades identificados.
    - Fornece recomendações práticas de mitigação e melhores práticas de segurança.

---

## Como Usar

### Pré-requisitos
Certifique-se de que as seguintes dependências estão instaladas no seu sistema:
- **Python 3.10+**
- Bibliotecas Python:
  ```bash
  pip install requests beautifulsoup4 openai
Ferramentas do Kali Linux:
dig, whois, nmap, wget, metagoofil, theHarvester, Sublist3r, WhatWeb, Photon, dnsenum.
Execução
Clone o repositório:

bash
Copiar código
git clone https://github.com/seu-usuario/osintia_tools.git
cd osintia_tools
Execute o script:

bash
Copiar código
python3 OsintIA_Tools.py <domínio>
Exemplos:

bash
Copiar código
python3 OsintIA_Tools.py globo.com
python3 OsintIA_Tools.py example.org
Saída
Relatório em Texto: osint_report.txt
Relatório em HTML: osint_report.html
Principais Tecnologias e Ferramentas
Shodan API: Obtenção de dados detalhados sobre IPs e dispositivos conectados.
Nmap: Varredura de portas e identificação de serviços.
Photon: Coleta avançada de URLs indexadas.
Metagoofil: Extração de metadados de arquivos públicos.
WhatWeb: Detecção de tecnologias e frameworks.
Sublist3r: Descoberta de subdomínios.
TheHarvester: Coleta de dados públicos, incluindo emails e hosts.
OpenAI API: Inteligência Artificial para análises detalhadas e recomendações.
Estrutura do Script
Instalação e Verificação de Dependências

O script verifica se todas as dependências estão instaladas e sugere a instalação caso faltem.
Execução de Cada Passo

Para cada passo, resultados são coletados e analisados individualmente.
Após cada coleta, análises são realizadas com IA para enriquecer o relatório.
Relatórios

Os resultados são apresentados de forma clara em arquivos TXT e HTML.
Casos de Uso
Auditoria de Segurança:

Identificação de vulnerabilidades em infraestruturas expostas.
Avaliação de subdomínios e configurações DNS.
Reconhecimento em Pentests:

Coleta de informações para suportar etapas iniciais de testes de invasão.
Análise de Metadados:

Extração e avaliação de dados sensíveis em documentos públicos.
Educação e Pesquisa:

Uso em projetos educacionais e estudos relacionados à cibersegurança e inteligência.
Contribuições
Contribuições são bem-vindas! Caso queira melhorar ou adicionar funcionalidades:

Faça um fork do projeto.
Crie um branch para sua funcionalidade:
bash
Copiar código
git checkout -b minha-melhoria
Submeta um Pull Request!
Licença
Este projeto é licenciado sob a licença MIT. Consulte o arquivo LICENSE para mais detalhes.




