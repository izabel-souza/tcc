# Análise de Vulnerabilidades de Segurança (CVE Analysis)

Este repositório contém o projeto de Trabalho de Conclusão de Curso (TCC) cujo objetivo é a coleta, integração, análise e visualização de dados de vulnerabilidades de segurança, com base em fontes públicas amplamente utilizadas na área de cibersegurança.

O projeto busca consolidar diferentes bases de dados sobre vulnerabilidades, permitindo análises que auxiliem na compreensão do cenário de riscos, priorização de correções e estudo de tendências.

## Objetivo do Projeto

O objetivo principal do projeto é desenvolver uma plataforma de visualização interativa que permita analisar vulnerabilidades de segurança a partir de diferentes perspectivas, como severidade, probabilidade de exploração e exploração ativa conhecida.

O sistema foi desenvolvido para:

* Análise Histórica e Temporal: Cobertura abrangente de vulnerabilidades registradas entre 2015 e 2026.

* Priorização Baseada em Risco: Cruzamento de dados para separar falhas teóricas de ameaças iminentes.

* Correlação com Ataques Reais: Mapeamento de falhas de software para táticas e técnicas do framework MITRE ATT&CK.

## Fontes de Dados Utilizadas

Atualmente, o projeto utiliza as seguintes fontes de dados:

* **NVD / CVE (National Vulnerability Database):** Base oficial mantida pelo NIST, contendo informações detalhadas sobre vulnerabilidades identificadas por CVE, incluindo severidade, descrição, produtos afetados e classificações de fraquezas (CWE).
* **EPSS (Exploit Prediction Scoring System):** Sistema que fornece uma pontuação probabilística indicando a chance de uma vulnerabilidade ser explorada, auxiliando na priorização baseada em risco real.
* **KEV (Known Exploited Vulnerabilities):** Lista mantida pela CISA que identifica vulnerabilidades já exploradas ativamente, sendo uma fonte crítica para análises de risco.
* **CWE (Common Weakness Enumeration):** Dicionário que classifica dos tipos de falhas de programação que causam vulnerabilidades 
* **MITRE ATT&CK & CAPEC**: Frameworks que descrevem os objetivos (Táticas) e métodos (Técnicas) utilizados pelos adversários.

## Arquitetura do Projeto

A arquitetura do projeto foi definida visando simplicidade, flexibilidade e possibilidade de evolução futura.

**Componentes principais:**

* **Python:** Scripts responsáveis por consumir as APIs das fontes de dados. Realizam o tratamento, normalização e inserção dos dados no banco.
* **Streamlit & Plotly:** Biblioteca utilizada para a construção dos dashboards e visualizações interativas, permitindo rápida prototipação e alto nível de personalização.
* **PostgreSQL:** Banco de dados relacional utilizado para armazenar os dados consolidados. Executado em ambiente containerizado.
* **Docker:** Utilizado para padronizar o ambiente de execução do banco de dados, facilitando testes locais e futura migração para nuvem.
* **Self-hosted Runner:** Execução dos fluxos de automação diretamente no ambiente local para integração com o banco de dados Docker.
* **GitHub Actions:** Automação do pipeline de atualização de dados.


## Automação com GitHub Actions
O projeto conta com uma esteira de CI/CD para Dados que mantém a base atualizada semanalmente.

Workflow Agendado
Localizado em ```.github/workflows/update_data.yml```, o fluxo é executado automaticamente todo domingo à meia-noite, utilizando um Self-hosted Runner para acessar o banco de dados local com segurança.

Segurança (GitHub Secrets)
As credenciais de acesso não estão expostas no código. Para o funcionamento da automação, é necessário configurar os seguintes segredos no repositório do GitHub:

>       DB_PASS: Senha do banco de dados PostgreSQL.
>       NVD_API_KEY: Chave de acesso à API do NIST.

---

## Guia de Instalação e Execução

Siga os passos abaixo para configurar o ambiente e executar o projeto localmente.

### Pré-requisitos
* Git instalado.
* [Docker Desktop](https://www.docker.com/) instalado.
* [Python 3.9+](https://www.python.org/) instalado.
* [GitHub Actions Runner](https://github.com/settings/actions/runners) configurado localmente.

### 1. Configuração do Banco de Dados (Docker)

Na raiz do projeto, execute o comando para subir os containers do PostgreSQL e do pgAdmin:

```bash
docker-compose up -d
```

1.2. Acesso e Configuração do pgAdmin
* Abra o navegador e acesse: http://localhost:5050
* Faça login com as credenciais configuradas no docker-compose.yml:

>       Email: admin@admin.com 
>       Senha: admin

1.3 Conectar ao Servidor:

* No pgAdmin, clique com botão direito em Servers > Register > Server.

* Na aba General:
>       Name (ex: Local Docker).

* Na aba Connection:
>       Host name/address: db (ou host.docker.internal)
>       Port: 5432
>       Username: admin
>       Password: admin_password

> As tabelas são criadas no primeiro boot através do script `ddl.sql` localizado em `docker-entrypoint-initdb/`.

* Clique em Save.


### 2. Instalação das Dependências
Utilize o arquivo de requerimentos para preparar o ambiente:

```bash
pip install -r requirements.txt
```

### 3. Coleta e Orquestração de Dados (ETL)

O projeto utiliza um Orquestrador Central que gerencia a ordem das cargas e a integridade do banco:

```bash
python setup.py
```
O setup.py automatiza a execução dos scripts de coleta localizados na pasta populate-tables. Ele garante que os dados sejam baixados das APIs e inseridos no banco respeitando a integridade referencial (Chaves Estrangeiras).

⚠️ Importante: O orquestrador executa os scripts na ordem abaixo para evitar erros de dependência:

cve.py: Base principal (deve ser o primeiro a ser populado).

kev.py: Catálogo de vulnerabilidades exploradas.

epss.py: Pontuações de risco de exploração.

cwe.py: Dicionário de fraquezas de software.

Se preferir a execução manual (certifique-se de estar com o ambiente virtual ativo):

```bash
# Entra na pasta dos scripts
cd "populate tables"

# Executa a carga principal (Isso pode demorar alguns minutos)
python cve.py

# Executa as cargas complementares
python kev.py
python epss.py
python cwe.py

# Retorna para a raiz do projeto
cd ..
```

### 4. Execução do Dashboard
Com o banco populado, inicie a aplicação Streamlit na raiz do projeto:

```bash
streamlit run app.py
```

O dashboard abrirá automaticamente no seu navegador em: http://localhost:8501
