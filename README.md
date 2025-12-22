# Análise de Vulnerabilidades de Segurança (CVE Analysis)

Este repositório contém o projeto de Trabalho de Conclusão de Curso (TCC) cujo objetivo é a coleta, integração, análise e visualização de dados de vulnerabilidades de segurança, com base em fontes públicas amplamente utilizadas na área de cibersegurança.

O projeto busca consolidar diferentes bases de dados sobre vulnerabilidades, permitindo análises que auxiliem na compreensão do cenário de riscos, priorização de correções e estudo de tendências.

## Objetivo do Projeto

O objetivo principal do projeto é desenvolver uma plataforma de visualização interativa que permita analisar vulnerabilidades de segurança a partir de diferentes perspectivas, como severidade, probabilidade de exploração e exploração ativa conhecida.

O sistema foi pensado para:
* Consolidar dados de múltiplas fontes.
* Normalizar e armazenar essas informações em um banco de dados relacional.
* Disponibilizar dashboards interativos para análise.

## Fontes de Dados Utilizadas

Atualmente, o projeto utiliza as seguintes fontes de dados:

* **NVD / CVE (National Vulnerability Database):** Base oficial mantida pelo NIST, contendo informações detalhadas sobre vulnerabilidades identificadas por CVE, incluindo severidade, descrição, produtos afetados e classificações de fraquezas (CWE).
* **EPSS (Exploit Prediction Scoring System):** Sistema que fornece uma pontuação probabilística indicando a chance de uma vulnerabilidade ser explorada, auxiliando na priorização baseada em risco real.
* **KEV (Known Exploited Vulnerabilities):** Lista mantida pela CISA que identifica vulnerabilidades já exploradas ativamente, sendo uma fonte crítica para análises de risco.

## Arquitetura do Projeto

A arquitetura do projeto foi definida visando simplicidade, flexibilidade e possibilidade de evolução futura.

**Componentes principais:**

* **Python:** Scripts responsáveis por consumir as APIs das fontes de dados. Realizam o tratamento, normalização e inserção dos dados no banco.
* **PostgreSQL:** Banco de dados relacional utilizado para armazenar os dados consolidados. Executado em ambiente containerizado.
* **Docker:** Utilizado para padronizar o ambiente de execução do banco de dados, facilitando testes locais e futura migração para nuvem.
* **Streamlit:** Biblioteca utilizada para a construção dos dashboards e visualizações interativas, permitindo rápida prototipação e alto nível de personalização.

---

## Guia de Instalação e Execução

Siga os passos abaixo para configurar o ambiente e executar o projeto localmente.

### Pré-requisitos
* [Docker](https://www.docker.com/) e Docker Compose instalados.
* [Python 3.9+](https://www.python.org/) instalado.
* Git instalado.

### 1. Configuração do Banco de Dados (Docker)

Na raiz do projeto, execute o comando para subir os containers do PostgreSQL e do pgAdmin:

```bash
docker-compose up -d
```

2. Acesso e Configuração do pgAdmin
Abra o navegador e acesse: http://localhost:5050

Faça login com as credenciais configuradas no docker-compose.yml:

Email: admin@admin.com

Senha: admin

Conectar ao Servidor:

No pgAdmin, clique com botão direito em Servers > Register > Server.

Na aba General, dê um nome (ex: Local Docker).

Na aba Connection:

Host name/address: db (ou host.docker.internal)

Port: 5432

Username: admin

Password: admin_password

Clique em Save.

Criar as Tabelas:

Abra a Query Tool no banco de dados vuln_db.

Vá até a pasta schema/ deste projeto, copie o conteúdo do script SQL (DDL) e execute-o na Query Tool para criar as tabelas e índices.

3. Instalação das Dependências Python

```bash
pip install requests psycopg2 pandas plotly streamlit sqlalchemy
```


4. Coleta de Dados (ETL)
Os scripts de coleta estão localizados na pasta populate tables. Eles devem ser executados para baixar os dados das APIs e popular o banco.

⚠️ Importante: Execute os scripts na ordem abaixo para garantir a integridade dos dados (Chaves Estrangeiras):

cve.py: Base principal (deve ser o primeiro).

kev.py: Catálogo de vulnerabilidades exploradas.

epss.py: Pontuações de risco.

cwe.py: Dicionário de fraquezas.

Comando para execução (certifique-se de estar com o ambiente virtual ativo):

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

5. Execução do Dashboard
Com o banco populado, inicie a aplicação Streamlit na raiz do projeto:

```bash
streamlit run app.py
```

O dashboard abrirá automaticamente no seu navegador em: http://localhost:8501
