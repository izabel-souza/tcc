import streamlit as st

def render_about_tab():
    st.header("Sobre a Plataforma")
    
    # --- PROPOSTA ---
    st.subheader("Proposta do Projeto")
    st.markdown("""
        Este trabalho apresenta uma plataforma analítica para visualização e análise de vulnerabilidades de segurança da informação. 

        A proposta integra fontes públicas como **NVD/CVE**, **EPSS**, **KEV**, **CWE** e **MITRE ATT&CK**, permitindo relacionar severidade, probabilidade de exploração, exploração ativa e padrões de ataque. 
            
        Por meio de um pipeline de ingestão e processamento de dados, com persistência em banco relacional e dashboard interativo, o sistema viabiliza análises históricas entre **2015 e 2026** e apoia a priorização de correções e a análise de risco.
    """)

    # --- ESTILIZACAO DO GLOSSÁRIO ---
    st.markdown("""
        <style>
        .glossary-table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
            border: 1px solid #374151;
            border-radius: 10px;
            overflow: hidden;
        }
        .glossary-header {
            background-color: #1f77b4; 
            color: white;
            text-align: center;
            font-weight: bold;
            padding: 15px;
            font-size: 18px;
            text-transform: uppercase;
        }
        .glossary-row-header {
            background-color: #111827;
            color: #F9FAFB;
            font-weight: bold;
            padding: 10px;
            border: 1px solid #374151;
            text-align: center;
        }
        .glossary-cell-abbreviation {
            width: 15%;
            background-color: #374151;
            color: #F9FAFB;
            font-weight: semibold;
            padding: 12px;
            border: 1px solid #374151;
            text-align: center;
        }
        .glossary-cell-term {
            width: 25%;
            background-color: #1F2937;
            color: #F9FAFB;
            padding: 12px;
            border: 1px solid #374151;
        }
        .glossary-cell-desc {
            background-color: #1F2937;
            color: white;
            padding: 12px;
            border: 1px solid #374151;
            line-height: 1.5;
        }
        </style>
    """, unsafe_allow_html=True)

    # --- CONSTRUCAO DA TABELA ---
    st.markdown("""
        <table class="glossary-table">
            <thead>
                <tr>
                    <th colspan="3" class="glossary-header" style="text-align: center">GLOSSÁRIO DE TERMOS</th>
                </tr>
                <tr>
                    <th class="glossary-row-header" style="text-align: center">SIGLA</th>
                    <th class="glossary-row-header">TERMO</th>
                    <th class="glossary-row-header">DEFINIÇÃO</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td class="glossary-cell-abbreviation">NVD</td>
                    <td class="glossary-cell-term">National Vulnerability Database</td>
                    <td class="glossary-cell-desc">Banco de dados oficial mantido pelo NIST com informações detalhadas das CVEs.</td>
                </tr>
                <tr>
                    <td class="glossary-cell-abbreviation">CVE</td>
                    <td class="glossary-cell-term">Common Vulnerabilities and Exposures</td>
                    <td class="glossary-cell-desc">Catálogo público que lista vulnerabilidades conhecidas em softwares e sistemas.</td>
                </tr>
                <tr>
                    <td class="glossary-cell-abbreviation">CVSS</td>
                    <td class="glossary-cell-term">Common Vulnerability Scoring System</td>
                    <td class="glossary-cell-desc">Sistema de pontuação (0 a 10) que mede a gravidade técnica de uma vulnerabilidade.</td>
                </tr>
                <tr>
                    <td class="glossary-cell-abbreviation">EPSS</td>
                    <td class="glossary-cell-term">Exploit Prediction Scoring System</td>
                    <td class="glossary-cell-desc">Modelo probabilístico que estima a chance de uma vulnerabilidade ser explorada em ataques reais.</td>
                </tr>
                <tr>
                    <td class="glossary-cell-abbreviation">CWE</td>
                    <td class="glossary-cell-term">Common Weakness Enumeration</td>
                    <td class="glossary-cell-desc">Classificação das causas raiz e falhas de programação que resultam em vulnerabilidades.</td>
                </tr>
                <tr>
                    <td class="glossary-cell-abbreviation">KEV</td>
                    <td class="glossary-cell-term">Known Exploited Vulnerabilities</td>
                    <td class="glossary-cell-desc">Catálogo da CISA que lista falhas com evidência confirmada de exploração ativa.</td>
                </tr>
                <tr>
                    <td class="glossary-cell-abbreviation">ATT&CK</td>
                    <td class="glossary-cell-term">MITRE Adversarial Tactics & Techniques</td>
                    <td class="glossary-cell-desc">Framework que cataloga comportamentos, métodos e táticas de adversários reais.</td>
                </tr>
                <tr>
                    <td class="glossary-cell-abbreviation">CAPEC</td>
                    <td class="glossary-cell-term">Common Attack Pattern Enumeration</td>
                    <td class="glossary-cell-desc">Dicionário de padrões de ataque utilizados para explorar fraquezas de software.</td>
                </tr>
                <tr>
                    <td class="glossary-cell-abbreviation">Ransomware</td>
                    <td class="glossary-cell-term">-</td>
                    <td class="glossary-cell-desc">Malware que sequestra dados digitais e exige resgate para a devolução do acesso.</td>
                </tr>
            </tbody>
        </table>
    """, unsafe_allow_html=True)
