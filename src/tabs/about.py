import streamlit as st


def render_about_tab():
    st.markdown(
        """
        <style>
        .about-section {
            margin-top: 1.35rem;
        }

        .about-grid {
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: 1rem;
            margin-top: 0.85rem;
        }

        .about-grid.two {
            grid-template-columns: repeat(2, minmax(0, 1fr));
        }

        .about-card {
            height: 100%;
            background: rgba(30, 41, 59, 0.88);
            border: 1px solid rgba(51, 65, 85, 0.95);
            border-radius: 14px;
            padding: 1.05rem 1.1rem;
        }

        .about-card h3 {
            margin: 0 0 0.45rem;
            color: #38b6ff;
            font-size: 1.05rem;
            font-weight: 800;
        }

        .about-card p {
            margin: 0;
            color: #CBD5E1;
            font-size: 0.93rem;
            line-height: 1.55;
        }

        .about-card strong {
            color: #F8FAFC;
        }

        .about-feature-card {
            background: rgba(30, 41, 59, 0.88);
            border: 1px solid rgba(51, 65, 85, 0.95);
            border-radius: 14px;
            padding: 1.15rem 1.25rem;
            margin-top: 0.9rem;
        }

        .about-feature-card h2 {
            margin: 0 0 0.65rem;
            color: #F8FAFC;
            font-size: 1.55rem;
            font-weight: 800;
            letter-spacing: 0;
        }

        .about-feature-card p {
            margin: 0 0 0.85rem;
            color: #CBD5E1;
            font-size: 0.96rem;
            line-height: 1.6;
        }

        .about-feature-card p:last-child {
            margin-bottom: 0;
        }

        .about-list {
            margin: 0.7rem 0 0;
            padding-left: 1.1rem;
            color: #CBD5E1;
            line-height: 1.6;
        }

        .about-list li {
            margin-bottom: 0.35rem;
        }

        .source-table {
            width: 100%;
            border-collapse: separate;
            border-spacing: 0;
            overflow: hidden;
            margin-top: 0.85rem;
            border: 1px solid rgba(51, 65, 85, 0.95);
            border-radius: 14px;
        }

        .source-table th {
            background: rgba(0, 74, 173, 0.34);
            color: #F8FAFC;
            padding: 0.85rem 1rem;
            text-align: left;
            font-weight: 800;
            border-bottom: 1px solid rgba(51, 65, 85, 0.95);
        }

        .source-table td {
            background: rgba(30, 41, 59, 0.72);
            color: #CBD5E1;
            padding: 0.85rem 1rem;
            border-bottom: 1px solid rgba(51, 65, 85, 0.72);
            vertical-align: top;
            line-height: 1.45;
        }

        .source-table tr:last-child td {
            border-bottom: none;
        }

        .source-table td:first-child {
            width: 16%;
            color: #F8FAFC;
            font-weight: 800;
        }

        @media (max-width: 980px) {
            .about-grid,
            .about-grid.two {
                grid-template-columns: 1fr;
            }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <div class="about-feature-card">
            <h2>Sobre a Vulnera</h2>
            <p>
                A Vulnera é uma plataforma analítica para integração, visualização e
                análise de vulnerabilidades de segurança da informação. O projeto reúne
                dados públicos de diferentes fontes para apoiar a priorização de correções,
                a investigação de risco e a compreensão de padrões associados à exploração
                de vulnerabilidades.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown('<div class="about-section">', unsafe_allow_html=True)
    st.markdown(
        """
        <div class="about-feature-card">
            <h2>Problema Abordado</h2>
            <p>
                O crescimento contínuo do volume de CVEs torna a priorização de correções
                uma tarefa cada vez mais complexa. A severidade técnica indicada pelo CVSS
                é uma dimensão importante, mas não é suficiente para representar, sozinha,
                a urgência operacional de uma vulnerabilidade.
            </p>
            <p>
                Por isso, a plataforma combina severidade, probabilidade de exploração,
                exploração ativa conhecida, fraquezas de software e padrões de ataque.
                Essa integração permite uma leitura mais próxima do risco observado e
                apoia decisões de segurança mais contextualizadas.
            </p>
        </div>
        """
        ,
        unsafe_allow_html=True,
    )
    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown('<div class="about-section">', unsafe_allow_html=True)
    st.markdown(
        """
        <div class="about-feature-card">
            <h2>Objetivo do Projeto</h2>
            <p>
                O objetivo da Vulnera é oferecer um ambiente interativo para análise de
                vulnerabilidades, permitindo correlacionar informações de múltiplas fontes
                públicas e transformar esses dados em visualizações, indicadores e consultas
                úteis para priorização baseada em risco.
            </p>
        </div>
        """
        ,
        unsafe_allow_html=True,
    )
    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown('<div class="about-section">', unsafe_allow_html=True)
    st.subheader("Fontes de Dados Integradas")
    st.markdown(
        """
        <table class="source-table">
            <thead>
                <tr>
                    <th>Fonte</th>
                    <th>Papel na plataforma</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td>CVE/NVD</td>
                    <td>Base central das vulnerabilidades, incluindo identificação, datas, descrições e métricas técnicas.</td>
                </tr>
                <tr>
                    <td>CVSS</td>
                    <td>Representa a severidade técnica da vulnerabilidade por meio de score, classificação e vetor de métricas.</td>
                </tr>
                <tr>
                    <td>EPSS</td>
                    <td>Estima a probabilidade de exploração de uma CVE, oferecendo uma dimensão preditiva para priorização.</td>
                </tr>
                <tr>
                    <td>CISA KEV</td>
                    <td>Identifica vulnerabilidades com exploração ativa conhecida, incluindo informações de ransomware quando disponíveis.</td>
                </tr>
                <tr>
                    <td>CWE</td>
                    <td>Classifica as fraquezas de software associadas às vulnerabilidades, apoiando a análise de causa raiz.</td>
                </tr>
                <tr>
                    <td>CAPEC</td>
                    <td>Auxilia o relacionamento entre fraquezas de software e padrões de ataque conhecidos.</td>
                </tr>
                <tr>
                    <td>MITRE ATT&CK</td>
                    <td>Contextualiza técnicas e táticas ofensivas relacionadas às fraquezas e vulnerabilidades analisadas.</td>
                </tr>
            </tbody>
        </table>
        """,
        unsafe_allow_html=True,
    )
    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown('<div class="about-section">', unsafe_allow_html=True)
    st.subheader("Módulos da Plataforma")
    st.markdown(
        """
        <div class="about-grid">
            <div class="about-card">
                <h3>Visão Geral</h3>
                <p>Apresenta métricas globais, evolução temporal e distribuição das vulnerabilidades por severidade.</p>
            </div>
            <div class="about-card">
                <h3>Consulta CVE</h3>
                <p>Permite consultar vulnerabilidades individuais e visualizar detalhes integrados de CVSS, EPSS, KEV, CWE e MITRE.</p>
            </div>
            <div class="about-card">
                <h3>Risco e Exploração</h3>
                <p>Relaciona severidade, probabilidade de exploração e presença no catálogo KEV para apoiar a priorização.</p>
            </div>
            <div class="about-card">
                <h3>Raiz do Problema</h3>
                <p>Explora as fraquezas de software mais recorrentes e sua relação com vulnerabilidades críticas ou exploradas.</p>
            </div>
            <div class="about-card">
                <h3>Padrões de Ataque</h3>
                <p>Conecta vulnerabilidades e CWEs a técnicas e táticas do MITRE ATT&CK para análise orientada a ameaças.</p>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown('<div class="about-section">', unsafe_allow_html=True)
    st.subheader("Arquitetura Resumida")
    st.markdown(
        """
        <div class="about-grid">
            <div class="about-card">
                <h3>Ingestão e processamento</h3>
                <p>Scripts em Python coletam, transformam e integram dados das fontes públicas utilizadas pelo projeto.</p>
            </div>
            <div class="about-card">
                <h3>Persistência relacional</h3>
                <p>O PostgreSQL centraliza vulnerabilidades, scores, catálogos e relacionamentos entre CVE, CWE e MITRE.</p>
            </div>
            <div class="about-card">
                <h3>Visualização interativa</h3>
                <p>A interface em Streamlit e Plotly apresenta dashboards, filtros, gráficos e consultas exploratórias.</p>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown('<div class="about-section">', unsafe_allow_html=True)
    st.subheader("Escopo e Limitações")
    st.markdown(
        """
        <div class="about-grid two">
            <div class="about-card">
                <h3>Escopo</h3>
                <p>
                    A plataforma foi desenvolvida para apoiar análise exploratória e priorização
                    de vulnerabilidades a partir de dados públicos. Seu foco é integrar dimensões
                    complementares de risco em um ambiente único de consulta e visualização.
                </p>
            </div>
            <div class="about-card">
                <h3>Limitações</h3>
                <p>
                    Os resultados dependem da disponibilidade e qualidade das fontes originais.
                    O EPSS representa uma estimativa probabilística, o KEV cobre exploração
                    confirmada pela CISA e os mapeamentos CWE/MITRE devem ser interpretados
                    como apoio analítico.
                </p>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.markdown("</div>", unsafe_allow_html=True)
