# --- IMPORTS ---
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from src.utils.database import get_data

#FUNCAO COM OS GRAFICOS
def render_mitre_tab(filtro_sql):

    st.header("Inteligência de Ameaças: MITRE ATT&CK")
    st.markdown(
        "Cruzamento das vulnerabilidades com as Técnicas do MITRE mais prováveis de serem utilizadas pelos atacantes."
    )

    c1, c2 = st.columns([1, 1])

 # Grafico Top 10 Tecnicas
    with c1:
        with st.container(border=True):

            st.subheader("Top 10 Técnicas Mais Utilizadas")
            query_tech = f"""
                SELECT 
                    t.name AS tecnica, 
                    COUNT(DISTINCT c.id) AS quantidade
                FROM cves c
                JOIN cve_cwe_mapping ccm ON c.id = ccm.cve_id
                JOIN cwe_mitre_mapping cmm ON ccm.cwe_id = cmm.cwe_id
                JOIN mitre_techniques t ON (t.id = cmm.mitre_id OR t.id = 'T' || cmm.mitre_id)
                WHERE {filtro_sql}
                GROUP BY t.name
                ORDER BY quantidade DESC
                LIMIT 10
            """

            df_tech = get_data(query_tech)

            if not df_tech.empty:
                fig_tech = px.bar(
                    df_tech,
                    x='quantidade',
                    y='tecnica',
                    orientation='h',
                    labels={
                        'quantidade': 'Quantidade',
                        'tecnica': 'Técnica MITRE'
                    },
                    color='quantidade',
                    color_continuous_scale='Reds'
                )

                fig_tech.update_layout(
                    yaxis={'categoryorder': 'total ascending'},
                    paper_bgcolor='rgba(0,0,0,0)', 
                    plot_bgcolor='rgba(0,0,0,0)'
                )

                st.plotly_chart(fig_tech, width='stretch', key=f"tech_{filtro_sql}")
            else:
                st.info("Nenhuma técnica mapeada para este filtro.")


    # Grafico Top 10 taticas
    with c2:
        with st.container(border=True):
            st.subheader("Top 10 Táticas Mais Reportadas")

            query_taticas = f"""
                SELECT 
                    tac.name AS tatica, 
                    COUNT(DISTINCT c.id) AS quantidade
                FROM cves c
                JOIN cve_cwe_mapping ccm ON c.id = ccm.cve_id
                JOIN cwe_mitre_mapping cmm ON ccm.cwe_id = cmm.cwe_id
                JOIN mitre_techniques tec ON (tec.id = cmm.mitre_id OR tec.id = 'T' || cmm.mitre_id)
                JOIN mitre_tactic_technique mtt ON mtt.technique_id = tec.id
                JOIN mitre_tactics tac ON tac.id = mtt.tactic_id
                WHERE {filtro_sql}
                GROUP BY tac.name
                ORDER BY quantidade DESC
                LIMIT 10
            """

            df_taticas = get_data(query_taticas)

            if not df_taticas.empty:
                fig_taticas = px.bar(
                    df_taticas,
                    x='quantidade',
                    y='tatica',
                    orientation='h',
                    labels={
                        'quantidade': 'Quantidade',
                        'tatica': 'Tática MITRE (Objetivo)'
                    },
                    color='quantidade',
                    color_continuous_scale='Blues'
                )

                fig_taticas.update_layout(
                    yaxis={'categoryorder': 'total ascending'},
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)'
                )

                st.plotly_chart(fig_taticas, width='stretch', key=f"tac_{filtro_sql}")
            else:
                st.info("Nenhuma técnica mapeada para este filtro.")

    st.divider()

    # TREEMAP QUE MOSTRA A RELACAO ENTRE AS TOP 5 TECNICAS E SUAS FRAQUEZAS
    with st.container(border=True): 
        st.subheader("Mapeamento Detalhado: Relação Técnica ➔ Fraqueza (CWE)")
        
        query_tree = f"""
            WITH TopTechniques AS (
                SELECT t.id
                FROM mitre_techniques t
                JOIN cwe_mitre_mapping cmm ON (t.id = cmm.mitre_id OR t.id = 'T' || cmm.mitre_id)
                JOIN cve_cwe_mapping ccm ON cmm.cwe_id = ccm.cwe_id
                JOIN cves c ON ccm.cve_id = c.id
                WHERE {filtro_sql}
                GROUP BY t.id
                ORDER BY COUNT(DISTINCT c.id) DESC
                LIMIT 5
            )
            SELECT 
                t.name AS tecnica,
                cw.id || ' - ' || SUBSTRING(cw.description, 1, 30) || '...' AS fraqueza,
                COUNT(DISTINCT c.id) AS qtd_cves
            FROM cves c
            JOIN cve_cwe_mapping ccm ON c.id = ccm.cve_id
            JOIN cwes cw ON ccm.cwe_id = cw.id
            JOIN cwe_mitre_mapping cmm ON cw.id = cmm.cwe_id
            JOIN mitre_techniques t ON (t.id = cmm.mitre_id OR t.id = 'T' || cmm.mitre_id)
            WHERE t.id IN (SELECT id FROM TopTechniques) AND {filtro_sql}
            GROUP BY 1, 2
            ORDER BY 3 DESC
        """
        
        df_tree = get_data(query_tree)

        if not df_tree.empty:
            fig_tree = px.treemap(
                df_tree, 
                path=['tecnica', 'fraqueza'], 
                values='qtd_cves',
                template="plotly_dark",
                color='qtd_cves',
                color_continuous_scale='Reds',
                labels={'qtd_cves': 'Total de CVEs', 'tecnica': 'Técnica', 'fraqueza': 'Fraqueza (CWE)'}
            )
            fig_tree.update_layout(
                margin=dict(t=30, l=10, r=10, b=10),
                paper_bgcolor='rgba(0,0,0,0)'
            )
            st.plotly_chart(fig_tree, width='stretch', key=f"tree_{filtro_sql}")
        else:
            st.info("Dados insuficientes para o mapeamento detalhado com os filtros atuais.")

    st.divider()

    # ==============================================================================
    # CASO DE USO 3: RELAÇÃO ENTRE FRAQUEZAS (CWE) E TÁTICAS DE ATAQUE (MITRE)
    # ==============================================================================
    with st.container(border=True):

        st.subheader("Defesa Baseada em Ameaças: Do Erro ao Comportamento")
        st.markdown("""
        Esta análise conecta a causa raiz técnica (CWE) ao objetivo tático do adversário. 
        Permite entender quais falhas de software facilitam comportamentos específicos de ataque.
        """)
        
        st.subheader("Fluxograma de Exploração (CWE ➔ Técnica ➔ Tática)")

        query_sankey = f"""
            SELECT 
                cw.id AS origem,
                tec.name AS intermediario,
                tac.name AS destino,
                COUNT(DISTINCT c.id) AS qtd
            FROM mitre_tactics tac
            JOIN mitre_tactic_technique mtt ON tac.id = mtt.tactic_id
            JOIN mitre_techniques tec ON mtt.technique_id = tec.id
            JOIN cwe_mitre_mapping cmm ON (tec.id = cmm.mitre_id OR tec.id = 'T' || cmm.mitre_id)
            JOIN cwes cw ON cmm.cwe_id = cw.id
            JOIN cve_cwe_mapping ccm ON cw.id = ccm.cwe_id
            JOIN cves c ON ccm.cve_id = c.id
            WHERE {filtro_sql}
            GROUP BY 1, 2, 3
            ORDER BY qtd DESC
            LIMIT 50
        """

        df_s = get_data(query_sankey)

        if not df_s.empty:
            # Criando listas únicas de nós para mapeamento de índices
            nodes = list(set(df_s['origem']) | set(df_s['intermediario']) | set(df_s['destino']))
            node_map = {name: i for i, name in enumerate(nodes)}

            # Construindo as conexões (Links)
            # Link 1: CWE -> Técnica
            sources = [node_map[row['origem']] for _, row in df_s.iterrows()]
            targets = [node_map[row['intermediario']] for _, row in df_s.iterrows()]
            values = df_s['qtd'].tolist()

            # Link 2: Técnica -> Tática
            sources.extend([node_map[row['intermediario']] for _, row in df_s.iterrows()])
            targets.extend([node_map[row['destino']] for _, row in df_s.iterrows()])
            values.extend(df_s['qtd'].tolist())

            # Cores baseadas na sua paleta: Azul para Técnicas, Vermelho para Táticas
            node_colors = []
            for node in nodes:
                if node in df_s['origem'].values: node_colors.append("#EAB308") # Amarelo (CWE)
                elif node in df_s['intermediario'].values: node_colors.append("#3B82F6") # Azul (Técnica)
                else: node_colors.append("#EF4444") # Vermelho (Tática)

            fig_sankey = go.Figure(data=[go.Sankey(
                node=dict(
                    pad=15, thickness=20, line=dict(color="black", width=0.5),
                    label=nodes, color=node_colors
                ),
                link=dict(
                    source=sources, target=targets, value=values,
                    color="rgba(255, 255, 255, 0.1)" # Links sutis e transparentes
                )
            )])

            fig_sankey.update_layout(
                title_text="Fluxo de Disseminação de Vulnerabilidades",
                font_size=12, template="plotly_dark",
                paper_bgcolor='rgba(0,0,0,0)',
                height=600
            )

            st.plotly_chart(fig_sankey, width='stretch')

        with st.expander("Guia de Análise: "):
            st.markdown("""
                ### Objetivo: Visualizar a Ponte entre Erro e Comportamento
                Este diagrama de **Sankey** revela como uma falha técnica no código se transforma em uma capacidade de ataque para o adversário. O fluxo segue a lógica: **Onde o erro nasce ➔ Como ele é usado ➔ O que o atacante quer.**

                #### Como ler o fluxo (Da esquerda para a direita):
                1.  **CWE (Amarelo - Origem):** Representa a fraqueza de software (ex: Estouro de Buffer). É a causa raiz técnica.
                2.  **Técnica (Azul - Meio):** Representa o método do **MITRE ATT&CK** utilizado para explorar aquela fraqueza (ex: Execução de API).
                3.  **Tática (Vermelho - Destino):** Representa o objetivo final do atacante (ex: Persistência ou Exfiltração de Dados).

                #### O que observar:
                * **Espessura das Barras:** Quanto mais larga a conexão, maior é o volume de vulnerabilidades que seguem aquele caminho específico.
                * **Convergência:** Observe como diferentes tipos de erros de programação (CWEs) podem convergir para uma mesma técnica de ataque, mostrando a "versatilidade" de certas ferramentas dos invasores.

                #### Valor para a Defesa:
                Este gráfico sustenta o conceito de **Threat-Informed Defense**. Ao entender qual tática é mais alimentada por certas fraquezas, a organização pode priorizar correções de código que "cortam o fluxo" de múltiplos comportamentos de ataque simultaneamente.
            """)


    st.divider()

    #Rankings Específicos de Priorização
    col_m1, col_m2 = st.columns(2)

    with col_m1:
        with st.container(border=True):

            st.write("### Top 10 Técnicas Associadas a Falhas Críticas")

            q_tech_crit = f"""
                SELECT 
                    tec.name AS nome_tecnica,
                    COUNT(DISTINCT c.id) AS quantidade_vulnerabilidades
                FROM mitre_techniques tec
                JOIN cwe_mitre_mapping cmm ON (tec.id = cmm.mitre_id OR tec.id = 'T' || cmm.mitre_id)
                JOIN cve_cwe_mapping ccm ON cmm.cwe_id = ccm.cwe_id
                JOIN cves c ON ccm.cve_id = c.id
                WHERE c.cvss_base_severity = 'CRITICAL' AND {filtro_sql}
                GROUP BY 1
                ORDER BY 2 DESC LIMIT 10
            """

            df_tech_crit = get_data(q_tech_crit)

            fig_tech_crit = px.bar(
                df_tech_crit,
                x='quantidade_vulnerabilidades',
                y='nome_tecnica',
                orientation='h',
                labels={
                    'quantidade_vulnerabilidades': 'Quantidade de Vulnerabilidades Críticas',
                    'nome_tecnica': 'Técnica de Ataque'
                },
                color='quantidade_vulnerabilidades',
                color_continuous_scale='Reds'
            )

            fig_tech_crit.update_layout(
                yaxis={'categoryorder': 'total ascending'},
                paper_bgcolor='rgba(0,0,0,0)', 
                plot_bgcolor='rgba(0,0,0,0)'
            )
        
            st.plotly_chart(fig_tech_crit, width='stretch', key=f"mitre_crit_{filtro_sql}")

    with col_m2:
        with st.container(border=True):

            st.write("### Top 10 Táticas Associadas a Fraquezas Exploradas")
            q_tac_kev = f"""
                SELECT 
                    tac.name AS nome_tatica,
                    COUNT(DISTINCT k.cve_id) AS quantidade_no_catalogo_kev
                FROM mitre_tactics tac
                JOIN mitre_tactic_technique mtt ON tac.id = mtt.tactic_id
                JOIN mitre_techniques tec ON mtt.technique_id = tec.id
                JOIN cwe_mitre_mapping cmm ON (tec.id = cmm.mitre_id OR tec.id = 'T' || cmm.mitre_id)
                JOIN cve_cwe_mapping ccm ON cmm.cwe_id = ccm.cwe_id
                JOIN kev k ON ccm.cve_id = k.cve_id
                JOIN cves c ON k.cve_id = c.id
                WHERE {filtro_sql}
                GROUP BY 1
                ORDER BY 2 DESC 
                LIMIT 10
            """

            df_tac_kev = get_data(q_tac_kev)

            fig_tac_kev = px.bar(
                df_tac_kev,
                x='quantidade_no_catalogo_kev',
                y='nome_tatica',
                orientation='h',
                labels={
                    'quantidade_no_catalogo_kev': 'Quantidade no Catálogo KEV',
                    'nome_tatica': 'Tática do Atacante'
                },
                color='quantidade_no_catalogo_kev',
                color_continuous_scale='Blues')
            
            fig_tac_kev.update_layout(
                yaxis={'categoryorder': 'total ascending'},
                paper_bgcolor='rgba(0,0,0,0)', 
                plot_bgcolor='rgba(0,0,0,0)'
            )

            st.plotly_chart(fig_tac_kev, width='stretch', key=f"mitre_kev_{filtro_sql}")