# --- IMPORTS ---
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from src.utils.database import get_data
from src.utils.components import apply_chart_layout

#FUNCAO COM OS GRAFICOS
def render_mitre_tab(filtro_sql):

    st.subheader("Inteligência de Ameaças: MITRE ATT&CK")
    st.markdown(
        "Cruzamento das vulnerabilidades com as técnicas do MITRE mais prováveis de serem utilizadas pelos atacantes."
    )

    c1, c2 = st.columns([1, 1])

 # Grafico Top 10 Tecnicas
    with c1:
        with st.container(border=True):

            st.subheader("Top 10 Técnicas Mais Associadas")
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
                )
                fig_tech.update_traces(
                    hovertemplate=(
                        "Técnica MITRE: %{y}<br>"
                        "Quantidade: %{x}<extra></extra>"
                    )
                )
                apply_chart_layout(fig_tech)

                st.plotly_chart(fig_tech, width='stretch', key=f"tech_{filtro_sql}")
            else:
                st.info("Nenhuma técnica mapeada para este filtro.")


    # Grafico Top 10 taticas
    with c2:
        with st.container(border=True):
            st.subheader("Top 10 Táticas Mais Associadas")

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
                        'tatica': 'Tática MITRE (objetivo)'
                    },
                    color='quantidade',
                    color_continuous_scale='Blues'
                )

                fig_taticas.update_layout(
                    yaxis={'categoryorder': 'total ascending'},
                )
                fig_taticas.update_traces(
                    hovertemplate=(
                        "Tática MITRE: %{y}<br>"
                        "Quantidade: %{x}<extra></extra>"
                    )
                )
                apply_chart_layout(fig_taticas)

                st.plotly_chart(fig_taticas, width='stretch', key=f"tac_{filtro_sql}")
            else:
                st.info("Nenhuma técnica mapeada para este filtro.")

    st.markdown('<div style="height: 1.2rem;"></div>', unsafe_allow_html=True)

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
                margin=dict(t=45, l=25, r=25, b=25),
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)'
            )
            fig_tree.update_traces(
                hovertemplate=(
                    "Item: %{label}<br>"
                    "Grupo: %{parent}<br>"
                    "Total de CVEs: %{value}<extra></extra>"
                )
            )
            st.plotly_chart(fig_tree, width='stretch', key=f"tree_{filtro_sql}")
        else:
            st.info("Dados insuficientes para o mapeamento detalhado com os filtros atuais.")

    st.markdown('<div style="height: 1.2rem;"></div>', unsafe_allow_html=True)

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

        with st.expander("Guia de análise: "):
            st.markdown("""
                ### Objetivo: visualizar a ponte entre erro e comportamento.
                Este diagrama de Sankey mostra como uma fraqueza técnica de software pode se relacionar com técnicas e táticas do MITRE ATT&CK. O fluxo segue a lógica: onde o erro nasce, como ele pode ser explorado e qual objetivo ofensivo ele pode facilitar.

                #### Como interpretar:
                1. **CWE:** representa a fraqueza de software, ou seja, a causa raiz técnica.
                2. **Técnica:** representa o método de ataque associado no MITRE ATT&CK.
                3. **Tática:** representa o objetivo do adversário, como execução, persistência ou acesso a credenciais.
                4. **Espessura do fluxo:** quanto maior a conexão, maior é a quantidade de vulnerabilidades associadas àquele caminho.

                #### Leitura prática:
                O fluxo ajuda a priorizar fraquezas que alimentam múltiplas técnicas ou táticas relevantes. Isso permite direcionar ações de correção e prevenção para pontos que reduzem mais de um caminho possível de ataque.
            """)

        query_sankey = f"""
            SELECT 
                cw.id AS origem,
                cw.description AS origem_descricao,
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
            GROUP BY 1, 2, 3, 4
            ORDER BY qtd DESC
            LIMIT 30
        """

        df_s = get_data(query_sankey)

        if not df_s.empty:
            # Criando listas únicas de nós para mapeamento de índices
            nodes = list(set(df_s['origem']) | set(df_s['intermediario']) | set(df_s['destino']))
            node_map = {name: i for i, name in enumerate(nodes)}
            cwe_descriptions = dict(zip(df_s['origem'], df_s['origem_descricao']))
            node_customdata = [
                cwe_descriptions.get(node, node)
                for node in nodes
            ]

            # Construindo as conexões (Links)
            # Link 1: CWE -> Técnica
            sources = [node_map[row['origem']] for _, row in df_s.iterrows()]
            targets = [node_map[row['intermediario']] for _, row in df_s.iterrows()]
            values = df_s['qtd'].tolist()
            link_customdata = [
                [f"{row['origem']} - {row['origem_descricao']}", row['intermediario']]
                for _, row in df_s.iterrows()
            ]

            # Link 2: Técnica -> Tática
            sources.extend([node_map[row['intermediario']] for _, row in df_s.iterrows()])
            targets.extend([node_map[row['destino']] for _, row in df_s.iterrows()])
            values.extend(df_s['qtd'].tolist())
            link_customdata.extend([[row['intermediario'], row['destino']] for _, row in df_s.iterrows()])

            # Cores baseadas na sua paleta: Azul para Técnicas, Vermelho para Táticas
            node_colors = []
            for node in nodes:
                if node in df_s['origem'].values: node_colors.append("#EAB308") # Amarelo (CWE)
                elif node in df_s['intermediario'].values: node_colors.append("#3B82F6") # Azul (Técnica)
                else: node_colors.append("#EF4444") # Vermelho (Tática)

            fig_sankey = go.Figure(data=[go.Sankey(
                node=dict(
                    pad=15, thickness=20, line=dict(color="black", width=0.5),
                    label=nodes, color=node_colors,
                    customdata=node_customdata,
                    hovertemplate="Nó: %{label}<br>Descrição: %{customdata}<extra></extra>"
                ),
                link=dict(
                    source=sources, target=targets, value=values,
                    customdata=link_customdata,
                    hovertemplate=(
                        "Origem: %{customdata[0]}<br>"
                        "Destino: %{customdata[1]}<br>"
                        "Quantidade: %{value}<extra></extra>"
                    ),
                    color="rgba(255, 255, 255, 0.1)" # Links sutis e transparentes
                )
            )])

            fig_sankey.update_layout(
                title_text="Fluxo entre Fraquezas, Técnicas e Táticas",
                font_size=12, template="plotly_dark",
                height=600
            )
            apply_chart_layout(fig_sankey, margin=dict(l=50, r=50, t=80, b=50), height=600)

            st.plotly_chart(fig_sankey, width='stretch')

    st.markdown('<div style="height: 1.2rem;"></div>', unsafe_allow_html=True)

    #Rankings Específicos de Priorização
    col_m1, col_m2 = st.columns(2)

    with col_m1:
        with st.container(border=True):

            st.write("### Top 10 Técnicas Associadas a Falhas Críticas")

            q_tech_crit = f"""
                SELECT 
                    tec.name AS nome_tecnica,
                    CASE 
                        WHEN LENGTH(tec.name) > 28 THEN SUBSTRING(tec.name, 1, 28) || '...'
                        ELSE tec.name
                    END AS nome_tecnica_eixo,
                    COUNT(DISTINCT c.id) AS quantidade_vulnerabilidades
                FROM mitre_techniques tec
                JOIN cwe_mitre_mapping cmm ON (tec.id = cmm.mitre_id OR tec.id = 'T' || cmm.mitre_id)
                JOIN cve_cwe_mapping ccm ON cmm.cwe_id = ccm.cwe_id
                JOIN cves c ON ccm.cve_id = c.id
                WHERE c.cvss_base_severity = 'CRITICAL' AND {filtro_sql}
                GROUP BY 1, 2
                ORDER BY 3 DESC LIMIT 10
            """

            df_tech_crit = get_data(q_tech_crit)

            fig_tech_crit = px.bar(
                df_tech_crit,
                x='quantidade_vulnerabilidades',
                y='nome_tecnica_eixo',
                orientation='h',
                labels={
                    'quantidade_vulnerabilidades': 'Quantidade de vulnerabilidades críticas',
                    'nome_tecnica_eixo': 'Técnica de ataque'
                },
                custom_data=['nome_tecnica'],
                color='quantidade_vulnerabilidades',
                color_continuous_scale='Reds'
            )

            fig_tech_crit.update_layout(
                yaxis={'categoryorder': 'total ascending'},
                xaxis=dict(tickangle=0, nticks=5, tickformat="~s"),
                coloraxis_colorbar=dict(title="Quantidade"),
            )
            fig_tech_crit.update_traces(
                hovertemplate=(
                    "Técnica de ataque: %{customdata[0]}<br>"
                    "Quantidade de vulnerabilidades críticas: %{x}<extra></extra>"
                )
            )
            apply_chart_layout(fig_tech_crit)
        
            st.plotly_chart(fig_tech_crit, width='stretch', key=f"mitre_crit_{filtro_sql}")

    with col_m2:
        with st.container(border=True):

            st.write("### Top 10 Táticas Associadas a Exploração Ativa")
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
                    'quantidade_no_catalogo_kev': 'Quantidade no catálogo KEV',
                    'nome_tatica': 'Tática do atacante'
                },
                color='quantidade_no_catalogo_kev',
                color_continuous_scale='Blues')
            
            fig_tac_kev.update_layout(
                yaxis={'categoryorder': 'total ascending'},
                coloraxis_colorbar=dict(title="Quantidade"),
            )
            fig_tac_kev.update_traces(
                hovertemplate=(
                    "Tática do atacante: %{y}<br>"
                    "Quantidade no catálogo KEV: %{x}<extra></extra>"
                )
            )
            apply_chart_layout(fig_tac_kev)

            st.plotly_chart(fig_tac_kev, width='stretch', key=f"mitre_kev_{filtro_sql}")
