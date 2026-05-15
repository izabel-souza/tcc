# --- IMPORTS ---
import streamlit as st
import plotly.express as px
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
                        'quantidade': 'Quantidade de Vulnerabilidades',
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
                        'quantidade': 'Quantidade de Vulnerabilidades',
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

    st.divider()

    with st.container(border=True): 
        st.subheader("Mapeamento Detalhado (Top 5 Técnicas ➔ CWEs)")

        query_tree = """
            WITH TopTechniques AS (
                -- Descobre quais são os 5 IDs de técnicas mais comuns
                SELECT t.id
                FROM cwe_mitre_mapping cmm
                JOIN mitre_techniques t ON (t.id = cmm.mitre_id OR t.id = 'T' || cmm.mitre_id)
                JOIN cve_cwe_mapping ccm ON cmm.cwe_id = ccm.cwe_id
                GROUP BY t.id
                ORDER BY COUNT(DISTINCT ccm.cve_id) DESC
                LIMIT 5
            )
            SELECT 
                t.name AS tecnica,
                cw.id || ' - ' || SUBSTRING(cw.description, 1, 30) || '...' AS fraqueza,
                COUNT(DISTINCT ccm.cve_id) AS qtd_cves
            FROM cwe_mitre_mapping cmm
            JOIN mitre_techniques t ON (t.id = cmm.mitre_id OR t.id = 'T' || cmm.mitre_id)
            JOIN cve_cwe_mapping ccm ON cmm.cwe_id = ccm.cwe_id
            JOIN cwes cw ON ccm.cwe_id = cw.id
            WHERE t.id IN (SELECT id FROM TopTechniques)
            GROUP BY t.name, fraqueza
        """

        df_tree = get_data(query_tree)

        if not df_tree.empty:
            fig_tree = px.treemap(
                df_tree,
                path=['tecnica', 'fraqueza'],
                labels={'qtd_cves': 'Quantidade'},
                values='qtd_cves',
                color='qtd_cves',
                color_continuous_scale='Reds'
            )

            fig_tree.update_layout(
                margin=dict(t=20, l=0, r=0, b=0),
                legend_itemclick="toggleothers", 
                legend_itemdoubleclick="toggle"
            )

            st.plotly_chart(fig_tree, width='stretch')

    st.divider()

    # ==============================================================================
    # CASO DE USO 3: RELAÇÃO ENTRE FRAQUEZAS (CWE) E TÁTICAS DE ATAQUE (MITRE)
    # ==============================================================================
    st.subheader("Defesa Baseada em Ameaças: Do Erro ao Comportamento")
    st.markdown("""
    Esta análise conecta a causa raiz técnica (CWE) ao objetivo tático do adversário. 
    Permite entender quais falhas de software facilitam comportamentos específicos de ataque.
    """)

    # 1. Visualização de Fluxo Hierárquico: Tática ➔ Técnica ➔ CWE
    st.write("### Fluxo de Exploração: Tática, Técnica e Fraqueza")

    q_fluxo_mitre = f"""
        SELECT 
            tac.name AS nome_tatica,
            tec.name AS nome_tecnica,
            cw.id AS identificador_fraqueza,
            COUNT(DISTINCT c.id) AS quantidade_vulnerabilidades
        FROM mitre_tactics tac
        JOIN mitre_tactic_technique mtt ON tac.id = mtt.tactic_id
        JOIN mitre_techniques tec ON mtt.technique_id = tec.id
        JOIN cwe_mitre_mapping cmm ON (tec.id = cmm.mitre_id OR tec.id = 'T' || cmm.mitre_id)
        JOIN cwes cw ON cmm.cwe_id = cw.id
        JOIN cve_cwe_mapping ccm ON cw.id = ccm.cwe_id
        JOIN cves c ON ccm.cve_id = c.id
        WHERE {filtro_sql}
        GROUP BY 1, 2, 3
        ORDER BY quantidade_vulnerabilidades DESC
        LIMIT 20
    """

    df_fluxo = get_data(q_fluxo_mitre)

    if not df_fluxo.empty:
        # elo solicitado (Tática -> Técnica -> CWE)
        fig_sunburst = px.sunburst(
            df_fluxo,
            path=['nome_tatica', 'nome_tecnica', 'identificador_fraqueza'],
            values='quantidade_vulnerabilidades',
            title="Hierarquia de Ataque: Tática ➔ Técnica ➔ Fraqueza Associada",
            color='quantidade_vulnerabilidades',
            color_continuous_scale='OrRd',
            labels={
                'nome_tatica': 'Tática (Objetivo)',
                'nome_tecnica': 'Técnica (Método)',
                'identificador_fraqueza': 'Fraqueza (CWE)',
                'quantidade_vulnerabilidades': 'Total de Vulnerabilidades'
            })
        st.plotly_chart(fig_sunburst,
                        width='stretch',
                        key=f"sunburst_mitre_{filtro_sql}")
    else:
        st.info("Dados insuficientes para gerar a visualização hierárquica.")

    st.divider()

    #Rankings Específicos de Priorização
    col_m1, col_m2 = st.columns(2)

    with col_m1:
        with st.container(border=True):

            st.write("### Técnicas Associadas a Falhas Críticas")

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

            st.write("### Táticas Associadas a Fraquezas Exploradas")
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