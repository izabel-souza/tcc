# --- IMPORTS ---
import streamlit as st
import plotly.express as px
from src.utils.database import get_data

#FUNCAO COM OS GRAFICOS
def render_cwe_tab(filtro_sql):

    st.header("Fraquezas de Software (CWE)")

    c1, c2 = st.columns(2)

    #Grafico Top 10 CWEs 
    with c1:
        with st.container(border=True):
            st.subheader("Top 10 CWEs")
            q_cwe = f"""
                SELECT 
                    cw.id || ' - ' || SUBSTRING(cw.description, 1, 30) || '...' as fraqueza, 
                    COUNT(m.cve_id) as qtd
                FROM cve_cwe_mapping m 
                JOIN cwes cw ON m.cwe_id = cw.id 
                JOIN cves c ON m.cve_id = c.id
                WHERE {filtro_sql} 
                GROUP BY 1 
                ORDER BY 2 DESC 
                LIMIT 10
            """

            df_cwe = get_data(q_cwe)

            fig_cwe = px.bar(
                df_cwe,
                x='qtd',
                y='fraqueza',
                orientation='h',
                labels={
                    'fraqueza': 'Fraqueza',
                    'qtd': 'Quantidade'
                },
            )

            # AJUSTE DE TRANSPARÊNCIA PARA O CARD
            fig_cwe.update_layout(
                paper_bgcolor='rgba(0,0,0,0)', # fundo do papel transparente
                plot_bgcolor='rgba(0,0,0,0)',  # fundo do gráfico transparente
                legend_itemclick="toggleothers"
            )

            fig_cwe.update_layout(yaxis={'categoryorder': 'total ascending'})
            st.plotly_chart(fig_cwe, width='stretch', key=f"cwe_g_{filtro_sql}")

    # Grafico Top 10 CWEs em Vulnerabilidades Críticas
    with c2:
        with st.container(border=True):
            st.subheader("Top 10 CWEs em Vulnerabilidades Críticas")
            q_cwe_c = f"""
                SELECT 
                    cw.id || ' - ' || SUBSTRING(cw.description, 1, 40) || '...' as fraqueza, 
                    COUNT(m.cve_id) as qtd
                FROM cve_cwe_mapping m 
                JOIN cwes cw ON m.cwe_id = cw.id 
                JOIN cves c ON m.cve_id = c.id
                WHERE c.cvss_base_severity = 'CRITICAL' AND {filtro_sql} 
                GROUP BY 1 
                ORDER BY 2 DESC 
                LIMIT 10
            """

            df_cwe_c = get_data(q_cwe_c)

            fig_cwe_c = px.bar(df_cwe_c,
                           x='qtd',
                           y='fraqueza',
                           orientation='h',
                           labels={
                               'fraqueza': 'Fraqueza',
                               'qtd': 'Quantidade'
                           },
                           color_discrete_sequence=['darkred'])
            
            fig_cwe_c.update_layout(
                yaxis={'categoryorder': 'total ascending'},
                paper_bgcolor='rgba(0,0,0,0)', # fundo do papel transparente
                plot_bgcolor='rgba(0,0,0,0)',  # fundo do gráfico transparente        
            )

            st.plotly_chart(fig_cwe_c, width='stretch', key=f"cwe_c_{filtro_sql}")

    st.divider()

    # ==============================================================================
    # CASO DE USO 2: IDENTIFICAÇÃO DE FRAQUEZAS ASSOCIADAS A RISCO REAL
    # ==============================================================================
    with st.container(border=True):
        st.subheader("Análise de Fraquezas por Perspectivas de Risco")

        # Seletor para abranger todo o escopo da ideia analítica
        opcao_analise = st.selectbox(
            "Selecione a perspectiva de análise das fraquezas:", [
                "Mais Frequentes (Volume Total)",
                "Mais Frequentes em Vulnerabilidades Críticas",
                "Mais Presentes em Exploração Ativa (KEV)",
                "Maior Média de Probabilidade de Exploração (EPSS)"
            ]
        )

        # Lógica de consulta baseada na opção selecionada
        if opcao_analise == "Mais Frequentes (Volume Total)":
            order_by = "total_vulnerabilidades DESC"
            extra_filter = ""
            y_axis = "total_vulnerabilidades"
            label_y = "Total de Vulnerabilidades"
            titulo_grafico = "Top 10 Fraquezas por Volume Total de Registros"

        elif opcao_analise == "Mais Frequentes em Vulnerabilidades Críticas":
            order_by = "total_vulnerabilidades DESC"
            extra_filter = "AND c.cvss_base_severity = 'CRITICAL'"
            y_axis = "total_vulnerabilidades"
            label_y = "Quantidade de Vulnerabilidades Críticas"
            titulo_grafico = "Top 10 Fraquezas em Vulnerabilidades de Severidade Crítica"

        elif opcao_analise == "Mais Presentes em Exploração Ativa (KEV)":
            order_by = "quantidade_no_kev DESC"
            extra_filter = "AND k.cve_id IS NOT NULL"
            y_axis = "quantidade_no_kev"
            label_y = "Quantidade no Catálogo KEV"
            titulo_grafico = "Fraquezas com Maior Presença em Exploração Ativa (CISA KEV)"

        else:  # Maior Média de EPSS
            order_by = "media_probabilidade_epss DESC"
            extra_filter = ""
            y_axis = "media_probabilidade_epss"
            label_y = "Média de Probabilidade (EPSS)"
            titulo_grafico = "Fraquezas com Maior Probabilidade Média de Exploração"

        #QUERY PARA METRICAS
        q_cwe_completa = f"""
            SELECT 
                cw.id as identificador_cwe,
                SUBSTRING(cw.description, 1, 40) || '...' as descricao_fraqueza,
                COUNT(DISTINCT c.id) as total_vulnerabilidades,
                COUNT(DISTINCT k.cve_id) as quantidade_no_kev,
                ROUND(AVG(e.epss_score)::numeric, 4) as media_probabilidade_epss
            FROM cwes cw
            JOIN cve_cwe_mapping m ON cw.id = m.cwe_id
            JOIN cves c ON m.cve_id = c.id
            LEFT JOIN kev k ON c.id = k.cve_id
            LEFT JOIN epss_scores e ON c.id = e.cve_id
            WHERE {filtro_sql} {extra_filter}
            GROUP BY 1, 2
            ORDER BY {order_by}
            LIMIT 10
        """

        df_cwe_analise = get_data(q_cwe_completa)

        if not df_cwe_analise.empty:
            fig_cwe_final = px.bar(
                df_cwe_analise,
                x='descricao_fraqueza',
                y=y_axis,
                text_auto='.2f' if "EPSS" in opcao_analise else True,
                labels={
                    'descricao_fraqueza': 'CWE',
                    y_axis: label_y,
                    'identificador_cwe': 'ID CWE'
                },
                title=titulo_grafico,
                color=y_axis,
                color_continuous_scale='Reds')

            fig_cwe_final.update_layout(
                xaxis_tickangle=-45,
                paper_bgcolor='rgba(0,0,0,0)', 
                plot_bgcolor='rgba(0,0,0,0)'
            )

            st.plotly_chart(fig_cwe_final, width='stretch', key=f"cwe_analise_{opcao_analise}_{filtro_sql}")