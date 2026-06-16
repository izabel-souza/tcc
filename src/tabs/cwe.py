# --- IMPORTS ---
import streamlit as st
import plotly.express as px
from src.utils.database import get_data
from src.utils.components import apply_chart_layout

#FUNCAO COM OS GRAFICOS
def render_cwe_tab(filtro_sql):

    st.subheader("Fraquezas de Software (CWE)")

    c1, c2 = st.columns(2)

    #Grafico Top 10 CWEs 
    with c1:
        with st.container(border=True):
            st.subheader("Top 10 CWEs")
            q_cwe = f"""
                SELECT 
                    cw.id as identificador_cwe,
                    cw.description as descricao_completa,
                    cw.id || ' - ' || SUBSTRING(cw.description, 1, 30) || '...' as fraqueza, 
                    COUNT(m.cve_id) as qtd
                FROM cve_cwe_mapping m 
                JOIN cwes cw ON m.cwe_id = cw.id 
                JOIN cves c ON m.cve_id = c.id
                WHERE {filtro_sql} 
                GROUP BY 1, 2, 3
                ORDER BY 4 DESC 
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
                custom_data=['identificador_cwe', 'descricao_completa'],
                color_discrete_sequence=['#1f77b4']
            )

            # AJUSTE DE TRANSPARÊNCIA PARA O CARD
            fig_cwe.update_layout(
                legend_itemclick="toggleothers"
            )

            fig_cwe.update_layout(yaxis={'categoryorder': 'total ascending'})
            fig_cwe.update_traces(
                hovertemplate=(
                    "<b>%{customdata[0]}</b><br>"
                    "Nome: %{customdata[1]}<br>"
                    "Quantidade: %{x}<extra></extra>"
                )
            )
            apply_chart_layout(fig_cwe)
            st.plotly_chart(fig_cwe, width='stretch', key=f"cwe_g_{filtro_sql}")

    # Grafico Top 10 CWEs em Vulnerabilidades Críticas
    with c2:
        with st.container(border=True):
            st.subheader("Top 10 CWEs em Vulnerabilidades Críticas")
            q_cwe_c = f"""
                SELECT 
                    cw.id as identificador_cwe,
                    cw.description as descricao_completa,
                    cw.id || ' - ' || SUBSTRING(cw.description, 1, 40) || '...' as fraqueza, 
                    COUNT(m.cve_id) as qtd
                FROM cve_cwe_mapping m 
                JOIN cwes cw ON m.cwe_id = cw.id 
                JOIN cves c ON m.cve_id = c.id
                WHERE c.cvss_base_severity = 'CRITICAL' AND {filtro_sql} 
                GROUP BY 1, 2, 3
                ORDER BY 4 DESC 
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
                           custom_data=['identificador_cwe', 'descricao_completa'],
                           color_discrete_sequence=['darkred'])
            
            fig_cwe_c.update_layout(
                yaxis={'categoryorder': 'total ascending'},
            )
            fig_cwe_c.update_traces(
                hovertemplate=(
                    "<b>%{customdata[0]}</b><br>"
                    "Nome: %{customdata[1]}<br>"
                    "Quantidade: %{x}<extra></extra>"
                )
            )
            apply_chart_layout(fig_cwe_c)

            st.plotly_chart(fig_cwe_c, width='stretch', key=f"cwe_c_{filtro_sql}")

    st.divider()

    # ==============================================================================
    # CASO DE USO 2: IDENTIFICAÇÃO DE FRAQUEZAS ASSOCIADAS A RISCO REAL
    # ==============================================================================
    with st.container(border=True):
        st.subheader("Análise de Fraquezas por Perspectivas de Risco")

        with st.expander("Guia de análise:"):
            st.markdown("""
                ### Objetivo: Identificar as falhas de programação mais perigosas
                Este caso de uso investiga quais tipos de erros de desenvolvimento (**CWE**) estão por trás das vulnerabilidades mais exploradas no mundo real.

                #### Como interpretar as 4 perspectivas:
                1.  **Volume total:** Mostra quais falhas são mais comuns na base geral (ex: falhas de permissão ou gestão de memória).
                2.  **Vulnerabilidades críticas:** Filtra as falhas que geram os maiores impactos teóricos (CVSS > 9.0).
                3.  **Exploração ativa (KEV):** Esta é a visão mais importante para defesa. Revela quais erros de programação os atacantes **realmente conseguem explorar** hoje.
                4.  **Maior média EPSS:** Identifica classes de falhas que, estatisticamente, têm maior chance de virarem um problema no futuro próximo.

                #### Valor:
                Esta análise conecta a **segurança de aplicações (AppSec)** com a **inteligência de ameaças**. Ela permite provar que certas classes de fraqueza (como *Injection* ou *Broken Access Control*) concentram muito mais risco prático do que outras, mesmo que não sejam as mais numerosas no total.
            """)

        # Seletor para abranger todo o escopo da ideia analítica
        opcao_analise = st.selectbox(
            "Selecione a perspectiva de análise das fraquezas:", [
                "Mais frequentes (volume total)",
                "Mais frequentes em vulnerabilidades críticas",
                "Mais presentes em exploração ativa (KEV)",
                "Maior média de probabilidade de exploração (EPSS)"
            ]
        )

        # Lógica de consulta baseada na opção selecionada
        if opcao_analise == "Mais frequentes (volume total)":
            order_by = "total_vulnerabilidades DESC"
            extra_filter = ""
            y_axis = "total_vulnerabilidades"
            label_y = "Total de vulnerabilidades"
            titulo_grafico = "Top 10 Fraquezas por Volume Total de Registros"

        elif opcao_analise == "Mais frequentes em vulnerabilidades críticas":
            order_by = "total_vulnerabilidades DESC"
            extra_filter = "AND c.cvss_base_severity = 'CRITICAL'"
            y_axis = "total_vulnerabilidades"
            label_y = "Quantidade de vulnerabilidades críticas"
            titulo_grafico = "Top 10 Fraquezas em Vulnerabilidades de Severidade Crítica"

        elif opcao_analise == "Mais presentes em exploração ativa (KEV)":
            order_by = "quantidade_no_kev DESC"
            extra_filter = "AND k.cve_id IS NOT NULL"
            y_axis = "quantidade_no_kev"
            label_y = "Quantidade no catálogo KEV"
            titulo_grafico = "Fraquezas com Maior Presença em Exploração Ativa (CISA KEV)"

        else:  # Maior Média de EPSS
            order_by = "media_probabilidade_epss DESC"
            extra_filter = ""
            y_axis = "media_probabilidade_epss"
            label_y = "Média de probabilidade (EPSS)"
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
            )
            apply_chart_layout(fig_cwe_final, margin=dict(l=70, r=45, t=75, b=110))

            st.plotly_chart(fig_cwe_final, width='stretch', key=f"cwe_analise_{opcao_analise}_{filtro_sql}")
