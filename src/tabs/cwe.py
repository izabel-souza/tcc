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

    st.markdown('<div style="height: 1.2rem;"></div>', unsafe_allow_html=True)

    # ==============================================================================
    # CASO DE USO 2: IDENTIFICAÇÃO DE FRAQUEZAS ASSOCIADAS A RISCO REAL
    # ==============================================================================
    with st.container(border=True):
        st.subheader("Fraquezas Associadas a Risco Real")

        with st.expander("Guia de análise:"):
            st.markdown("""
                ### Objetivo: identificar fraquezas associadas a maior risco real.
                Esta análise destaca classes de CWE relacionadas a exploração ativa ou maior probabilidade estimada de exploração, complementando os rankings gerais de frequência.

                #### Como interpretar:
                1. **Exploração ativa (KEV):** mostra os tipos de fraqueza mais presentes em vulnerabilidades exploradas no mundo real.
                2. **Maior média EPSS:** mostra os tipos de fraqueza com maior probabilidade média de exploração.
                3. **Diferença em relação aos rankings gerais:** ajuda a separar fraquezas comuns de fraquezas que indicam maior risco operacional.

                #### Leitura prática:
                Fraquezas que aparecem com destaque no KEV ou com EPSS médio elevado podem orientar políticas de desenvolvimento seguro, revisão de código, priorização de correções e ações preventivas.
            """)

        st.markdown('<div style="height: 0.75rem;"></div>', unsafe_allow_html=True)

        # Seletor para abranger todo o escopo da ideia analítica
        opcao_analise = st.selectbox(
            "Selecione a perspectiva de análise das fraquezas:", [
                "Mais presentes em exploração ativa (KEV)",
                "Maior média de probabilidade de exploração (EPSS)"
            ]
        )

        st.markdown('<div style="height: 0.75rem;"></div>', unsafe_allow_html=True)

        # Lógica de consulta baseada na opção selecionada
        if opcao_analise == "Mais presentes em exploração ativa (KEV)":
            order_by = "quantidade_no_kev DESC"
            extra_filter = "AND k.cve_id IS NOT NULL"
            y_axis = "quantidade_no_kev"
            label_y = "Quantidade no catálogo KEV"
            titulo_grafico = "Fraquezas com Maior Presença em Exploração Ativa (CISA KEV)"

        else:  # Maior Média de EPSS
            order_by = "media_probabilidade_epss DESC"
            extra_filter = ""
            y_axis = "media_probabilidade_epss"
            label_y = "Média EPSS"
            titulo_grafico = "Fraquezas com Maior Probabilidade Média de Exploração"

        #QUERY PARA METRICAS
        q_cwe_completa = f"""
            SELECT 
                cw.id as identificador_cwe,
                cw.description as descricao_completa,
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
            GROUP BY 1, 2, 3
            ORDER BY {order_by}
            LIMIT 10
        """

        df_cwe_analise = get_data(q_cwe_completa)

        if not df_cwe_analise.empty:
            is_epss_view = "EPSS" in opcao_analise
            fig_cwe_final = px.bar(
                df_cwe_analise,
                x='descricao_fraqueza',
                y=y_axis,
                text_auto=False if is_epss_view else True,
                labels={
                    'descricao_fraqueza': 'CWE',
                    y_axis: label_y,
                    'identificador_cwe': 'ID CWE'
                },
                custom_data=['identificador_cwe', 'descricao_completa'],
                title=titulo_grafico,
                color=y_axis,
                color_continuous_scale='Reds')

            fig_cwe_final.update_layout(
                xaxis_tickangle=-45,
            )
            if is_epss_view:
                fig_cwe_final.update_layout(
                    yaxis_tickformat=".0%",
                    coloraxis_colorbar=dict(tickformat=".0%")
                )
                fig_cwe_final.update_traces(texttemplate="%{y:.0%}", textposition="auto")

            valor_hover = "Média EPSS" if is_epss_view else label_y
            valor_template = "%{y:.1%}" if is_epss_view else "%{y}"
            fig_cwe_final.update_traces(
                hovertemplate=(
                    "<b>%{customdata[0]}</b><br>"
                    "Nome: %{customdata[1]}<br>"
                    f"{valor_hover}: {valor_template}<extra></extra>"
                )
            )
            chart_margin = dict(l=95, r=45, t=95, b=110) if is_epss_view else dict(l=70, r=45, t=75, b=110)
            apply_chart_layout(fig_cwe_final, margin=chart_margin)

            st.plotly_chart(fig_cwe_final, width='stretch', key=f"cwe_analise_{opcao_analise}_{filtro_sql}")
