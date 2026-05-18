# --- IMPORTS ---
import streamlit as st
import plotly.express as px
from src.utils.database import get_data
from src.utils.components import render_kpi_card

#FUNCAO COM OS GRAFICOS
def render_vision_tab(filtro_sql, filtro_sql_alias, condicao_ano, severidades_selecionadas):
    st.header("Métricas Globais de Vulnerabilidades")

    # QUERY DOS KPIs
    kpi_query = f"""
        SELECT 
            COUNT(c.id) as total, 
            ROUND(AVG(c.cvss_base_score), 2) as media,
            COUNT(k.cve_id) as total_kev
        FROM cves c
        LEFT JOIN kev k ON c.id = k.cve_id
        WHERE {filtro_sql_alias}
    """
    df_kpi = get_data(kpi_query)

    col1, col2, col3 = st.columns(3)

    # KPI COM TOTAL DE CVEs DESDE 2015
    with col1:
        valor_total = f"{df_kpi['total'][0]:,}".replace(",", ".")
        render_kpi_card("CVEs na Seleção", valor_total)
    
    # KPI COM MEDIA CVSS DAS CVEs
    with col2:
        valor_media = f"{df_kpi['media'][0]}"
        render_kpi_card("Média Score CVSS", valor_media)

    # KPI COM % DE CVE EM EXPLORACAO ATIVA (KEV)
    with col3:
        total_cves = df_kpi['total'][0] if df_kpi['total'][0] > 0 else 1
        pct_kev = (df_kpi['total_kev'][0] / total_cves) * 100
        render_kpi_card("Em Exploração (KEV)", f"{pct_kev:.1f}%")

    st.divider()
    
    c1, c2 = st.columns(2)

    # GRAFICO DE BARRA SOBRE EVOLUÇÃO TEMPORAL DAS QUANTIDADES DE CVEs SEPARADOS POR SEVERIDADE
    with c1:
        with st.container(border=True): # envolve o gráfico no card
            st.subheader("Evolução Temporal")

            timeline_query = f"""
                SELECT 
                    TO_CHAR(published_date, 'YYYY-MM') as mes_ano, 
                    cvss_base_severity, COUNT(id) as qtd
                FROM cves 
                WHERE {filtro_sql} AND cvss_base_severity IS NOT NULL
                GROUP BY 1, 2 ORDER BY 1
            """

            df_timeline = get_data(timeline_query)

            fig_bar = px.bar(
                df_timeline, 
                x='mes_ano', 
                y='qtd', 
                color='cvss_base_severity', 
                labels={"qtd": "Quantidade de CVEs", "mes_ano": "Mês/Ano de Publicação", 'cvss_base_severity': 'Severidade CVSS'},
                color_discrete_map={'CRITICAL': 'darkred', 'HIGH': 'red', 'MEDIUM': 'orange', 'LOW': 'yellow'}
            )
            
            # AJUSTE DE TRANSPARÊNCIA PARA O CARD
            fig_bar.update_layout(
                paper_bgcolor='rgba(0,0,0,0)', # fundo do papel transparente
                plot_bgcolor='rgba(0,0,0,0)',  # fundo do gráfico transparente
                legend_itemclick="toggleothers"
            )
            
            st.plotly_chart(fig_bar, width="stretch", key=f"bar_{filtro_sql}")


    # GRAFICO DE PIZZA COM O PORCENTUAL DE CVEs SEPARADOS POR SEVERIDADE
    with c2:
        with st.container(border=True):
            st.subheader("Distribuição por Severidade (% Global)")

            query_base = f"""
                SELECT 
                    cvss_base_severity as severidade, 
                    COUNT(id) as qtd 
                FROM cves 
                WHERE cvss_base_severity IS NOT NULL AND {condicao_ano} 
                GROUP BY 1
            """

            df_base = get_data(query_base)

            total_global_periodo = df_base['qtd'].sum() if not df_base.empty else 1

            if severidades_selecionadas:
                df_display = df_base[df_base['severidade'].isin(
                    severidades_selecionadas)].copy()
            else:
                df_display = df_base.copy()

            df_display['porcentagem_fixa'] = (df_display['qtd'] / total_global_periodo) * 100

            if not df_display.empty:
                fig_pie = px.pie(df_display,
                            values='qtd',
                            names='severidade',
                            custom_data=['porcentagem_fixa'],
                            color='severidade',
                            color_discrete_map={'CRITICAL': 'darkred', 'HIGH': 'red', 'MEDIUM': 'orange', 'LOW': 'yellow'},
                            category_orders={"severidade": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]}
                        )
                
                fig_pie.update_traces(
                    texttemplate="<b>%{label}</b><br>%{customdata[0]:.1f}%",
                    hovertemplate="<b>%{label}</b><br>Qtd: %{value}<br>Prop. no Período: %{customdata[0]:.1f}%"
                )

                fig_pie.update_layout(
                    legend_itemclick="toggleothers",
                    legend_itemdoubleclick="toggle",
                    paper_bgcolor='rgba(0,0,0,0)', # fundo do papel transparente
                    plot_bgcolor='rgba(0,0,0,0)',  # fundo do gráfico transparente
                )

                st.plotly_chart(fig_pie, width='stretch', key=f"pie_{filtro_sql}")