# --- IMPORTS ---
import streamlit as st
import plotly.express as px
from src.utils.database import get_data
from src.utils.components import apply_chart_layout, render_kpi_card

#FUNCAO COM OS GRAFICOS
def render_vision_tab(
    filtro_sql,
    filtro_sql_alias,
    condicao_ano,
    severidades_selecionadas,
    data_inicio=None,
    data_fim=None
):
    st.subheader("Métricas Globais de Vulnerabilidades")

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
        render_kpi_card("Média do Score CVSS", valor_media)

    # KPI COM % DE CVE EM EXPLORACAO ATIVA (KEV)
    with col3:
        total_cves = df_kpi['total'][0] if df_kpi['total'][0] > 0 else 1
        pct_kev = (df_kpi['total_kev'][0] / total_cves) * 100
        render_kpi_card("Em Exploração (KEV)", f"{pct_kev:.1f}%")

    st.markdown('<div style="height: 1.2rem;"></div>', unsafe_allow_html=True)
    
    c1, c2 = st.columns(2)

    # GRAFICO DE BARRA SOBRE EVOLUÇÃO TEMPORAL DAS QUANTIDADES DE CVEs SEPARADOS POR SEVERIDADE
    with c1:
        with st.container(border=True): # envolve o gráfico no card
            st.subheader("Evolução Temporal")
            intervalo_dias = (data_fim - data_inicio).days if data_inicio and data_fim else 9999

            if intervalo_dias > 365:
                periodo_sql = "EXTRACT(YEAR FROM published_date)::int"
                periodo_ordem_sql = "EXTRACT(YEAR FROM published_date)::int"
                periodo_label = "Ano de publicação"
                eixo_x_label = "Ano de publicação"
                eixo_x_config = dict(
                    type="category",
                    title=periodo_label,
                    tickangle=0
                )
            elif intervalo_dias > 31:
                periodo_sql = """
                    CASE EXTRACT(MONTH FROM published_date)::int
                        WHEN 1 THEN 'jan'
                        WHEN 2 THEN 'fev'
                        WHEN 3 THEN 'mar'
                        WHEN 4 THEN 'abr'
                        WHEN 5 THEN 'mai'
                        WHEN 6 THEN 'jun'
                        WHEN 7 THEN 'jul'
                        WHEN 8 THEN 'ago'
                        WHEN 9 THEN 'set'
                        WHEN 10 THEN 'out'
                        WHEN 11 THEN 'nov'
                        WHEN 12 THEN 'dez'
                    END || ' ' || EXTRACT(YEAR FROM published_date)::int
                """
                periodo_ordem_sql = "DATE_TRUNC('month', published_date)::date"
                periodo_label = "Mês/ano de publicação"
                eixo_x_label = "Mês/ano de publicação"
                eixo_x_config = dict(
                    type="category",
                    title=periodo_label,
                    tickangle=-35
                )
            else:
                periodo_sql = "TO_CHAR(published_date::date, 'DD/MM')"
                periodo_ordem_sql = "published_date::date"
                periodo_label = "Dia de publicação"
                eixo_x_label = "Dia de publicação"
                eixo_x_config = dict(
                    type="category",
                    title=periodo_label,
                    tickangle=-35
                )

            timeline_query = f"""
                SELECT 
                    {periodo_sql} as periodo_publicacao,
                    {periodo_ordem_sql} as ordem_periodo,
                    cvss_base_severity, 
                    COUNT(id) as qtd
                FROM cves 
                WHERE {filtro_sql} AND cvss_base_severity IS NOT NULL
                GROUP BY 1, 2, 3
                ORDER BY 2
            """

            df_timeline = get_data(timeline_query)
            categorias_periodo = df_timeline["periodo_publicacao"].drop_duplicates().tolist()
            tickvals_periodo = categorias_periodo

            if intervalo_dias <= 31 and len(categorias_periodo) > 16:
                tickvals_periodo = categorias_periodo[::2]

            fig_bar = px.bar(
                df_timeline, 
                x='periodo_publicacao',
                y='qtd', 
                color='cvss_base_severity', 
                labels={
                    "qtd": "Quantidade de CVEs", 
                    "periodo_publicacao": eixo_x_label,
                    'cvss_base_severity': 'Severidade CVSS'
                },
                color_discrete_map={
                    'CRITICAL': 'darkred', 
                    'HIGH': 'red', 
                    'MEDIUM': 'orange', 
                    'LOW': 'yellow'
                }
            )
            fig_bar.update_xaxes(
                categoryorder="array",
                categoryarray=categorias_periodo,
                tickmode="array",
                tickvals=tickvals_periodo
            )
            
            fig_bar.update_layout(
                legend_itemclick="toggleothers",
                xaxis=eixo_x_config
            )
            apply_chart_layout(fig_bar)
            
            st.plotly_chart(fig_bar, width="stretch", key=f"bar_{filtro_sql}")


    # GRAFICO DE PIZZA COM O PORCENTUAL DE CVEs SEPARADOS POR SEVERIDADE
    with c2:
        with st.container(border=True):
            st.subheader("Distribuição Global por Severidade")

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
                    hovertemplate="<b>%{label}</b><br>Qtd: %{value}<br>Prop. no período: %{customdata[0]:.1f}%"
                )

                fig_pie.update_layout(
                    legend_itemclick="toggleothers",
                    legend_itemdoubleclick="toggle"
                )
                apply_chart_layout(fig_pie, margin=dict(l=45, r=45, t=45, b=45))

                st.plotly_chart(fig_pie, width='stretch', key=f"pie_{filtro_sql}")
