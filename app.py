# --- IMPORTS ---
import streamlit as st
import pandas as pd
import plotly.express as px
from sqlalchemy import create_engine, text
import os

# --- CONFIGURAÇÕES DA PÁGINA ---
st.set_page_config(page_title="Dashboard de Ameaças e Vulnerabilidades",
                   page_icon="🛡️",
                   layout="wide")


# --- CONFIGURAÇÃO DO ENGINE (GLOBAL E COM POOLING) ---
@st.cache_resource
def get_engine():
    user = os.getenv("DB_USER", "admin")
    password = os.getenv("DB_PASS", "admin_password")
    host = os.getenv("DB_HOST", "127.0.0.1")
    db = os.getenv("DB_NAME", "vuln_db")
    # pool_size mantém conexões abertas para reuso, acelerando os gráficos
    return create_engine(
        f'postgresql+psycopg2://{user}:{password}@{host}/{db}',
        pool_size=10,
        max_overflow=20)

engine = get_engine()

@st.cache_data(show_spinner="Consultando banco de dados...")
def get_data(query):
    with engine.connect() as conn:
        return pd.read_sql(text(query), conn)


# --- CABEÇALHO ---
st.title("Dashboard de Ameaças e Vulnerabilidades")
st.markdown(
    "Análise de Vulnerabilidades, Risco de Exploração e Táticas MITRE ATT&CK")

# ==========================================
# BARRA LATERAL (FILTROS)
# ==========================================
st.sidebar.header("Filtros Globais")

#Filtro de Ano - Range Slider
ano_min, ano_max = 2015, 2026
periodo = st.sidebar.slider(
    "Período de Publicação (CVE)",
    min_value=ano_min,
    max_value=ano_max,
    value=(ano_min, ano_max),
    help="Arraste para selecionar o intervalo de anos.")

#Filtro de Severidade (CVSS)
opcoes_severidade = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
severidades_selecionadas = st.sidebar.multiselect(
    "Severidade CVSS",
    options=opcoes_severidade,
    default=[],
    placeholder="Todas as severidades")

# --- FILTRO VAZIO = TUDO ---
if periodo[0] == ano_min and periodo[1] == ano_max:
    condicao_ano = "1=1"
    condicao_ano_alias = "1=1"
else:
    condicao_ano = f"EXTRACT(YEAR FROM published_date) BETWEEN {periodo[0]} AND {periodo[1]}"
    condicao_ano_alias = f"EXTRACT(YEAR FROM c.published_date) BETWEEN {periodo[0]} AND {periodo[1]}"

if severidades_selecionadas:
    sev_formatadas = "', '".join(severidades_selecionadas)
    condicao_sev = f"cvss_base_severity IN ('{sev_formatadas}')"
    condicao_sev_alias = f"c.cvss_base_severity IN ('{sev_formatadas}')"
else:
    condicao_sev = "1=1"
    condicao_sev_alias = "1=1"

filtro_sql = f"{condicao_ano} AND {condicao_sev}"
filtro_sql_alias = f"{condicao_ano_alias} AND {condicao_sev_alias}"


# ABAS
tab1, tab2, tab3, tab4 = st.tabs([
    "Visão Geral (CVE & CVSS)", "Risco e Exploração (EPSS & KEV)",
    "Raiz do Problema (CWE)", "Padrões de Ataque (MITRE)"
])

# ==========================================
# ABA 1: VISÃO GERAL
# ==========================================
with tab1:
    st.header("Métricas Globais de Vulnerabilidades")

    # KPIs
    kpi_query = f"""
        SELECT COUNT(id) as total, 
        ROUND(AVG(cvss_base_score), 2) as media 
        FROM cves 
        WHERE {filtro_sql}
    """
    df_kpi = get_data(kpi_query)

    col1, col2, col3 = st.columns(3)
    col1.metric("Total de CVEs", f"{df_kpi['total'][0]:,}")
    col2.metric("Média Score CVSS", df_kpi['media'][0])

    st.divider()
    c1, c2 = st.columns(2)

    with c1:
        st.subheader("Evolução Temporal")
        timeline_query = f"""
            SELECT TO_CHAR(published_date, 'YYYY-MM') as mes_ano, cvss_base_severity, COUNT(id) as qtd
            FROM cves WHERE {filtro_sql} AND cvss_base_severity IS NOT NULL
            GROUP BY 1, 2 ORDER BY 1
        """
        df_timeline = get_data(timeline_query)
        fig_bar = px.bar(df_timeline,
                         x='mes_ano',
                         y='qtd',
                         color='cvss_base_severity',
                         labels={
                             'mes_ano': 'Período (Mês/Ano)',
                             'qtd': 'Quantidade de CVEs',
                             'cvss_base_severity': 'Severidade CVSS'
                         },
                         color_discrete_map={
                             'CRITICAL': 'darkred',
                             'HIGH': 'red',
                             'MEDIUM': 'orange',
                             'LOW': 'yellow'
                         })
        fig_bar.update_layout(legend_itemclick="toggleothers",
                              legend_itemdoubleclick="toggle")
        st.plotly_chart(fig_bar, width='stretch', key=f"bar_{filtro_sql}")

    with c2:
        st.subheader("Distribuição por Severidade (% Global)")

        query_base = f"SELECT cvss_base_severity as severidade, COUNT(id) as qtd FROM cves WHERE cvss_base_severity IS NOT NULL AND {condicao_ano} GROUP BY 1"
        df_base = get_data(query_base)
        total_global_periodo = df_base['qtd'].sum() if not df_base.empty else 1

        if severidades_selecionadas:
            df_display = df_base[df_base['severidade'].isin(
                severidades_selecionadas)].copy()
        else:
            df_display = df_base.copy()

        df_display['porcentagem_fixa'] = (df_display['qtd'] /
                                          total_global_periodo) * 100

        if not df_display.empty:
            fig_pie = px.pie(df_display,
                             values='qtd',
                             names='severidade',
                             custom_data=['porcentagem_fixa'],
                             color='severidade',
                             color_discrete_map={
                                 'CRITICAL': 'darkred',
                                 'HIGH': 'red',
                                 'MEDIUM': 'orange',
                                 'LOW': 'yellow'
                             })
            fig_pie.update_traces(
                texttemplate="<b>%{label}</b><br>%{customdata[0]:.1f}%",
                hovertemplate=
                "<b>%{label}</b><br>Qtd: %{value}<br>Prop. no Período: %{customdata[0]:.1f}%"
            )

            fig_pie.update_layout(legend_itemclick="toggleothers",
                                  legend_itemdoubleclick="toggle")

            st.plotly_chart(fig_pie, width='stretch', key=f"pie_{filtro_sql}")

# ==========================================
# ABA 2: RISCO E EXPLORAÇÃO
# ==========================================
with tab2:
    st.header("Análise de Risco Prático (KEV & EPSS)")

    # Gráfico de Rosca Ransomware
    ransom_query = f"""
        SELECT CASE WHEN k.known_ransomware_usage THEN 'Com Ransomware' ELSE 'Sem Ransomware' END as status, COUNT(k.cve_id) as qtd
        FROM kev k JOIN cves c ON k.cve_id = c.id
        WHERE {filtro_sql_alias} GROUP BY 1
    """
    df_ransom = get_data(ransom_query)
    fig_ran = px.pie(df_ransom,
                     values='qtd',
                     names='status',
                     hole=0.5,
                     color='status',
                     color_discrete_map={
                         'Com Ransomware': '#8b0000',
                         'Sem Ransomware': '#1f77b4'
                     })
    st.plotly_chart(fig_ran, width='stretch', key=f"ran_{filtro_sql}")

    col_k1, col_k2 = st.columns(2)
    with col_k1:
        st.subheader("Top Vendors (Explorados)")
        vendor_q = f"SELECT k.vendor_project, COUNT(k.cve_id) as qtd FROM kev k JOIN cves c ON k.cve_id = c.id WHERE {filtro_sql_alias} GROUP BY 1 ORDER BY 2 DESC LIMIT 10"
        df_v = get_data(vendor_q)
        fig_v = px.bar(df_v,
                       x='qtd',
                       y='vendor_project',
                       orientation='h',
                       labels={
                           'vendor_project': 'Vendor',
                           'qtd': 'Quantidade de CVEs Exploradas'
                       },
                       color_discrete_sequence=['#1f77b4'])
        fig_v.update_layout(yaxis={'categoryorder': 'total ascending'})
        st.plotly_chart(fig_v, width='stretch', key=f"vend_{filtro_sql}")

    with col_k2:
        st.subheader("Top Produtos (Explorados)")
        prod_q = f"SELECT k.product, COUNT(k.cve_id) as qtd FROM kev k JOIN cves c ON k.cve_id = c.id WHERE {filtro_sql_alias} GROUP BY 1 ORDER BY 2 DESC LIMIT 10"
        df_p = get_data(prod_q)
        fig_p = px.bar(df_p,
                       x='qtd',
                       y='product',
                       orientation='h',
                       labels={
                           'product': 'Produto',
                           'qtd': 'Quantidade de CVEs Exploradas'
                       },
                       color_discrete_sequence=['#1f77b4'])
        fig_p.update_layout(yaxis={'categoryorder': 'total ascending'})
        st.plotly_chart(fig_p, width='stretch', key=f"prod_{filtro_sql}")

    st.divider()

    # ==============================================================================
    # CASO DE USO 1: PRIORIZAÇÃO DE CORREÇÃO DE VULNERABILIDADES
    # ==============================================================================
    st.header("Priorização de Correção de Vulnerabilidades")

    query_prioridade = f"""
        SELECT 
            c.id,
            c.cvss_base_score,
            c.cvss_base_severity,
            e.epss_score,
            CASE WHEN k.cve_id IS NOT NULL THEN TRUE ELSE FALSE END as is_kev,
            CASE 
                WHEN k.cve_id IS NOT NULL AND (c.cvss_base_score >= 7.0 OR e.epss_score >= 0.1) THEN 'Prioridade Máxima'
                WHEN k.cve_id IS NOT NULL THEN 'Risco Subestimado'
                WHEN c.cvss_base_score >= 7.0 AND e.epss_score < 0.1 THEN 'Atenção (Vigilância)'
                ELSE 'Monitoramento'
            END as categoria_prioridade
        FROM cves c
        JOIN epss_scores e ON c.id = e.cve_id
        LEFT JOIN kev k ON c.id = k.cve_id
        WHERE {filtro_sql_alias}
        ORDER BY is_kev DESC, e.epss_score DESC, c.cvss_base_score DESC
        LIMIT 5000
    """
    df_prioridade = get_data(query_prioridade)

    if not df_prioridade.empty:
        fig_scatter = px.scatter(
            df_prioridade,
            x='cvss_base_score',
            y='epss_score',
            color='categoria_prioridade',
            symbol='is_kev',
            hover_data=['id', 'cvss_base_severity'],
            labels={
                'cvss_base_score': 'Severidade Técnica (CVSS)',
                'epss_score': 'Probabilidade de Exploração - EPSS (0-1)',
                'categoria_prioridade': 'Classificação de Risco'
            },
            color_discrete_map={
                'Prioridade Máxima': 'darkred',
                'Risco Subestimado': 'orange',
                'Atenção (Vigilância)': 'gold',
                'Monitoramento': 'gray'
            },
            title="Correlação CVSS x EPSS (KEV)")

        # Adicionando linhas de quadrante para facilitar a leitura
        fig_scatter.add_hline(
            y=0.5,
            line_dash="dot",
            line_color="red",
            annotation_text="Alta Probabilidade (EPSS > 0.5)")
        fig_scatter.add_vline(x=7.0,
                              line_dash="dot",
                              line_color="orange",
                              annotation_text="Alta Severidade (CVSS > 7.0)")

        st.plotly_chart(fig_scatter,
                        width='stretch',
                        key=f"scatter_prioridade_{filtro_sql}")

    st.divider()

    # ==============================================================================
    # CASO DE USO 4: PERFIL DAS VULNERABILIDADES EXPLORADAS (KEV VS. GERAL)
    # ==============================================================================
    st.header(
        "Perfil Investigativo: O que diferencia uma vulnerabilidade explorada?")
    st.markdown("""
    Esta análise compara o perfil das vulnerabilidades que entraram no catálogo KEV contra o restante da base de dados, 
    validando a hipótese de que vulnerabilidades exploradas apresentam padrões distintos de severidade e probabilidade.
    """)

    # 1. Comparação de Médias Estatísticas (CVSS e EPSS)
    st.write(
        "### Comparativo de Médias: Severidade Técnica vs. Probabilidade Real")

    q_perfil_estatistico = f"""
        SELECT 
            CASE 
                WHEN k.cve_id IS NOT NULL THEN 'No Catálogo KEV (Explorada)' 
                ELSE 'Fora do Catálogo KEV' 
            END as status_exploracao,
            ROUND(AVG(c.cvss_base_score)::numeric, 2) as media_score_cvss,
            ROUND(AVG(e.epss_score)::numeric, 4) as media_probabilidade_epss
        FROM cves c
        LEFT JOIN kev k ON c.id = k.cve_id
        LEFT JOIN epss_scores e ON c.id = e.cve_id
        WHERE {filtro_sql_alias}
        GROUP BY 1
    """

    df_perfil = get_data(q_perfil_estatistico)

    if not df_perfil.empty:
        col_est1, col_est2 = st.columns(2)

    with col_est1:
        fig_cvss_comp = px.bar(df_perfil,
                               x='status_exploracao',
                               y='media_score_cvss',
                               labels={
                                   'media_score_cvss': 'Média do Score CVSS',
                                   'status_exploracao': 'Grupo de Análise'
                               },
                               title="Diferença de Severidade Média (CVSS)",
                               color='status_exploracao',
                               color_discrete_sequence=['#1f77b4', '#8b0000'])
        st.plotly_chart(fig_cvss_comp,
                        width='stretch',
                        key=f"cvss_perfil_{filtro_sql}")

    with col_est2:
        fig_epss_comp = px.bar(df_perfil,
                               x='status_exploracao',
                               y='media_probabilidade_epss',
                               labels={
                                   'media_probabilidade_epss':
                                   'Média de Probabilidade EPSS',
                                   'status_exploracao': 'Grupo de Análise'
                               },
                               title="Diferença de Probabilidade Média (EPSS)",
                               color='status_exploracao',
                               color_discrete_sequence=['#1f77b4', '#8b0000'])
        st.plotly_chart(fig_epss_comp,
                        width='stretch',
                        key=f"epss_perfil_{filtro_sql}")

    st.divider()

    # 2. Comparação de Tipos de Fraqueza (CWE) - Top 5 de cada grupo
    st.write("### Comparativo de Fraquezas (CWE): KEV vs. Geral")

    q_cwe_perfil = f"""
        (SELECT 
            'No Catálogo KEV' as grupo,
            cw.id as identificador_fraqueza,
            COUNT(c.id) as quantidade_vulnerabilidades
        FROM cves c
        JOIN kev k ON c.id = k.cve_id
        JOIN cve_cwe_mapping m ON c.id = m.cve_id
        JOIN cwes cw ON m.cwe_id = cw.id
        WHERE {filtro_sql_alias}
        GROUP BY 2 ORDER BY 3 DESC LIMIT 5)
        UNION ALL
        (SELECT 
            'Fora do Catálogo KEV' as grupo,
            cw.id as identificador_fraqueza,
            COUNT(c.id) as quantidade_vulnerabilidades
        FROM cves c
        LEFT JOIN kev k ON c.id = k.cve_id
        JOIN cve_cwe_mapping m ON c.id = m.cve_id
        JOIN cwes cw ON m.cwe_id = cw.id
        WHERE k.cve_id IS NULL AND {filtro_sql_alias}
        GROUP BY 2 ORDER BY 3 DESC LIMIT 5)
    """

    df_cwe_perfil = get_data(q_cwe_perfil)

    if not df_cwe_perfil.empty:
        fig_cwe_perfil = px.bar(
            df_cwe_perfil,
            x='identificador_fraqueza',
            y='quantidade_vulnerabilidades',
            color='grupo',
            barmode='group',
            labels={
                'identificador_fraqueza': 'Tipo de Fraqueza (CWE)',
                'quantidade_vulnerabilidades': 'Quantidade de CVEs'
            },
            title="Top 5 Fraquezas em cada Grupo (KEV vs. Restante da Base)",
            color_discrete_map={
                'No Catálogo KEV': '#8b0000',
                'Fora do Catálogo KEV': '#1f77b4'
            })
        st.plotly_chart(fig_cwe_perfil,
                        width='stretch',
                        key=f"cwe_perfil_bar_{filtro_sql}")

    st.divider()

    # ==============================================================================
    # CASO DE USO 5: TENDÊNCIA TEMPORAL DA EXPLORAÇÃO (VOLUME VS. RISCO)
    # ==============================================================================
    st.divider()
    st.header("Tendência Temporal: O volume implica em mais risco?")
    st.markdown("""
    Esta análise investiga se o crescimento anual no registro de vulnerabilidades reflete um aumento real 
    na superfície de exploração ou se representa uma inflação de registros de baixo risco operacional.
    """)

    # 1. Query para consolidar métricas anuais
    q_tendencia_temporal = f"""
        SELECT 
            EXTRACT(YEAR FROM c.published_date) as ano_publicacao,
            COUNT(c.id) as quantidade_total_cves,
            COUNT(CASE WHEN c.cvss_base_severity = 'CRITICAL' THEN 1 END) as quantidade_criticas,
            COUNT(k.cve_id) as quantidade_exploradas_kev,
            ROUND(AVG(e.epss_score)::numeric, 4) as media_probabilidade_epss
        FROM cves c
        LEFT JOIN kev k ON c.id = k.cve_id
        LEFT JOIN epss_scores e ON c.id = e.cve_id
        WHERE {filtro_sql_alias}
        GROUP BY 1
        ORDER BY 1
    """

    df_tendencia = get_data(q_tendencia_temporal)

    if not df_tendencia.empty:
        # Gráfico 1: Comparativo de Volume (Total vs. Críticas vs. KEV)
        fig_vol_evolucao = px.line(
            df_tendencia,
            x='ano_publicacao',
            y=[
                'quantidade_total_cves', 'quantidade_criticas',
                'quantidade_exploradas_kev'
            ],
            labels={
                'ano_publicacao': 'Ano de Publicação',
                'value': 'Quantidade de Vulnerabilidades',
                'variable': 'Métrica de Análise'
            },
            title=
            "Evolução Temporal: Volume Total vs. Severidade Crítica vs. Exploração Ativa",
            markers=True)

        # Renomeando as legendas para nomes amigáveis no gráfico
        new_names = {
            'quantidade_total_cves': 'Total de Vulnerabilidades Registradas',
            'quantidade_criticas': 'Vulnerabilidades de Severidade Crítica',
            'quantidade_exploradas_kev':
            'Vulnerabilidades em Exploração Ativa (KEV)'
        }
        fig_vol_evolucao.for_each_trace(lambda t: t.update(name=new_names[t.name]))

        st.plotly_chart(fig_vol_evolucao,
                        width='stretch',
                        key=f"trend_vol_{filtro_sql}")

        st.divider()

        # Gráfico 2: Evolução da Probabilidade Média (EPSS) ao longo dos anos
        st.write("### Evolução da Probabilidade Média de Exploração (EPSS)")
        fig_epss_trend = px.area(
            df_tendencia,
            x='ano_publicacao',
            y='media_probabilidade_epss',
            labels={
                'ano_publicacao': 'Ano de Publicação',
                'media_probabilidade_epss': 'Média de Probabilidade (EPSS)'
            },
            title="Tendência de Probabilidade Média de Exploração por Ano",
            color_discrete_sequence=['blue'])
        st.plotly_chart(fig_epss_trend,
                        width='stretch',
                        key=f"trend_epss_{filtro_sql}")

    else:
        st.info("Ajuste os filtros de data para visualizar a tendência temporal.")

# ==========================================
# ABA 3: RAIZ DO PROBLEMA (CWE)
# ==========================================
with tab3:
    st.header("Fraquezas de Software (CWE)")
    c1, c2 = st.columns(2)

    with c1:
        st.subheader("Top 10 CWEs Gerais")
        q_cwe = f"""
            SELECT cw.id || ' - ' || SUBSTRING(cw.description, 1, 30) || '...' as fraqueza, COUNT(m.cve_id) as qtd
            FROM cve_cwe_mapping m JOIN cwes cw ON m.cwe_id = cw.id JOIN cves c ON m.cve_id = c.id
            WHERE {filtro_sql_alias} GROUP BY 1 ORDER BY 2 DESC LIMIT 10
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
        fig_cwe.update_layout(yaxis={'categoryorder': 'total ascending'})
        st.plotly_chart(fig_cwe, width='stretch', key=f"cwe_g_{filtro_sql}")

    with c2:
        st.subheader("CWEs em Vulnerabilidades Críticas")
        q_cwe_c = f"""
            SELECT cw.id || ' - ' || SUBSTRING(cw.description, 1, 30) || '...' as fraqueza, COUNT(m.cve_id) as qtd
            FROM cve_cwe_mapping m JOIN cwes cw ON m.cwe_id = cw.id JOIN cves c ON m.cve_id = c.id
            WHERE c.cvss_base_severity = 'CRITICAL' AND {filtro_sql_alias} GROUP BY 1 ORDER BY 2 DESC LIMIT 10
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
        fig_cwe_c.update_layout(yaxis={'categoryorder': 'total ascending'})
        st.plotly_chart(fig_cwe_c, width='stretch', key=f"cwe_c_{filtro_sql}")

    st.divider()

    # ==============================================================================
    # CASO DE USO 2: IDENTIFICAÇÃO DE FRAQUEZAS ASSOCIADAS A RISCO REAL
    # ==============================================================================
    st.subheader("Análise de Fraquezas (CWE) por Perspectivas de Risco")

    # Seletor para abranger todo o escopo da ideia analítica
    opcao_analise = st.selectbox(
        "Selecione a perspectiva de análise das fraquezas:", [
            "Mais Frequentes (Volume Total)",
            "Mais Frequentes em Vulnerabilidades Críticas",
            "Mais Presentes em Exploração Ativa (KEV)",
            "Maior Média de Probabilidade de Exploração (EPSS)"
        ])

    # Lógica de consulta baseada na opção selecionada
    if opcao_analise == "Mais Frequentes (Volume Total)":
        order_by = "total_vulnerabilidades DESC"
        extra_filter = ""
        y_axis = "total_vulnerabilidades"
        label_y = "Total de Vulnerabilidades"
        titulo_grafico = "Top 10 Fraquezas por Volume Total de Registros"

    elif opcao_analise == "Mais Frequentes em Vulnerabilidades Críticas":
        order_by = "total_vulnerabilidades DESC"
        # Adiciona filtro de severidade crítica na subquery
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

    # Query otimizada para abranger as novas métricas
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
        WHERE {filtro_sql_alias} {extra_filter}
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
                'descricao_fraqueza': 'Tipo de Fraqueza (CWE)',
                y_axis: label_y,
                'identificador_cwe': 'ID CWE'
            },
            title=titulo_grafico,
            color=y_axis,
            color_continuous_scale='Reds')

        fig_cwe_final.update_layout(xaxis_tickangle=-45)
        st.plotly_chart(fig_cwe_final,
                        width='stretch',
                        key=f"cwe_analise_{opcao_analise}_{filtro_sql}")
    else:
        st.info(
            "Nenhum dado encontrado para os filtros selecionados nesta categoria."
        )

# ==========================================
# ABA 4: PADRÕES DE ATAQUE (MITRE)
# ==========================================
with tab4:
    st.header("Inteligência de Ameaças: MITRE ATT&CK")
    st.markdown(
        "Cruzamento das vulnerabilidades com as Técnicas do MITRE mais prováveis de serem utilizadas pelos atacantes."
    )

    col_mitre1, col_mitre2 = st.columns([1, 1])

    #(grafico de barras) - Top 10 Técnicas
    with col_mitre1:
        st.subheader("Top 10 Técnicas Mais Utilizadas")
        query_tech = f"""
            SELECT 
                t.name AS tecnica, 
                COUNT(DISTINCT c.id) AS quantidade
            FROM cves c
            JOIN cve_cwe_mapping ccm ON c.id = ccm.cve_id
            JOIN cwe_mitre_mapping cmm ON ccm.cwe_id = cmm.cwe_id
            JOIN mitre_techniques t ON (t.id = cmm.mitre_id OR t.id = 'T' || cmm.mitre_id)
            WHERE {filtro_sql_alias}
            GROUP BY t.name
            ORDER BY quantidade DESC
            LIMIT 10
        """
        df_tech = get_data(query_tech)

        if not df_tech.empty:
            fig_tech = px.bar(df_tech,
                              x='quantidade',
                              y='tecnica',
                              orientation='h',
                              labels={
                                  'quantidade':
                                  'Quantidade de Vulnerabilidades',
                                  'tecnica': 'Técnica MITRE (Modo de Ataque)'
                              },
                              color='quantidade',
                              color_continuous_scale='Reds')
            fig_tech.update_layout(yaxis={'categoryorder': 'total ascending'})
            st.plotly_chart(fig_tech,
                            width='stretch',
                            key=f"tech_{filtro_sql}")

    # (grafico de barras) - Top 10 taticas
    with col_mitre2:
        st.subheader("Top 10 Táticas Mais Reportadas (Objetivo do Atacante)")

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
            WHERE {filtro_sql_alias}
            GROUP BY tac.name
            ORDER BY quantidade DESC
            LIMIT 10
        """

        df_taticas = get_data(query_taticas)

        if not df_taticas.empty:
            fig_taticas = px.bar(df_taticas,
                                 x='quantidade',
                                 y='tatica',
                                 orientation='h',
                                 labels={
                                     'quantidade':
                                     'Quantidade de Vulnerabilidades',
                                     'tatica': 'Tática MITRE (Objetivo)'
                                 },
                                 color='quantidade',
                                 color_continuous_scale='Blues')
            fig_taticas.update_layout(
                yaxis={'categoryorder': 'total ascending'})

            st.plotly_chart(fig_taticas,
                            width='stretch',
                            key=f"tac_{filtro_sql}")
        else:
            st.warning(
                "Ainda não existem dados suficientes para gerar o gráfico de Táticas."
            )

    st.divider()

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
        fig_tree = px.treemap(df_tree,
                              path=['tecnica', 'fraqueza'],
                              values='qtd_cves',
                              color='qtd_cves',
                              color_continuous_scale='Reds')
        fig_tree.update_layout(margin=dict(t=20, l=0, r=0, b=0))

        fig_tree.update_layout(legend_itemclick="toggleothers",
                               legend_itemdoubleclick="toggle")

        st.plotly_chart(fig_tree, width='stretch')
    else:
        st.warning("Sem dados suficientes para o detalhamento.")

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
        WHERE {filtro_sql_alias}
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
        st.write("### Técnicas Associadas a Falhas Críticas")
        q_tech_crit = f"""
            SELECT 
                tec.name AS nome_tecnica,
                COUNT(DISTINCT c.id) AS quantidade_vulnerabilidades
            FROM mitre_techniques tec
            JOIN cwe_mitre_mapping cmm ON (tec.id = cmm.mitre_id OR tec.id = 'T' || cmm.mitre_id)
            JOIN cve_cwe_mapping ccm ON cmm.cwe_id = ccm.cwe_id
            JOIN cves c ON ccm.cve_id = c.id
            WHERE c.cvss_base_severity = 'CRITICAL' AND {filtro_sql_alias}
            GROUP BY 1
            ORDER BY 2 DESC LIMIT 10
        """
        df_tech_crit = get_data(q_tech_crit)

        fig_tech_crit = px.bar(df_tech_crit,
                            x='quantidade_vulnerabilidades',
                            y='nome_tecnica',
                            orientation='h',
                            labels={
                                'quantidade_vulnerabilidades':
                                'Quantidade de Vulnerabilidades Críticas',
                                'nome_tecnica': 'Técnica de Ataque'
                            },
                            color='quantidade_vulnerabilidades',
                            color_continuous_scale='Reds')
        fig_tech_crit.update_layout(yaxis={'categoryorder': 'total ascending'})
        st.plotly_chart(fig_tech_crit,
                        width='stretch',
                        key=f"mitre_crit_{filtro_sql}")

    with col_m2:
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
            WHERE {filtro_sql_alias}
            GROUP BY 1
            ORDER BY 2 DESC LIMIT 10
        """
        df_tac_kev = get_data(q_tac_kev)

        fig_tac_kev = px.bar(df_tac_kev,
                            x='quantidade_no_catalogo_kev',
                            y='nome_tatica',
                            orientation='h',
                            labels={
                                'quantidade_no_catalogo_kev':
                                'Quantidade no Catálogo KEV',
                                'nome_tatica': 'Tática do Atacante'
                            },
                            color='quantidade_no_catalogo_kev',
                            color_continuous_scale='Blues')
        fig_tac_kev.update_layout(yaxis={'categoryorder': 'total ascending'})
        st.plotly_chart(fig_tac_kev,
                        width='stretch',
                        key=f"mitre_kev_{filtro_sql}")