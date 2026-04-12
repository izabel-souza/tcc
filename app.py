# --- IMPORTS ---
import streamlit as st
import pandas as pd
import plotly.express as px
from sqlalchemy import create_engine, text
import os

# --- CONFIGURAÇÕES DA PÁGINA ---
st.set_page_config(
    page_title="Dashboard de Ameaças e Vulnerabilidades",
    page_icon="🛡️",
    layout="wide"
)

# --- CONFIGURAÇÃO DO ENGINE (GLOBAL E COM POOLING) ---
@st.cache_resource
def get_engine():
    user = os.getenv("DB_USER", "admin")
    password = os.getenv("DB_PASS", "admin_password")
    host = os.getenv("DB_HOST", "127.0.0.1")
    db = os.getenv("DB_NAME", "vuln_db")
    # pool_size mantém conexões abertas para reuso, acelerando os gráficos
    return create_engine(f'postgresql+psycopg2://{user}:{password}@{host}/{db}', 
                         pool_size=10, max_overflow=20)

engine = get_engine()

@st.cache_data(show_spinner="Consultando banco de dados...")
def get_data(query):
    with engine.connect() as conn:
        return pd.read_sql(text(query), conn)

# --- CABEÇALHO ---
st.title("🛡️ Dashboard de Ameaças e Vulnerabilidades")
st.markdown("Análise de Vulnerabilidades, Risco de Exploração e Táticas MITRE ATT&CK")

# ==========================================
# BARRA LATERAL (FILTROS GLOBAIS)
# ==========================================
st.sidebar.header("Filtros Globais")

# 1. Filtro de Ano - Range Slider
ano_min, ano_max = 2015, 2026
periodo = st.sidebar.slider(
    "Período de Publicação (CVE)",
    min_value=ano_min, 
    max_value=ano_max,
    value=(ano_min, ano_max),
    help="Arraste para selecionar o intervalo de anos."
)

# 2. Filtro de Severidade (CVSS)
opcoes_severidade = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
severidades_selecionadas = st.sidebar.multiselect(
    "Severidade CVSS", 
    options=opcoes_severidade, 
    default=[],
    placeholder="Todas as severidades"
)

# --- LÓGICA DINÂMICA DO SQL (VAZIO = TUDO) ---
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

# Criação das Abas
tab1, tab2, tab3, tab4 = st.tabs([
    "Visão Geral (CVE & CVSS)", 
    "Risco e Exploração (EPSS & KEV)", 
    "Raiz do Problema (CWE)", 
    "Padrões de Ataque (MITRE)"
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
        fig_bar = px.bar(df_timeline, x='mes_ano', y='qtd', color='cvss_base_severity', labels={'mes_ano': 'Período (Mês/Ano)', 'qtd': 'Quantidade de CVEs', 'cvss_base_severity': 'Severidade CVSS'},
                         color_discrete_map={'CRITICAL': 'darkred', 'HIGH': 'red', 'MEDIUM': 'orange', 'LOW': 'yellow'})
        fig_bar.update_layout(legend_itemclick="toggleothers", legend_itemdoubleclick="toggle")
        st.plotly_chart(fig_bar, width='stretch', key=f"bar_{filtro_sql}")

    with c2:
        st.subheader("Distribuição por Severidade (% Global)")

        query_base = f"SELECT cvss_base_severity as severidade, COUNT(id) as qtd FROM cves WHERE cvss_base_severity IS NOT NULL AND {condicao_ano} GROUP BY 1"
        df_base = get_data(query_base)
        total_global_periodo = df_base['qtd'].sum() if not df_base.empty else 1
        
        if severidades_selecionadas:
            df_display = df_base[df_base['severidade'].isin(severidades_selecionadas)].copy()
        else:
            df_display = df_base.copy()
            
        df_display['porcentagem_fixa'] = (df_display['qtd'] / total_global_periodo) * 100

        if not df_display.empty:
            fig_pie = px.pie(df_display, values='qtd', names='severidade', custom_data=['porcentagem_fixa'],
                             color='severidade', color_discrete_map={'CRITICAL': 'darkred', 'HIGH': 'red', 'MEDIUM': 'orange', 'LOW': 'yellow'})
            fig_pie.update_traces(texttemplate="<b>%{label}</b><br>%{customdata[0]:.1f}%",
                                  hovertemplate="<b>%{label}</b><br>Qtd: %{value}<br>Prop. no Período: %{customdata[0]:.1f}%")

            fig_pie.update_layout(legend_itemclick="toggleothers", legend_itemdoubleclick="toggle")        
    
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
    fig_ran = px.pie(df_ransom, values='qtd', names='status', hole=0.5, color='status',
                     color_discrete_map={'Com Ransomware': '#8b0000', 'Sem Ransomware': '#1f77b4'})
    st.plotly_chart(fig_ran, width='stretch', key=f"ran_{filtro_sql}")

    col_k1, col_k2 = st.columns(2)
    with col_k1:
        st.subheader("Top Vendors (Explorados)")
        vendor_q = f"SELECT k.vendor_project, COUNT(k.cve_id) as qtd FROM kev k JOIN cves c ON k.cve_id = c.id WHERE {filtro_sql_alias} GROUP BY 1 ORDER BY 2 DESC LIMIT 10"
        df_v = get_data(vendor_q)
        fig_v = px.bar(df_v, x='qtd', y='vendor_project', orientation='h', labels={'vendor_project': 'Vendor', 'qtd': 'Quantidade de CVEs Exploradas'}, color_discrete_sequence=['#1f77b4'])
        fig_v.update_layout(yaxis={'categoryorder':'total ascending'})
        st.plotly_chart(fig_v, width='stretch', key=f"vend_{filtro_sql}")

    with col_k2:
        st.subheader("Top Produtos (Explorados)")
        prod_q = f"SELECT k.product, COUNT(k.cve_id) as qtd FROM kev k JOIN cves c ON k.cve_id = c.id WHERE {filtro_sql_alias} GROUP BY 1 ORDER BY 2 DESC LIMIT 10"
        df_p = get_data(prod_q)
        fig_p = px.bar(df_p, x='qtd', y='product', orientation='h',  labels={'product': 'Produto', 'qtd': 'Quantidade de CVEs Exploradas'}, color_discrete_sequence=['#1f77b4'])
        fig_p.update_layout(yaxis={'categoryorder':'total ascending'})
        st.plotly_chart(fig_p, width='stretch', key=f"prod_{filtro_sql}")

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
        fig_cwe = px.bar(df_cwe, x='qtd', y='fraqueza', orientation='h',  labels={'fraqueza': 'Fraqueza', 'qtd': 'Quantidade'},)
        fig_cwe.update_layout(yaxis={'categoryorder':'total ascending'})
        st.plotly_chart(fig_cwe, width='stretch', key=f"cwe_g_{filtro_sql}")

    with c2:
        st.subheader("CWEs em Vulnerabilidades Críticas")
        q_cwe_c = f"""
            SELECT cw.id || ' - ' || SUBSTRING(cw.description, 1, 30) || '...' as fraqueza, COUNT(m.cve_id) as qtd
            FROM cve_cwe_mapping m JOIN cwes cw ON m.cwe_id = cw.id JOIN cves c ON m.cve_id = c.id
            WHERE c.cvss_base_severity = 'CRITICAL' AND {filtro_sql_alias} GROUP BY 1 ORDER BY 2 DESC LIMIT 10
        """
        df_cwe_c = get_data(q_cwe_c)
        fig_cwe_c = px.bar(df_cwe_c, x='qtd', y='fraqueza', orientation='h', labels={'fraqueza': 'Fraqueza', 'qtd': 'Quantidade'},color_discrete_sequence=['darkred'])
        fig_cwe_c.update_layout(yaxis={'categoryorder':'total ascending'})
        st.plotly_chart(fig_cwe_c, width='stretch', key=f"cwe_c_{filtro_sql}")

# ==========================================
# ABA 4: PADRÕES DE ATAQUE (MITRE)
# ==========================================
with tab4:
    st.header("Inteligência de Ameaças: MITRE ATT&CK")
    st.markdown("Cruzamento das vulnerabilidades com as Técnicas do MITRE mais prováveis de serem utilizadas pelos atacantes.")
    
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
            fig_tech = px.bar(
                df_tech, x='quantidade', y='tecnica', orientation='h', 
                labels={'quantidade': 'Quantidade de Vulnerabilidades', 'tecnica': 'Técnica MITRE (Modo de Ataque)'},
                color='quantidade', color_continuous_scale='Reds'
            )
            fig_tech.update_layout(yaxis={'categoryorder':'total ascending'})
            st.plotly_chart(fig_tech, width='stretch', key=f"tech_{filtro_sql}")
            
            
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
            fig_taticas = px.bar(
                df_taticas, 
                x='quantidade', 
                y='tatica', 
                orientation='h', 
                labels={'quantidade': 'Quantidade de Vulnerabilidades', 'tatica': 'Tática MITRE (Objetivo)'},
                color='quantidade', 
                color_continuous_scale='Blues' 
            )
            fig_taticas.update_layout(yaxis={'categoryorder':'total ascending'})
            
            st.plotly_chart(fig_taticas, width='stretch', key=f"tac_{filtro_sql}")
        else:
            st.warning("Ainda não existem dados suficientes para gerar o gráfico de Táticas.")
        
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
            fig_tree = px.treemap(
                df_tree, 
                path=['tecnica', 'fraqueza'], 
                values='qtd_cves',
                color='qtd_cves',
                color_continuous_scale='Reds'
            )
            fig_tree.update_layout(margin=dict(t=20, l=0, r=0, b=0))
            
            fig_tree.update_layout(
                legend_itemclick="toggleothers",       
                legend_itemdoubleclick="toggle"        
            ) 
            
            st.plotly_chart(fig_tree, width='stretch')
    else:
            st.warning("Sem dados suficientes para o detalhamento.")