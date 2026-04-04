# --- IMPORTS ---
import streamlit as st
import pandas as pd
import plotly.express as px
from sqlalchemy import create_engine
import os

# --- CONFIGURAÇÕES DA PÁGINA ---
st.set_page_config(
    page_title="Dashboard de Ameaças e Vulnerabilidades",
    page_icon="🛡️",
    layout="wide"
)

# --- CONEXÃO COM O BANCO ---
user = os.getenv("DB_USER", "admin")
password = os.getenv("DB_PASS", "admin_password")
host = os.getenv("DB_HOST", "127.0.0.1")
db = os.getenv("DB_NAME", "vuln_db")

@st.cache_data
def get_data(query):
    """Função para buscar dados já agregados do PostgreSQL"""
    db_connection_str = f'postgresql+psycopg2://{user}:{password}@{host}/{db}'
    engine = create_engine(db_connection_str)
    return pd.read_sql(query, engine)

# --- CABEÇALHO ---
st.title("🛡️ Cyber Threat Intelligence Dashboard")
st.markdown("Análise de Vulnerabilidades, Risco de Exploração e Táticas MITRE ATT&CK")

# Criação das Abas
tab1, tab2, tab3, tab4 = st.tabs([
    "📊 Visão Geral (CVE & CVSS)", 
    "🎯 Risco e Exploração (EPSS & KEV)", 
    "🐛 Raiz do Problema (CWE)", 
    "🥷 Padrões de Ataque (MITRE)"
])

# ==========================================
# ABA 1: VISÃO GERAL (CVE & CVSS)
# ==========================================
with tab1:
    st.header("Métricas Globais de Vulnerabilidades")
    
    # KPIs
    kpi_query = """
        SELECT 
            COUNT(id) as total_cves,
            ROUND(AVG(cvss_base_score), 2) as media_score,
            COUNT(CASE WHEN cvss_base_severity = 'CRITICAL' THEN 1 END) as total_criticas
        FROM cves
    """
    df_kpi = get_data(kpi_query)
    
    col1, col2, col3 = st.columns(3)
    col1.metric("Total de CVEs Registadas", f"{df_kpi['total_cves'][0]:,}")
    col2.metric("Média de Score CVSS", df_kpi['media_score'][0])
    col3.metric("Vulnerabilidades Críticas", f"{df_kpi['total_criticas'][0]:,}")
    
    st.divider()
    
    col_chart1, col_chart2 = st.columns(2)
    
    # Grafico 1: Timeline e Proporção de Severidades
    with col_chart1:
        st.subheader("Evolução e Severidade ao Longo do Tempo")
        timeline_query = """
            SELECT 
                TO_CHAR(published_date, 'YYYY-MM') as mes_ano,
                cvss_base_severity,
                COUNT(id) as qtd
            FROM cves
            WHERE cvss_base_severity IS NOT NULL
            GROUP BY TO_CHAR(published_date, 'YYYY-MM'), cvss_base_severity
            ORDER BY mes_ano
        """
        df_timeline = get_data(timeline_query)
        fig_bar = px.bar(
            df_timeline, x='mes_ano', y='qtd', color='cvss_base_severity',
            labels={'mes_ano': 'Data', 'qtd': 'Nº de CVEs', 'cvss_base_severity': 'Severidade'},
            color_discrete_map={'CRITICAL': 'darkred', 'HIGH': 'red', 'MEDIUM': 'orange', 'LOW': 'yellow'}
        )
        st.plotly_chart(fig_bar, use_container_width=True)

    # Grafico 2: Distribuição de Severidade
    with col_chart2:
        st.subheader("Distribuição por Severidade")
        severity_query = """
            SELECT cvss_base_severity as severidade, COUNT(id) as qtd
            FROM cves WHERE cvss_base_severity IS NOT NULL
            GROUP BY cvss_base_severity
        """
        df_sev = get_data(severity_query)
        fig_pie = px.pie(df_sev, values='qtd', names='severidade',
                         color='severidade',
                         color_discrete_map={'CRITICAL': 'darkred', 'HIGH': 'red', 'MEDIUM': 'orange', 'LOW': 'yellow'})
        st.plotly_chart(fig_pie, use_container_width=True)

# ==========================================
# ABA 2: RISCO E EXPLORAÇÃO (EPSS & KEV)
# ==========================================
with tab2:
    st.header("Análise de Risco Prático vs Teórico")
    
    st.subheader("Fator Ransomware (KEV)")
    ransom_query = """
        SELECT 
            CASE WHEN known_ransomware_usage THEN 'Com Ransomware' ELSE 'Sem Ransomware' END as uso_ransomware,
            COUNT(cve_id) as qtd
        FROM kev
        GROUP BY known_ransomware_usage
        """
    df_ransom = get_data(ransom_query)
    fig_ransom = px.pie(df_ransom, values='qtd', names='uso_ransomware', hole=0.5,
                            color='uso_ransomware', color_discrete_map={'Com Ransomware': '#8b0000', 'Sem Ransomware': '#1f77b4'})
    st.plotly_chart(fig_ransom, use_container_width=True)
        
    st.divider()
    col_kev2, col_kev3 = st.columns([1, 2])
        
    with col_kev2:
        st.subheader("Top Vendors com Vulnerabilidades Exploradas")
        vendor_query = """
            SELECT vendor_project, COUNT(cve_id) as qtd
            FROM kev
            GROUP BY vendor_project
            ORDER BY qtd DESC LIMIT 10
        """
        df_vendor = get_data(vendor_query)
        fig_vendor = px.bar(df_vendor, x='qtd', y='vendor_project', orientation='h', 
                            labels={'qtd': 'Vulnerabilidades', 'vendor_project': 'Fabricante'})
        fig_vendor.update_layout(yaxis={'categoryorder':'total ascending'})
        st.plotly_chart(fig_vendor, use_container_width=True)
        
    with col_kev3:
        st.subheader("Top Produtos com Vulnerabilidades Exploradas")
        vendor_query = """
            SELECT product, COUNT(cve_id) as qtd
            FROM kev
            GROUP BY product
            ORDER BY qtd DESC LIMIT 10
        """
        df_vendor = get_data(vendor_query)
        fig_vendor = px.bar(df_vendor, x='qtd', y='product', orientation='h', 
                            labels={'qtd': 'Vulnerabilidades', 'product': 'Produto'})
        fig_vendor.update_layout(yaxis={'categoryorder':'total ascending'})
        st.plotly_chart(fig_vendor, use_container_width=True)
        
    st.divider()
    
    st.subheader("CVSS (Dano Teórico) vs EPSS (Probabilidade Real)")
    st.info("💡 A área no canto superior direito indica as vulnerabilidades mais críticas que devem ser corrigidas de imediato (Alto Dano + Alta Probabilidade).")
    
    scatter_query = """
        SELECT 
            c.id, 
            c.cvss_base_score, 
            e.epss_score, 
            c.cvss_base_severity,
            CASE WHEN k.cve_id IS NOT NULL THEN 'No KEV' ELSE 'Fora do KEV' END as status_kev
        FROM cves c
        JOIN epss_scores e ON c.id = e.cve_id
        LEFT JOIN kev k ON c.id = k.cve_id
        WHERE c.cvss_base_score IS NOT NULL
        LIMIT 5000
    """
    df_scatter = get_data(scatter_query)
    fig_scatter = px.scatter(
        df_scatter, x='cvss_base_score', y='epss_score', color='status_kev',
        hover_data=['id', 'cvss_base_severity'],
        labels={'cvss_base_score': 'CVSS Score (0-10)', 'epss_score': 'EPSS Score (Probabilidade 0-1)', 'status_kev': 'Catálogo KEV'},
        opacity=0.7
    )
    st.plotly_chart(fig_scatter, use_container_width=True)

# ==========================================
# ABA 3: RAIZ DO PROBLEMA (CWE)
# ==========================================
with tab3:
    st.header("Fraquezas de Software Mais Recorrentes")
    
    st.subheader("Top 10 CWEs (Geral)")
    cwe_geral_query = """
            SELECT cw.id || ' - ' || SUBSTRING(cw.description, 1, 30) || '...' as fraqueza, COUNT(m.cve_id) as qtd
            FROM cve_cwe_mapping m
            JOIN cwes cw ON m.cwe_id = cw.id
            GROUP BY cw.id, cw.description
            ORDER BY qtd DESC LIMIT 10
        """
    df_cwe_geral = get_data(cwe_geral_query)
    fig_cwe1 = px.bar(df_cwe_geral, x='qtd', y='fraqueza', orientation='h')
    fig_cwe1.update_layout(yaxis={'categoryorder':'total ascending'})
    st.plotly_chart(fig_cwe1, use_container_width=True)
        
    st.divider()

    st.subheader("Top 10 CWEs em Vulnerabilidades Críticas")
    cwe_crit_query = """
            SELECT cw.id || ' - ' || SUBSTRING(cw.description, 1, 30) || '...' as fraqueza, COUNT(m.cve_id) as qtd
            FROM cve_cwe_mapping m
            JOIN cwes cw ON m.cwe_id = cw.id
            JOIN cves c ON m.cve_id = c.id
            WHERE c.cvss_base_severity = 'CRITICAL'
            GROUP BY cw.id, cw.description
            ORDER BY qtd DESC LIMIT 10
        """
    df_cwe_crit = get_data(cwe_crit_query)
    fig_cwe2 = px.bar(df_cwe_crit, x='qtd', y='fraqueza', orientation='h', color_discrete_sequence=['darkred'])
    fig_cwe2.update_layout(yaxis={'categoryorder':'total ascending'})
    st.plotly_chart(fig_cwe2, use_container_width=True)


# ==========================================
# ABA 4: PADRÕES DE ATAQUE (MITRE)
# ==========================================
with tab4:
    st.header("Inteligência de Ameaças: MITRE ATT&CK")
    st.markdown("Cruzamento das vulnerabilidades com as Técnicas do MITRE mais prováveis de serem utilizadas pelos atacantes.")
    
    col_mitre1, col_mitre2 = st.columns([1, 1])
    
    # 1. Gráfico de Barras: Top 10 Técnicas
    with col_mitre1:
        st.subheader("Top 10 Técnicas Mais Utilizadas")
        query_tech = """
            SELECT 
                t.name AS tecnica,
                COUNT(DISTINCT ccm.cve_id) AS qtd_cves
            FROM cwe_mitre_mapping cmm
            JOIN mitre_techniques t ON (t.id = cmm.mitre_id OR t.id = 'T' || cmm.mitre_id)
            JOIN cve_cwe_mapping ccm ON cmm.cwe_id = ccm.cwe_id
            GROUP BY t.name
            ORDER BY qtd_cves DESC
            LIMIT 10
        """
        df_tech = get_data(query_tech)
        
        if not df_tech.empty:
            fig_tech = px.bar(df_tech, x='qtd_cves', y='tecnica', orientation='h', 
                              labels={'qtd_cves': 'Nº de CVEs Associadas', 'tecnica': 'Técnica MITRE'},
                              color='qtd_cves', color_continuous_scale='Reds')
            fig_tech.update_layout(yaxis={'categoryorder':'total ascending'})
            st.plotly_chart(fig_tech, use_container_width=True)
            
            
    # grafico com top 10 taticas a ser feito

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
            # px.treemap gera blocos retangulares, perfeitos para leitura
            fig_tree = px.treemap(
                df_tree, 
                path=['tecnica', 'fraqueza'], 
                values='qtd_cves',
                color='qtd_cves',
                color_continuous_scale='Reds'
            )
            fig_tree.update_layout(margin=dict(t=20, l=0, r=0, b=0))
            st.plotly_chart(fig_tree, use_container_width=True)
    else:
            st.warning("Sem dados suficientes para o detalhamento.")