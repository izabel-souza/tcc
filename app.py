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
st.title("Dashboard de Ameaças e Vulnerabilidades")
st.markdown("Análise de Vulnerabilidades, Risco de Exploração e Táticas MITRE ATT&CK")

# ==========================================
# BARRA LATERAL (FILTROS GLOBAIS - SLIDER)
# ==========================================
st.sidebar.header("⚙️ Filtros Globais")

# filtro de Ano - Range Slider
# O valor inicial (value) define o intervalo total
ano_min, ano_max = 2015, 2026
periodo = st.sidebar.slider(
    "Período de Publicação (CVE)",
    min_value=ano_min,
    max_value=ano_max,
    value=(ano_min, ano_max),
    help="Arraste as extremidades para filtrar um intervalo de anos."
)

# filtro de Severidade (CVSS) - multiselect
opcoes_severidade = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
severidades_selecionadas = st.sidebar.multiselect(
    "Severidade CVSS", 
    options=opcoes_severidade, 
    default=[],
    placeholder="Todas as severidades"
)

# --- LÓGICA DINÂMICA DO SQL ---

# logica para o ano: Se o intervalo for o máximo, ignora o filtro (1=1)
if periodo[0] == ano_min and periodo[1] == ano_max:
    condicao_ano = "1=1"
    condicao_ano_alias = "1=1"
else:
    condicao_ano = f"EXTRACT(YEAR FROM published_date) BETWEEN {periodo[0]} AND {periodo[1]}"
    condicao_ano_alias = f"EXTRACT(YEAR FROM c.published_date) BETWEEN {periodo[0]} AND {periodo[1]}"

# logica para severidade: Vazio = Tudo (1=1)
if severidades_selecionadas:
    sev_formatadas = "', '".join(severidades_selecionadas)
    condicao_sev = f"cvss_base_severity IN ('{sev_formatadas}')"
    condicao_sev_alias = f"c.cvss_base_severity IN ('{sev_formatadas}')"
else:
    condicao_sev = "1=1"
    condicao_sev_alias = "1=1"

# filtros para as queries
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
# ABA 1: VISÃO GERAL (CVE & CVSS)
# ==========================================
with tab1:
    st.header("Métricas Globais de Vulnerabilidades")
    
    # KPIs
    kpi_query = f"""
        SELECT 
            COUNT(id) as total_cves,
            ROUND(AVG(cvss_base_score), 2) as media_score,
            COUNT(CASE WHEN cvss_base_severity = 'CRITICAL' THEN 1 END) as total_criticas
        FROM cves
        WHERE {filtro_sql}
    """
    df_kpi = get_data(kpi_query)
    
    col1, col2, col3 = st.columns(3)
    col1.metric("Total de CVEs Registadas", f"{df_kpi['total_cves'][0]:,}")
    col2.metric("Média de Score CVSS", df_kpi['media_score'][0])
    col3.metric("Vulnerabilidades Críticas", f"{df_kpi['total_criticas'][0]:,}")
    
    st.divider()
    
    col_chart1, col_chart2 = st.columns(2)
    
    # (grafico de barra) - Evolução e Severidade ao Longo do Tempo
    with col_chart1:
        st.subheader("Evolução e Severidade ao Longo do Tempo")
        timeline_query = f"""
            SELECT 
                TO_CHAR(published_date, 'YYYY-MM') as mes_ano,
                cvss_base_severity,
                COUNT(id) as qtd
            FROM cves
            WHERE {filtro_sql} AND cvss_base_severity IS NOT NULL
            GROUP BY TO_CHAR(published_date, 'YYYY-MM'), cvss_base_severity
            ORDER BY mes_ano
        """
        df_timeline = get_data(timeline_query)
        fig_bar = px.bar(
            df_timeline, x='mes_ano', y='qtd', color='cvss_base_severity',
            labels={'mes_ano': 'Data', 'qtd': 'Nº de CVEs', 'cvss_base_severity': 'Severidade'},
            color_discrete_map={'CRITICAL': 'darkred', 'HIGH': 'red', 'MEDIUM': 'orange', 'LOW': 'yellow'}
        )
        
        # um clique foca no item selecionado
        fig_bar.update_layout(
            legend_itemclick="toggleothers",       
            legend_itemdoubleclick="toggle"        
        )
        
        st.plotly_chart(fig_bar, use_container_width=True)

    # (grafico de pizza) - Distribuição por Severidade
    with col_chart2:
        st.subheader("Distribuição por Severidade")
        
        severity_query = f"""
            SELECT cvss_base_severity as severidade, COUNT(id) as qtd
            FROM cves 
            WHERE cvss_base_severity IS NOT NULL 
            AND {filtro_sql}
            GROUP BY cvss_base_severity
        """
        df_sev = get_data(severity_query)

        if not df_sev.empty:
            # calcula a Porcentagem global
            total_filtrado = df_sev['qtd'].sum()
            df_sev['porcentagem_global'] = (df_sev['qtd'] / total_filtrado) * 100

            # cria o gráfico usando custom_data
            fig_pie = px.pie(
                df_sev, 
                values='qtd', 
                names='severidade',
                color='severidade',
                # passa a porcentagem calculada como um dado customizado
                custom_data=['porcentagem_global'],
                color_discrete_map={'CRITICAL': 'darkred', 'HIGH': 'red', 'MEDIUM': 'orange', 'LOW': 'yellow'}
            )
            
            # formata o texto para mostrar o valor fixo
            fig_pie.update_traces(
                # %{customdata[0]} pega o valor que calculamos, ignorando o calculo automatico do plotly
                texttemplate="<b>%{label}</b><br>%{customdata[0]:.1f}%",
                hovertemplate="<b>%{label}</b><br>Quantidade: %{value}<br>Proporção: %{customdata[0]:.1f}%<extra></extra>"
            )
            
            fig_pie.update_layout(
                legend_itemclick="toggleothers",       
                legend_itemdoubleclick="toggle"      
            )
            
            st.plotly_chart(fig_pie, use_container_width=True)
        else:
            st.warning("Sem dados para exibir a distribuição por severidade.")

# ==========================================
# ABA 2: RISCO E EXPLORAÇÃO (EPSS & KEV)
# ==========================================
with tab2:
    st.header("Análise de Risco Prático vs Teórico")
    
    # (grafico de rosca) - Fator Ransomware (KEV)
    st.subheader("Fator Ransomware (KEV)")
    ransom_query = """
        SELECT 
            CASE WHEN known_ransomware_usage THEN 'Com Ransomware' ELSE 'Sem Ransomware' END as uso_ransomware,
            COUNT(cve_id) as qtd
        FROM kev
        GROUP BY known_ransomware_usage
        """
    df_ransom = get_data(ransom_query)
    fig_ransom = px.pie(
        df_ransom, values='qtd', names='uso_ransomware', hole=0.5,
        color='uso_ransomware', color_discrete_map={
            'Com Ransomware': '#8b0000', 'Sem Ransomware': '#1f77b4'
        }
    )
    
    fig_ransom.update_layout(
        legend_itemclick="toggleothers",       
        legend_itemdoubleclick="toggle"        
    )
    
    st.plotly_chart(fig_ransom, use_container_width=True)
        
    col_kev2, col_kev3 = st.columns([1, 2])
        
    with col_kev2:

        # (grafico de barras laterais) - Top Vendors com Vulnerabilidades Exploradas
        st.subheader("Top Vendors com Vulnerabilidades Exploradas")
        vendor_query = f"""
            SELECT k.vendor_project, COUNT(k.cve_id) as qtd
            FROM kev k
            JOIN cves c ON k.cve_id = c.id
            WHERE {filtro_sql_alias}
            GROUP BY k.vendor_project
            ORDER BY qtd DESC LIMIT 10
        """
        df_vendor = get_data(vendor_query)
        fig_vendor = px.bar(df_vendor, x='qtd', y='vendor_project', orientation='h', 
                            labels={'qtd': 'Vulnerabilidades', 'vendor_project': 'Fabricante'})
        fig_vendor.update_layout(yaxis={'categoryorder':'total ascending'})
        
        fig_vendor.update_layout(
            legend_itemclick="toggleothers",       
            legend_itemdoubleclick="toggle"        
        )    
        st.plotly_chart(fig_vendor, use_container_width=True)
        
    with col_kev3:

        # (grafico de barras laterais) - Top products com Vulnerabilidades Exploradas
        st.subheader("Top Produtos com Vulnerabilidades Exploradas")
        vendor_query = f"""
            SELECT k.product, COUNT(k.cve_id) as qtd
            FROM kev k
            JOIN cves c ON k.cve_id = c.id
            WHERE {filtro_sql_alias}
            GROUP BY k.product
            ORDER BY qtd DESC LIMIT 10
        """
        df_vendor = get_data(vendor_query)
        fig_vendor = px.bar(df_vendor, x='qtd', y='product', orientation='h', 
                            labels={'qtd': 'Vulnerabilidades', 'product': 'Produto'})
        fig_vendor.update_layout(yaxis={'categoryorder':'total ascending'})
        
        fig_vendor.update_layout(
            legend_itemclick="toggleothers",       
            legend_itemdoubleclick="toggle"        
        )    
        
        st.plotly_chart(fig_vendor, use_container_width=True)
        
    st.divider()
    
    # (grafico de dispersao) - CVSS (Dano Teórico) vs EPSS (Probabilidade Real)
    st.subheader("CVSS (Dano Teórico) vs EPSS (Probabilidade Real)")
    st.info("💡 A área no canto superior direito indica as vulnerabilidades mais críticas que devem ser corrigidas de imediato (Alto Dano + Alta Probabilidade).")
    
    scatter_query = """
        SELECT 
            c.id, 
            c.cvss_base_score, 
            e.epss_score, 
            c.cvss_base_severity
        FROM cves c
        JOIN epss_scores e ON c.id = e.cve_id
        LEFT JOIN kev k ON c.id = k.cve_id
        WHERE c.cvss_base_score IS NOT NULL
        LIMIT 5000
    """
    df_scatter = get_data(scatter_query)
    fig_scatter = px.scatter(
        df_scatter, x='cvss_base_score', y='epss_score',
        hover_data=['id', 'cvss_base_severity'],
        labels={'cvss_base_score': 'CVSS Score (0-10)', 'epss_score': 'EPSS Score (Probabilidade 0-1)'},
        opacity=0.7
    )
    
    fig_scatter.update_layout(
        legend_itemclick="toggleothers",       
        legend_itemdoubleclick="toggle"        
    )    
    
    st.plotly_chart(fig_scatter, use_container_width=True)

# ==========================================
# ABA 3: RAIZ DO PROBLEMA (CWE)
# ==========================================
with tab3:
    st.header("Fraquezas de Software Mais Recorrentes")

    col_chart1, col_chart2 = st.columns(2)

    with col_chart1:
        
        st.subheader("Top 10 CWEs (Geral)")
        cwe_geral_query = f"""
            SELECT cw.id || ' - ' || SUBSTRING(cw.description, 1, 30) || '...' as fraqueza, COUNT(m.cve_id) as qtd
            FROM cve_cwe_mapping m
            JOIN cwes cw ON m.cwe_id = cw.id
            JOIN cves c ON m.cve_id = c.id
            WHERE {filtro_sql_alias}
            GROUP BY cw.id, cw.description
            ORDER BY qtd DESC LIMIT 10
        """
        df_cwe_geral = get_data(cwe_geral_query)
        fig_cwe1 = px.bar(df_cwe_geral, x='qtd', y='fraqueza', labels={'qtd': 'Quantidade', 'fraqueza': 'Fraqueza'}, orientation='h')
        fig_cwe1.update_layout(yaxis={'categoryorder':'total ascending'})
        
        fig_cwe1.update_layout(
                legend_itemclick="toggleothers",       
                legend_itemdoubleclick="toggle"        
            )   
        
        st.plotly_chart(fig_cwe1, use_container_width=True)

    with col_chart2:
        st.subheader("Top 10 CWEs em Vulnerabilidades Críticas")
        cwe_crit_query = f"""
            SELECT cw.id || ' - ' || SUBSTRING(cw.description, 1, 30) || '...' as fraqueza, COUNT(m.cve_id) as qtd
            FROM cve_cwe_mapping m
            JOIN cwes cw ON m.cwe_id = cw.id
            JOIN cves c ON m.cve_id = c.id
            WHERE c.cvss_base_severity = 'CRITICAL' AND {filtro_sql_alias}
            GROUP BY cw.id, cw.description
            ORDER BY qtd DESC LIMIT 10
        """
        df_cwe_crit = get_data(cwe_crit_query)
        fig_cwe2 = px.bar(df_cwe_crit, x='qtd', y='fraqueza', labels={'qtd': 'Quantidade', 'fraqueza': 'Fraqueza'},orientation='h', color_discrete_sequence=['darkred'])
        fig_cwe2.update_layout(yaxis={'categoryorder':'total ascending'})
        
        fig_cwe2.update_layout(
                legend_itemclick="toggleothers",       
                legend_itemdoubleclick="toggle"        
            ) 
        
        st.plotly_chart(fig_cwe2, use_container_width=True)

# ==========================================
# ABA 4: PADRÕES DE ATAQUE (MITRE)
# ==========================================
with tab4:
    st.header("Inteligência de Ameaças: MITRE ATT&CK")
    st.markdown("Cruzamento das vulnerabilidades com as Técnicas do MITRE mais prováveis de serem utilizadas pelos atacantes.")
    
    col_mitre1, col_mitre2 = st.columns([1, 1])
    
    # grafico com top 10 Técnicas
    with col_mitre1:
        st.subheader("Top 10 Técnicas Mais Utilizadas")
        query_tech = f"""
            SELECT t.name AS tecnica, COUNT(DISTINCT ccm.cve_id) AS qtd_cves
            FROM cwe_mitre_mapping cmm
            JOIN mitre_techniques t ON (t.id = cmm.mitre_id OR t.id = 'T' || cmm.mitre_id)
            JOIN cve_cwe_mapping ccm ON cmm.cwe_id = ccm.cwe_id
            JOIN cves c ON ccm.cve_id = c.id
            WHERE {filtro_sql_alias}
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
            
            fig_tech.update_layout(
                legend_itemclick="toggleothers",       
                legend_itemdoubleclick="toggle"        
            ) 
            
            st.plotly_chart(fig_tech, use_container_width=True)
            
            
    # grafico com top 10 taticas 
    with col_mitre2:
        st.subheader("Top 10 Táticas Mais Reportadas (Objetivo do Atacante)")

        query_taticas = f"""
            SELECT tac.name AS tatica, COUNT(DISTINCT ccm.cve_id) AS qtd_cves
            FROM cwe_mitre_mapping cmm
            JOIN mitre_techniques tec ON (tec.id = cmm.mitre_id OR tec.id = 'T' || cmm.mitre_id)
            JOIN mitre_tactic_technique mtt ON mtt.technique_id = tec.id
            JOIN mitre_tactics tac ON tac.id = mtt.tactic_id
            JOIN cve_cwe_mapping ccm ON ccm.cwe_id = ccm.cwe_id
            JOIN cves c ON ccm.cve_id = c.id
            WHERE {filtro_sql_alias}
            GROUP BY tac.name
            ORDER BY qtd_cves DESC
            LIMIT 10
        """

        df_taticas = get_data(query_taticas)

        if not df_taticas.empty:
            fig_taticas = px.bar(
                df_taticas, 
                x='qtd_cves', 
                y='tatica', 
                orientation='h', 
                labels={'qtd_cves': 'Nº de CVEs Associadas', 'tatica': 'Tática MITRE'},
                color='qtd_cves', 
                color_continuous_scale='Blues' 
            )
            fig_taticas.update_layout(yaxis={'categoryorder':'total ascending'})
            
            fig_taticas.update_layout(
                legend_itemclick="toggleothers",       
                legend_itemdoubleclick="toggle"        
            ) 
            
            st.plotly_chart(fig_taticas, use_container_width=True)
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
            
            st.plotly_chart(fig_tree, use_container_width=True)
    else:
            st.warning("Sem dados suficientes para o detalhamento.")