# --- IMPORTS ---
import streamlit as st
from src.tabs.vision import render_vision_tab
from src.tabs.kev_epss import render_risk_tab
from src.tabs.cwe import render_cwe_tab
from src.tabs.mitre import render_mitre_tab

# --- CONFIGURAÇÕES DA PÁGINA ---
st.set_page_config(
    page_title="Dashboard de Ameaças e Vulnerabilidades",
    page_icon="🛡️",
    layout="wide"
)

# --- TITULO E SUBTITULO DA PÁGINA ---
st.title("Dashboard de Ameaças e Vulnerabilidades")
st.markdown("Análise de Vulnerabilidades, Risco de Exploração e Táticas MITRE ATT&CK")

st.markdown("""
    <style>
    /* Estiliza o container com borda para parecer um card */
    [data-testid="stVerticalBlockBorderWrapper"] {
        background-color: #1F2937 !important;
        border: 1px solid #374151 !important;
        border-radius: 15px !important;
        padding: 15px !important;
    }
    /* Garante que o fundo do gráfico Plotly não sobrescreva o card */
    .stPlotlyChart {
        background-color: #1F2937 !important;
        border-radius: 15px !important;
    }
    </style>
    """, unsafe_allow_html=True)

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

# --- FILTRO VAZIO = RETORNA TUDO ---
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

tab1, tab2, tab3, tab4 = st.tabs([
    "Visão Geral", "Risco e Exploração", "Raiz do Problema", "Padrões de Ataque"
])

with tab1:
    render_vision_tab(filtro_sql, condicao_ano, severidades_selecionadas)

with tab2:
    render_risk_tab(filtro_sql_alias)

with tab3:
    render_cwe_tab(filtro_sql_alias)

with tab4:
    render_mitre_tab(filtro_sql_alias)