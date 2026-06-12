# --- IMPORTS ---
from pathlib import Path
import base64

import streamlit as st
from src.tabs.about import render_about_tab
from src.tabs.cwe import render_cwe_tab
from src.tabs.kev_epss import render_risk_tab
from src.tabs.mitre import render_mitre_tab
from src.tabs.vision import render_vision_tab

# --- ASSETS ---
BASE_DIR = Path(__file__).resolve().parent
LOGO_PATH = BASE_DIR / "assets" / "vulnera_logo.png"
ICON_PATH = BASE_DIR / "assets" / "vulnera_icon.png"
LOGO_BASE64 = base64.b64encode(LOGO_PATH.read_bytes()).decode("utf-8")
ICON_BASE64 = base64.b64encode(ICON_PATH.read_bytes()).decode("utf-8")

# --- CONFIGURACOES DA PAGINA ---
st.set_page_config(
    page_title="Vulnera",
    page_icon=str(ICON_PATH),
    layout="wide"
)

st.markdown("""
    <style>
    :root {
        --vulnera-blue: #004aad;
        --vulnera-cyan: #38b6ff;
        --vulnera-bg: #0F172A;
        --vulnera-card: #1E293B;
        --vulnera-border: #334155;
        --vulnera-text: #F8FAFC;
        --vulnera-muted: #CBD5E1;
    }

    .stApp {
        background:
            radial-gradient(circle at top left, rgba(56, 182, 255, 0.10), transparent 30rem),
            linear-gradient(180deg, #0B1120 0%, var(--vulnera-bg) 45%, #111827 100%);
        color: var(--vulnera-text);
    }

    [data-testid="stSidebar"] {
        background-color: #0B1120;
        border-right: 1px solid rgba(56, 182, 255, 0.16);
    }

    [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p,
    [data-testid="stSidebar"] label {
        color: var(--vulnera-muted);
    }

    .vulnera-hero {
        position: relative;
        overflow: hidden;
        margin: 0 0 2rem 0;
        padding: 2rem 1.6rem 1.9rem;
        border: 1px solid rgba(56, 182, 255, 0.24);
        border-radius: 18px;
        background:
            radial-gradient(circle at 50% 26%, rgba(0, 74, 173, 0.10), transparent 18rem),
            linear-gradient(135deg, rgba(0, 74, 173, 0.12), rgba(8, 13, 27, 0.96)),
            rgba(15, 23, 42, 0.94);
        box-shadow: 0 18px 42px rgba(0, 0, 0, 0.22);
    }

    .vulnera-hero > * {
        position: relative;
        z-index: 1;
    }

    .vulnera-logo {
        display: block;
        width: min(430px, 72vw);
        height: auto;
        margin: 0 auto 1rem;
        filter: drop-shadow(0 0 12px rgba(56, 182, 255, 0.10));
    }

    .vulnera-subtitle {
        margin: 0 0 0.25rem;
        color: var(--vulnera-text);
        font-size: 1.35rem;
        font-weight: 700;
        text-align: center;
    }

    .vulnera-description {
        margin: 0;
        color: var(--vulnera-muted);
        font-size: 1rem;
        line-height: 1.55;
        text-align: center;
    }

    .vulnera-pill-row {
        display: flex;
        justify-content: center;
        flex-wrap: wrap;
        gap: 0.6rem;
        margin-top: 1rem;
    }

    .vulnera-pill {
        border: 1px solid rgba(56, 182, 255, 0.28);
        border-radius: 999px;
        color: #E0F2FE;
        background: rgba(56, 182, 255, 0.08);
        padding: 0.35rem 0.72rem;
        font-size: 0.82rem;
        font-weight: 600;
    }

    .vulnera-sidebar-brand {
        margin: 0.15rem 0 1.35rem;
        text-align: center;
    }

    .vulnera-sidebar-icon {
        display: block;
        width: 76px;
        margin: 0 auto 0.9rem;
    }

    .vulnera-sidebar-title {
        margin-top: 0;
        color: var(--vulnera-text);
        font-size: 1.5rem;
        font-weight: 800;
        letter-spacing: 0;
        line-height: 1.1;
    }

    .vulnera-sidebar-caption {
        color: var(--vulnera-muted);
        font-size: 0.78rem;
        line-height: 1.35;
    }

    h1, h2, h3 {
        color: var(--vulnera-text);
        letter-spacing: 0;
    }

    div[data-testid="stHeader"] {
        background: rgba(11, 17, 32, 0.72);
    }

    /* Estilizacao dos containers com borda para os paineis parecerem cards. */
    [data-testid="stVerticalBlockBorderWrapper"] {
        background-color: rgba(30, 41, 59, 0.92) !important;
        border: 1px solid var(--vulnera-border) !important;
        border-radius: 14px !important;
        padding: 16px !important;
    }

    /* Garante que o fundo do grafico Plotly nao sobrescreva o card. */
    .stPlotlyChart {
        background-color: rgba(30, 41, 59, 0.92) !important;
        border-radius: 14px !important;
    }

    div[data-testid="stMetricValue"],
    div[data-testid="stMetricLabel"] {
        color: var(--vulnera-text);
    }

    hr {
        border-color: rgba(56, 182, 255, 0.16);
    }
    </style>
    """, unsafe_allow_html=True)

# --- IDENTIDADE DA PLATAFORMA ---
st.markdown(
    f"""
    <section class="vulnera-hero">
        <img class="vulnera-logo" src="data:image/png;base64,{LOGO_BASE64}" alt="Vulnera">
        <p class="vulnera-subtitle">Plataforma de Inteligência e Análise de Vulnerabilidades</p>
        <p class="vulnera-description">
            Integração entre CVE, EPSS, KEV, CWE e MITRE ATT&CK para priorização baseada em risco.
        </p>
        <div class="vulnera-pill-row">
            <span class="vulnera-pill">Múltiplas fontes públicas</span>
            <span class="vulnera-pill">Priorização por risco</span>
            <span class="vulnera-pill">Defesa orientada por ameaças</span>
        </div>
    </section>
    """,
    unsafe_allow_html=True
)

# ==========================================
# BARRA LATERAL (FILTROS)
# ==========================================
st.sidebar.markdown(
    f"""
    <div class="vulnera-sidebar-brand">
        <img class="vulnera-sidebar-icon" src="data:image/png;base64,{ICON_BASE64}" alt="Vulnera">
        <div class="vulnera-sidebar-title">Vulnera</div>
        <div class="vulnera-sidebar-caption">Inteligência e análise de vulnerabilidades</div>
    </div>
    """,
    unsafe_allow_html=True
)

st.sidebar.header("Filtros Globais")

# Filtro de Ano - Range Slider
ano_min, ano_max = 2015, 2026
periodo = st.sidebar.slider(
    "Período de Publicação (CVE)",
    min_value=ano_min,
    max_value=ano_max,
    value=(ano_min, ano_max),
    help="Arraste para selecionar o intervalo de anos.")

# Filtro de CVE
busca_cve = st.sidebar.text_input(
    "Buscar CVE por ID",
    placeholder="Ex: CVE-2024-1234",
    help="Digite o ID completo ou parcial para filtrar."
)

# Filtro de Severidade (CVSS)
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

if busca_cve:
    condicao_busca = f"id ILIKE '%{busca_cve}%'"
    condicao_busca_alias = f"c.id ILIKE '%{busca_cve}%'"
else:
    condicao_busca = "1=1"
    condicao_busca_alias = "1=1"

filtro_sql = f"({condicao_ano}) AND ({condicao_sev}) AND ({condicao_busca})"
filtro_sql_alias = f"({condicao_ano_alias}) AND ({condicao_sev_alias}) AND ({condicao_busca_alias})"
filtro_estatistico_alias = f"({condicao_ano_alias}) AND ({condicao_sev_alias})"


# NOME DAS PAGINAS/ABAS
titulos_paginas = ["Sobre", "Visão Geral", "Risco e Exploração", "Raiz do Problema", "Padrões de Ataque"]

st.sidebar.divider()

# NAVEGACAO
st.sidebar.header("Módulos")

# CRIA RADIO PARA NAVEGACAO
pagina_selecionada = st.sidebar.radio(
    label="Menu de Navegação",
    options=titulos_paginas,
    key="pagina_ativa",
    label_visibility="collapsed"
)

# RENDERIZA AS ABAS DE ACORDO COM A VARIAVEL SELECIONADA
if pagina_selecionada == "Sobre":
    render_about_tab()

elif pagina_selecionada == "Visão Geral":
    render_vision_tab(filtro_sql, filtro_sql_alias, condicao_ano, severidades_selecionadas)

elif pagina_selecionada == "Risco e Exploração":
    render_risk_tab(filtro_sql_alias, filtro_estatistico_alias)

elif pagina_selecionada == "Raiz do Problema":
    render_cwe_tab(filtro_estatistico_alias)

elif pagina_selecionada == "Padrões de Ataque":
    render_mitre_tab(filtro_estatistico_alias)
