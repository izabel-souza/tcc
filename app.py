# --- IMPORTS ---
from pathlib import Path
from datetime import date
import base64

import streamlit as st
from src.tabs.about import render_about_tab
from src.tabs.cve_lookup import render_cve_lookup_tab
from src.tabs.cwe import render_cwe_tab
from src.tabs.kev_epss import render_risk_tab
from src.tabs.mitre import render_mitre_tab
from src.tabs.vision import render_vision_tab
from src.utils.database import get_data

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


def normalizar_data(valor, fallback):
    if valor is None:
        return fallback

    if isinstance(valor, date):
        return valor

    if hasattr(valor, "date"):
        return valor.date()

    try:
        return date.fromisoformat(str(valor)[:10])
    except ValueError:
        return fallback


@st.cache_data(show_spinner=False)
def buscar_ultima_data_publicacao():
    fallback = date.today()

    try:
        resultado = get_data("""
            SELECT MAX(published_date)::date AS data_max
            FROM cves
            WHERE published_date IS NOT NULL
        """)
    except Exception:
        return fallback

    if resultado.empty:
        return fallback

    return normalizar_data(resultado.loc[0, "data_max"], fallback)

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

    .block-container {
        padding-top: 3.3rem;
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

    .vulnera-top-nav {
        margin: 0 0 0.9rem;
    }

    div[data-testid="stPills"] {
        margin-bottom: 0.2rem;
    }

    div[data-testid="stPills"] div[role="radiogroup"] {
        align-items: center;
        flex-wrap: wrap;
        gap: 0.9rem;
    }

    div[data-testid="stPills"] button {
        border: 1px solid rgba(56, 182, 255, 0.24);
        background: rgba(15, 23, 42, 0.72);
        color: var(--vulnera-muted);
        font-weight: 700;
    }

    div[data-testid="stPills"] button[aria-checked="true"] {
        border-color: rgba(56, 182, 255, 0.72);
        background: rgba(56, 182, 255, 0.16);
        color: var(--vulnera-text);
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

    [data-testid="stSidebar"] div.stButton > button {
        min-height: 2.25rem;
        border: 1px solid rgba(56, 182, 255, 0.34);
        border-radius: 8px;
        background: rgba(0, 74, 173, 0.18);
        color: #E0F2FE;
        font-size: 0.88rem;
        font-weight: 700;
    }

    [data-testid="stSidebar"] div.stButton > button:hover {
        border-color: rgba(56, 182, 255, 0.62);
        background: rgba(0, 74, 173, 0.28);
        color: #F8FAFC;
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

# NOME DAS PAGINAS/ABAS
titulos_paginas = ["Sobre", "Visão Geral", "Consulta CVE", "Risco e Exploração", "Raiz do Problema", "Padrões de Ataque"]

# --- NAVEGACAO PRINCIPAL ---
st.markdown('<div class="vulnera-top-nav">', unsafe_allow_html=True)
pagina_selecionada = st.pills(
    label="Menu de navegação",
    options=titulos_paginas,
    default=titulos_paginas[0],
    key="pagina_ativa",
    label_visibility="collapsed"
)
st.markdown('</div>', unsafe_allow_html=True)

# --- IDENTIDADE DA PLATAFORMA ---
if pagina_selecionada == "Sobre":
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


def limpar_filtros(data_inicial, data_final):
    st.session_state["filtro_periodo_publicacao"] = (data_inicial, data_final)
    st.session_state["filtro_busca_cve"] = ""
    st.session_state["filtro_severidade_cvss"] = []


# Filtro de data de publicação
data_min = date(2015, 1, 1)
data_max = max(buscar_ultima_data_publicacao(), data_min)
periodo = st.sidebar.date_input(
    "Período de publicação (CVE)",
    value=(data_min, data_max),
    min_value=data_min,
    max_value=data_max,
    format="DD/MM/YYYY",
    key="filtro_periodo_publicacao",
    help="Selecione o intervalo de datas de publicação das CVEs."
)

if isinstance(periodo, tuple) and len(periodo) == 2:
    data_inicio, data_fim = periodo
else:
    data_inicio = data_min
    data_fim = data_max

if data_inicio > data_fim:
    data_inicio, data_fim = data_fim, data_inicio

# Filtro de CVE
busca_cve = st.sidebar.text_input(
    "Buscar CVE por ID",
    placeholder="Ex: CVE-2024-1234",
    key="filtro_busca_cve",
    help="Digite o ID completo ou parcial para filtrar."
)

# Filtro de Severidade (CVSS)
opcoes_severidade = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
severidades_selecionadas = st.sidebar.multiselect(
    "Severidade CVSS",
    options=opcoes_severidade,
    default=[],
    key="filtro_severidade_cvss",
    placeholder="Todas as severidades")

st.sidebar.markdown('<div style="height: 0.55rem;"></div>', unsafe_allow_html=True)
_, col_limpar_filtros, _ = st.sidebar.columns([0.12, 0.76, 0.12])
with col_limpar_filtros:
    st.button(
        "Limpar filtros",
        use_container_width=True,
        on_click=limpar_filtros,
        args=(data_min, data_max)
    )

# --- FILTRO VAZIO = RETORNA TUDO ---
if data_inicio == data_min and data_fim == data_max:
    condicao_ano = "1=1"
    condicao_ano_alias = "1=1"
else:
    condicao_ano = f"published_date::date BETWEEN '{data_inicio.isoformat()}' AND '{data_fim.isoformat()}'"
    condicao_ano_alias = f"c.published_date::date BETWEEN '{data_inicio.isoformat()}' AND '{data_fim.isoformat()}'"

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


# RENDERIZA AS ABAS DE ACORDO COM A VARIAVEL SELECIONADA
if pagina_selecionada == "Sobre":
    render_about_tab()

elif pagina_selecionada == "Visão Geral":
    render_vision_tab(filtro_sql, filtro_sql_alias, condicao_ano, severidades_selecionadas)

elif pagina_selecionada == "Consulta CVE":
    render_cve_lookup_tab(filtro_sql_alias)

elif pagina_selecionada == "Risco e Exploração":
    render_risk_tab(filtro_sql_alias, filtro_estatistico_alias)

elif pagina_selecionada == "Raiz do Problema":
    render_cwe_tab(filtro_estatistico_alias)

elif pagina_selecionada == "Padrões de Ataque":
    render_mitre_tab(filtro_estatistico_alias)
