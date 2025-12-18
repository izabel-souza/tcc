import streamlit as st
import pandas as pd
import plotly.express as px
from sqlalchemy import create_engine

# --- CONFIGURAÇÃO DA PÁGINA ---
st.set_page_config(
    page_title="Dashboard de Vulnerabilidades (CVE)",
    page_icon="🛡️",
    layout="wide"
)

#conexao com banco de dados
#@st.cache_data para nao recarregar o banco a cada clique
@st.cache_data
def load_data():
    #conexao
    db_connection_str = 'postgresql+psycopg2://admin:admin_password@localhost/vuln_db'
    db_connection = create_engine(db_connection_str)

    query = """
    SELECT 
        id, 
        published_date, 
        cvss_base_score, 
        cvss_base_severity,
        cvss_attack_vector
    FROM cves
    """
    
    try:
        df = pd.read_sql(query, db_connection)
        
        # Tratamento de dados básico
        df['published_date'] = pd.to_datetime(df['published_date'])
        df['year'] = df['published_date'].dt.year
        df['month_year'] = df['published_date'].dt.strftime('%Y-%m')
        
        # Ordenar severidade para os gráficos ficarem bonitos
        severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, None: 0}
        df['severity_sort'] = df['cvss_base_severity'].map(severity_order)
        df = df.sort_values('severity_sort', ascending=False)
        
        return df
    except Exception as e:
        st.error(f"Erro ao conectar no banco: {e}")
        return pd.DataFrame()

# --- CARGA DOS DADOS ---
df_completo = load_data()

if df_completo.empty:
    st.warning("Nenhum dado encontrado ou erro de conexão.")
    st.stop()

# --- BARRA LATERAL (FILTROS) ---
st.sidebar.header("Filtros")

# Filtro de Ano
anos_disponiveis = sorted(df_completo['year'].unique(), reverse=True)
anos_selecionados = st.sidebar.multiselect(
    "Selecione o Ano de Publicação:",
    options=anos_disponiveis,
    default=anos_disponiveis[:1] # Seleciona o ano mais recente por padrão
)

# Aplica o filtro
if anos_selecionados:
    df_filtrado = df_completo[df_completo['year'].isin(anos_selecionados)]
else:
    df_filtrado = df_completo

# --- CORPO PRINCIPAL DO DASHBOARD ---
st.title("🛡️ Análise de Vulnerabilidades (CVEs)")
st.markdown("Visão geral das vulnerabilidades publicadas no NVD.")

# 1. KPIs (Indicadores Chave)
col1, col2, col3 = st.columns(3)
with col1:
    st.metric("Total de CVEs Analisadas", f"{len(df_filtrado):,}")
with col2:
    media_score = df_filtrado['cvss_base_score'].mean()
    st.metric("Média Score CVSS", f"{media_score:.2f}")
with col3:
    criticas = len(df_filtrado[df_filtrado['cvss_base_severity'] == 'CRITICAL'])
    st.metric("Vulnerabilidades Críticas", f"{criticas:,}")

st.divider()

# 2. GRÁFICOS
col_graf1, col_graf2 = st.columns(2)

# Gráfico 1: Evolução Temporal (Linha do Tempo)
with col_graf1:
    st.subheader("Publicação de CVEs ao Longo do Tempo")
    
    # Agrupa por Mês/Ano
    df_timeline = df_filtrado.groupby('month_year').size().reset_index(name='count')
    
    fig_line = px.line(
        df_timeline, 
        x='month_year', 
        y='count',
        markers=True,
        labels={'month_year': 'Mês de Publicação', 'count': 'Qtd. CVEs'}
    )
    st.plotly_chart(fig_line, use_container_width=True)

# Gráfico 2: Distribuição por Severidade (Pizza/Donut)
with col_graf2:
    st.subheader("Distribuição por Severidade")
    
    # Agrupa por Severidade
    df_severity = df_filtrado.groupby('cvss_base_severity').size().reset_index(name='count')
    
    fig_pie = px.pie(
        df_severity, 
        values='count', 
        names='cvss_base_severity',
        hole=0.4, # Faz virar um gráfico de Rosca (Donut)
        color='cvss_base_severity',
        color_discrete_map={
            'CRITICAL': 'red',
            'HIGH': 'orange',
            'MEDIUM': 'yellow',
            'LOW': 'green'
        }
    )
    st.plotly_chart(fig_pie, use_container_width=True)

# 3. TABELA DE DADOS BRUTOS (Expansível)
with st.expander("Ver Dados Brutos"):
    st.dataframe(df_filtrado[['id', 'published_date', 'cvss_base_score', 'cvss_base_severity', 'cvss_attack_vector']])