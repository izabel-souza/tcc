# --- IMPORTS ---
import streamlit as st
import pandas as pd
from sqlalchemy import create_engine, text
import os

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