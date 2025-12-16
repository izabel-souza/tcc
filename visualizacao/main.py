import psycopg2
import streamlit as st

def get_connection():
    try:
        conn = psycopg2.connect(
            dbname="vuln_db", 
            user="admin", 
            password="admin_password",
            host="localhost", 
            port="5432"
        )
        return conn
    except Exception as e:
        print(f"Erro de conexão: {e}")
        return None