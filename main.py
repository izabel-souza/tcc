import pandas as pd
from sqlalchemy import create_engine, text

db_connection_str = 'postgresql://admin:admin_password@localhost:5050/vuln_db'
db_connection = create_engine(db_connection_str)

try:
    with db_connection.connect() as connection:
        result = connection.execute(text("SELECT version()"))
        print("Conectado com sucesso ao Postgres!")
        print("Versão:", result.fetchone()[0])
except Exception as e:
    print("Erro ao conectar:", e)