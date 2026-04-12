# --- IMPORTS ---
import subprocess
import os
import sys
import time
import psycopg2

# Captura as variáveis
env_pass = os.getenv("DB_PASS")
env_nvd = os.getenv("NVD_API_KEY")

db_password = env_pass if env_pass else "admin_password"

RUN_MODE = os.getenv("RUN_MODE", "incremental")

# --- CONFIGURAÇÃO DO BANCO DE DADOS ---
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME", "vuln_db"),
    "user": os.getenv("DB_USER", "admin"),
    "password": db_password,
    "host": os.getenv("DB_HOST", "127.0.0.1"),
    "port": os.getenv("DB_PORT", "5432")
}

# --- VARIAVEIS ---
SCRIPTS_FOLDER = "populate-tables"

SCRIPTS_ORDER = [
    "cve.py",  
    "kev.py",  
    "epss.py",
    "cwe.py",
    "mitreattack.py",
    "capec.py"
]

# --- FUNÇÃO QUE ESPERA BANCO PARA CONEXAO ---
def wait_for_db():
    retries = 30
    while retries > 0:
        try:
            conn = psycopg2.connect(**DB_CONFIG)
            conn.close()
            print("Conexão estabelecida com sucesso!")
            return True
        except psycopg2.OperationalError as e:
            print(f"Erro de conexão: {e}") 
            print(f"Tentando novamente. ({retries} tentativas restantes).") 
            time.sleep(2)
            retries -= 1
    return False

# --- FUNÇÃO QUE EXECUTA OS SCRIPTS NA PASTA 'POPULATE TABLES' ---
def run_script(script_name):
    """Roda um script python localizado na pasta 'populate-tables'"""
    script_path = os.path.join(SCRIPTS_FOLDER, script_name)
    
    # verifica se arquivo existe
    if not os.path.exists(script_path):
        print(f"Erro: Arquivo {script_path} não encontrado.")
        return False

    print(f"\nIniciando execução de: {script_name}")
    try:
        subprocess.check_call([sys.executable, script_path])
        print(f"{script_name} finalizado com sucesso.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Erro ao rodar {script_name}. Código de saída: {e.returncode}")
        return False

# --- FUNÇÃO PRINCIPAL ---
def main():
    print("="*40)
    print(f" INICIANDO ETL - MODO: {RUN_MODE.upper()}")
    print("="*40)

    if not wait_for_db():
        sys.exit(1)

    for script in SCRIPTS_ORDER:
        success = run_script(script)
        if not success:
            sys.exit(1)

    print("\n" + "="*40)
    print("PROCESSO FINALIZADO!")
    print("="*40)

if __name__ == "__main__":
    main()