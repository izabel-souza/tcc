import subprocess
import os
import sys
import time
import psycopg2

# --- CONFIGURAÇÃO ---
DB_CONFIG = {
    "dbname": "vuln_db",
    "user": "admin",
    "password": "admin_password",
    "host": "localhost",
    "port": "5432"
}

SCRIPTS_FOLDER = "populate tables"

SCRIPTS_ORDER = [
    "cve.py",  
    "kev.py",  
    "epss.py",
    "cwe.py"
]

def wait_for_db():
    print("Aguardando banco de dados ficar online...")
    retries = 30
    while retries > 0:
        try:
            conn = psycopg2.connect(**DB_CONFIG)
            conn.close()
            print("Banco de dados conectado")
            return True
        except psycopg2.OperationalError:
            time.sleep(2)
            retries -= 1
            print(f"   Tentando conectar... ({retries} tentativas restantes)")
    return False

def run_script(script_name):
    """Roda um script python localizado na pasta 'populate tables'"""
    script_path = os.path.join(SCRIPTS_FOLDER, script_name)
    
    # Verifica se arquivo existe
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

def main():
    print("="*40)
    print(" INICIANDO AUTOMAÇÃO DE CARGA (ETL)")
    print("="*40)

    # garante que o banco está de pé (caso tenha acabado de dar docker up)
    if not wait_for_db():
        print("❌ Falha: O banco de dados não está respondendo. Verifique o Docker.")
        sys.exit(1)

    # roda os scripts na ordem
    for script in SCRIPTS_ORDER:
        success = run_script(script)
        if not success:
            print("\nProcesso interrompido devido a erro no script anterior.")
            sys.exit(1)

    print("\n" + "="*40)
    print("CARGA COMPLETA FINALIZADA COM SUCESSO!")
    print(" Agora você pode rodar: streamlit run app.py")
    print("="*40)

if __name__ == "__main__":
    main()