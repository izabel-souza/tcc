# --- IMPORTS ---
import requests
import psycopg2
import zipfile
import io
import os
import csv

# --- CONFIGURACOES DE API ---
MITRE_CWE_URL = "https://cwe.mitre.org/data/csv/2000.csv.zip"

# --- CONFIGURACOES DO BANCO ---
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME", "vuln_db"),
    "user": os.getenv("DB_USER", "admin"),
    "password": os.getenv("DB_PASS", "admin_password"),
    "host": os.getenv("DB_HOST", "localhost"),
    "port": os.getenv("DB_PORT", "5432")
}

#funcao de conexao com banco de dados 
def get_connection():
    try:
        return psycopg2.connect(**DB_CONFIG)
    except Exception as e:
        print(f"Erro de conexão: {e}")
        return None
    

#funcao de insert no banco
def fetch_and_load_cwes():
    conn = get_connection()
    if not conn: return

    print(f"--- Baixando Dicionário CWE da MITRE ---")
    
    try:
        #download do ZIP
        response = requests.get(MITRE_CWE_URL)
        if response.status_code != 200:
            print(f"Erro ao baixar: {response.status_code}")
            return

        with zipfile.ZipFile(io.BytesIO(response.content)) as z:
            csv_filename = z.namelist()[0]
            print(f"Lendo arquivo interno: {csv_filename}")
            
            with z.open(csv_filename) as f:
                text_file = io.TextIOWrapper(f, encoding='utf-8', errors='replace')
                reader = csv.DictReader(text_file)
                cursor = conn.cursor()
                count_updated = 0
                
                print("Atualizando descrições no banco.")

                for row in reader:
                    raw_id = row.get('CWE-ID')
                    name = row.get('Name')
                    
                    if raw_id and name:
                        cwe_id_formatted = f"CWE-{raw_id}"

                        #query de INSERT
                        sql = """
                            INSERT INTO cwes (id, description)
                            VALUES (%s, %s)
                            ON CONFLICT (id) DO UPDATE SET
                                description = EXCLUDED.description;
                        """
                        cursor.execute(sql, (cwe_id_formatted, name))
                        count_updated += 1

                    if count_updated % 500 == 0:
                        conn.commit()
                        print(f"Processados: {count_updated}.", end='\r')

                conn.commit()
                print(f"\n\n--- Dicionário CWE Atualizado! ---")
                print(f"Total de registros processados: {count_updated}")

    except Exception as e:
        print(f"Erro fatal: {e}")
    finally:
        if conn: conn.close()


if __name__ == "__main__":
    fetch_and_load_cwes()