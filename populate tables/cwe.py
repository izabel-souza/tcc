import requests
import psycopg2
import zipfile
import io
import csv

# --- CONFIGURAÇÕES ---
# URL oficial da MITRE com a lista completa de CWEs (CSV zipado)
MITRE_CWE_URL = "https://cwe.mitre.org/data/csv/2000.csv.zip"

def get_connection():
    try:
        conn = psycopg2.connect(
            dbname="vuln_db", user="admin", password="admin_password",
            host="localhost", port="5432"
        )
        return conn
    except Exception as e:
        print(f"Erro de conexão: {e}")
        return None

def fetch_and_load_cwes():
    conn = get_connection()
    if not conn: return

    print(f"--- Baixando Dicionário CWE da MITRE ---")
    
    try:
        # 1. Download do ZIP
        response = requests.get(MITRE_CWE_URL)
        if response.status_code != 200:
            print(f"Erro ao baixar: {response.status_code}")
            return

        # 2. Abrir ZIP em memória
        with zipfile.ZipFile(io.BytesIO(response.content)) as z:
            # O ZIP contém um arquivo CSV (ex: 2000.csv)
            csv_filename = z.namelist()[0]
            print(f"Lendo arquivo interno: {csv_filename}")
            
            with z.open(csv_filename) as f:
                # Wrapper para ler bytes como texto (utf-8)
                text_file = io.TextIOWrapper(f, encoding='utf-8', errors='replace')
                
                # O CSV da MITRE tem um cabeçalho antes dos dados reais? 
                # Geralmente começa direto com headers: "CWE-ID","Name",...
                reader = csv.DictReader(text_file)
                
                cursor = conn.cursor()
                count_updated = 0
                
                print("Atualizando descrições no banco...")

                for row in reader:
                    # O CSV traz o ID apenas como número (ex: 79)
                    # Seu banco usa o formato NVD (ex: CWE-79)
                    raw_id = row.get('CWE-ID')
                    name = row.get('Name')
                    
                    if raw_id and name:
                        cwe_id_formatted = f"CWE-{raw_id}"
                        
                        # Query de UPSERT
                        # Se o ID já existe (inserido pelo NVD), atualizamos a descrição.
                        # Se não existe, inserimos novo.
                        sql = """
                            INSERT INTO cwes (id, description)
                            VALUES (%s, %s)
                            ON CONFLICT (id) DO UPDATE SET
                                description = EXCLUDED.description;
                        """
                        cursor.execute(sql, (cwe_id_formatted, name))
                        count_updated += 1

                    if count_updated % 500 == 0:
                        conn.commit() # Commit parcial
                        print(f"Processados: {count_updated}...", end='\r')

                conn.commit() # Commit final
                print(f"\n\n--- Dicionário CWE Atualizado! ---")
                print(f"Total de registros processados: {count_updated}")

    except Exception as e:
        print(f"Erro fatal: {e}")
    finally:
        if conn: conn.close()

if __name__ == "__main__":
    fetch_and_load_cwes()