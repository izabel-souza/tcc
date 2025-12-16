import requests
import psycopg2
import time
from math import ceil

# --- CONFIGURAÇÕES ---
EPSS_API_URL = "https://api.first.org/data/v1/epss"
BATCH_SIZE = 90  # Quantas CVEs perguntamos por vez (recomendado: 50-100)

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

def get_cves_from_db(conn):
    """Busca todas as CVEs que JÁ existem no seu banco"""
    cursor = conn.cursor()
    print("Lendo CVEs existentes no banco...")
    # Opcional: Adicionar "WHERE published_date >= '2020-01-01'" se quiser garantir
    cursor.execute("SELECT id FROM cves")
    # Retorna uma lista simples: ['CVE-2020-1234', 'CVE-2020-5678', ...]
    cves = [row[0] for row in cursor.fetchall()]
    cursor.close()
    return cves

def insert_epss_scores(conn, data_list):
    """Insere um lote de notas no banco"""
    cursor = conn.cursor()
    try:
        for item in data_list:
            cve_id = item.get("cve")
            epss_score = item.get("epss")
            percentile = item.get("percentile")

            sql = """
                INSERT INTO epss_scores (cve_id, epss_score, percentile)
                VALUES (%s, %s, %s)
                ON CONFLICT (cve_id) DO UPDATE SET
                    epss_score = EXCLUDED.epss_score,
                    percentile = EXCLUDED.percentile;
            """
            cursor.execute(sql, (cve_id, epss_score, percentile))
        
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"Erro ao salvar lote: {e}")
    finally:
        cursor.close()

def fetch_and_load_epss_api():
    conn = get_connection()
    if not conn: return

    # 1. Pega todas as suas CVEs
    all_cves = get_cves_from_db(conn)
    total_cves = len(all_cves)
    print(f"Total de CVEs no banco para consultar: {total_cves}")

    if total_cves == 0:
        print("Nenhuma CVE encontrada. Rode o script do NVD primeiro!")
        return

    # 2. Processa em Lotes (Chunks)
    # Loop de 0 até o total, pulando de 50 em 50
    for i in range(0, total_cves, BATCH_SIZE):
        batch = all_cves[i : i + BATCH_SIZE]
        
        # Transforma a lista em uma string separada por vírgulas
        # Ex: "CVE-2020-1234,CVE-2020-5678"
        cve_param = ",".join(batch)
        
        try:
            # Chama a API pedindo apenas essas 50
            params = {"cve": cve_param}
            response = requests.get(EPSS_API_URL, params=params)
            
            if response.status_code == 200:
                json_response = response.json()
                data = json_response.get("data", [])
                
                # Insere no banco
                if data:
                    insert_epss_scores(conn, data)
                
                print(f"Processado: {i + len(batch)}/{total_cves}...", end='\r')
            else:
                print(f"Erro API ({response.status_code}) no lote {i}")
            
            # Pequeno delay para ser gentil com a API da FIRST
            time.sleep(0.2)

        except Exception as e:
            print(f"Erro de conexão no lote {i}: {e}")
            time.sleep(5)

    print("\n--- Atualização EPSS via API Finalizada! ---")
    conn.close()

if __name__ == "__main__":
    fetch_and_load_epss_api()