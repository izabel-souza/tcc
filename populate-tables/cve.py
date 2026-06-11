# --- IMPORTS ---
import requests
import psycopg2
import time
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv

load_dotenv()

#data de inicio para pegar os dados
MODE = os.getenv("RUN_MODE", "incremental")
if MODE == "initial":
    START_DATE = datetime(2015, 1, 1)
    print(">>> MODO INICIAL: Coletando dados desde 2015.")
else:
    START_DATE = datetime.now() - timedelta(days=7)
    print(">>> MODO INCREMENTAL: Coletando atualizações dos últimos 7 dias.")

END_DATE = datetime.now()


# --- CONFIGURACOES DE API ---
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0" 
RESULTS_PER_PAGE = 2000
DELAY_SECONDS = 0.6

# --- CONFIGURACOES DO BANCO ---
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME", "vuln_db"),
    "user": os.getenv("DB_USER", "admin"),
    "password": os.getenv("DB_PASS", "admin_password"),
    "host": os.getenv("DB_HOST", "localhost"),
    "port": os.getenv("DB_PORT", "5432")
}

API_KEY = os.getenv("NVD_API_KEY")


#funcao de conexao com banco de dados 
def get_connection():
    try:
        return psycopg2.connect(**DB_CONFIG)
    except Exception as e:
        print(f"Erro de conexão: {e}")
        return None


def insert_cve_data(conn, cve_item):
    cursor = conn.cursor()
    cve_id = cve_item.get("id", "UNKNOWN")
    try:
        # Extração das datas
        published = cve_item.get("published")
        last_modified = cve_item.get("lastModified")

        # Extração das métricas simplificadas (Apenas Base Score e Severity)
        metrics_list = cve_item.get("metrics", {}).get("cvssMetricV31", [])
        base_score = None
        severity = None

        if metrics_list:
            metric_obj = metrics_list[0]
            cvss_data = metric_obj.get("cvssData", {})
            base_score = cvss_data.get("baseScore")
            severity = cvss_data.get("baseSeverity")
        
        # Query de INSERT baseada no novo schema
        sql_insert = """
            INSERT INTO cves (
                id, published_date, last_modified_date, cvss_base_score, cvss_base_severity
            ) VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET
                last_modified_date = EXCLUDED.last_modified_date,
                cvss_base_score = EXCLUDED.cvss_base_score,
                cvss_base_severity = EXCLUDED.cvss_base_severity;
        """
        cursor.execute(sql_insert, (
            cve_id, published, last_modified, base_score, severity
        ))

        # O mapeamento de CWEs foi mantido intacto conforme o novo schema
        cursor.execute("DELETE FROM cve_cwe_mapping WHERE cve_id = %s", (cve_id,))
        for weak in cve_item.get("weaknesses", []):
            for desc in weak.get("description", []):
                cwe_val = desc.get("value")
                if cwe_val and cwe_val.startswith("CWE"):
                    cursor.execute("INSERT INTO cwes (id) VALUES (%s) ON CONFLICT DO NOTHING", (cwe_val,))
                    cursor.execute("INSERT INTO cve_cwe_mapping (cve_id, cwe_id) VALUES (%s, %s) ON CONFLICT DO NOTHING", (cve_id, cwe_val))

        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"Erro ao processar {cve_id}: {e}")
    finally:
        cursor.close()


# Conecta no banco e chama a funcao de insert
def fetch_by_date_range():
    conn = get_connection()
    if not conn: return

    headers = {"apiKey": API_KEY} if API_KEY else {}
    current_start = START_DATE

    while current_start < END_DATE:
        current_end = current_start + timedelta(days=120)
        
        if current_end > END_DATE:
            current_end = END_DATE

        str_start = current_start.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
        str_end = current_end.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]

        print(f"\n>>> Buscando período: {str_start} até {str_end}")

        start_index = 0
        total_results = 1

        while start_index < total_results:
            params = {
                "resultsPerPage": RESULTS_PER_PAGE,
                "startIndex": start_index,
                "pubStartDate": str_start,
                "pubEndDate": str_end
            }

            try:
                response = requests.get(NVD_API_URL, params=params, headers=headers)
                
                if response.status_code == 200:
                    data = response.json()
                    total_results = data.get("totalResults", 0)
                    vulnerabilities = data.get("vulnerabilities", [])
                    
                    print(f"   - Página (Index {start_index}): Encontrados {len(vulnerabilities)} CVEs.")
                    
                    for item in vulnerabilities:
                        insert_cve_data(conn, item.get("cve", {}))
                    
                    start_index += RESULTS_PER_PAGE
            
                    print(f"   - Aguardando {DELAY_SECONDS}s.")
                    time.sleep(DELAY_SECONDS)
                
                else:
                    print(f"Erro API ({response.status_code}). Tentando novamente em 10s.")
                    time.sleep(10)
            
            except Exception as e:
                print(f"Erro de rede: {e}")
                time.sleep(10)

        current_start = current_end

    print("--- Carga CVE Finalizada ---")
    conn.close()

if __name__ == "__main__":
    fetch_by_date_range()