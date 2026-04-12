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


#funcao de insert no banco
def insert_cve_data(conn, cve_item):
    cursor = conn.cursor()
    cve_id = cve_item.get("id", "UNKNOWN")
    try:
        published = cve_item.get("published")
        last_modified = cve_item.get("lastModified")
        vuln_status = cve_item.get("vulnStatus")
        
        tags_list = []
        raw_tags = cve_item.get("cveTags", [])
        for t in raw_tags:
            if isinstance(t, dict): tags_list.extend(t.get("tags", []))
        
        descriptions = cve_item.get("descriptions", [])
        description_text = next((d['value'] for d in descriptions if d['lang'] == 'en'), None)
        if not description_text and descriptions: description_text = descriptions[0].get("value")

        metrics_list = cve_item.get("metrics", {}).get("cvssMetricV31", [])
        (cvss_type, version, vector, base_score, severity, attack_vector, 
         attack_complexity, privileges, user_interaction, scope, 
         conf_impact, integ_impact, avail_impact, exploitability, impact_score) = (None,) * 15

        if metrics_list:
            metric_obj = metrics_list[0]
            cvss_data = metric_obj.get("cvssData", {})
            cvss_type = metric_obj.get("type")
            exploitability = metric_obj.get("exploitabilityScore")
            impact_score = metric_obj.get("impactScore")
            version = cvss_data.get("version")
            vector = cvss_data.get("vectorString")
            base_score = cvss_data.get("baseScore")
            severity = cvss_data.get("baseSeverity")
            attack_vector = cvss_data.get("attackVector")
            attack_complexity = cvss_data.get("attackComplexity")
            privileges = cvss_data.get("privilegesRequired")
            user_interaction = cvss_data.get("userInteraction")
            scope = cvss_data.get("scope")
            conf_impact = cvss_data.get("confidentialityImpact")
            integ_impact = cvss_data.get("integrityImpact")
            avail_impact = cvss_data.get("availabilityImpact")
        
        #query de INSERT
        sql_insert = """
            INSERT INTO cves (
                id, published_date, last_modified_date, vuln_status, description, cve_tags,
                cvss_metric_type, cvss_version, cvss_vector_string, cvss_base_score, cvss_base_severity,
                cvss_attack_vector, cvss_attack_complexity, cvss_privileges_required, 
                cvss_user_interaction, cvss_scope, cvss_confidentiality_impact, 
                cvss_integrity_impact, cvss_availability_impact, 
                cvss_exploitability_score, cvss_impact_score
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET
                vuln_status = EXCLUDED.vuln_status,
                last_modified_date = EXCLUDED.last_modified_date,
                cvss_base_score = EXCLUDED.cvss_base_score,
                cvss_base_severity = EXCLUDED.cvss_base_severity;
        """
        cursor.execute(sql_insert, (
            cve_id, published, last_modified, vuln_status, description_text, tags_list,
            cvss_type, version, vector, base_score, severity,
            attack_vector, attack_complexity, privileges, user_interaction, scope,
            conf_impact, integ_impact, avail_impact, exploitability, impact_score
        ))

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


#conecta no banco e chama a funcao de insert
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