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


def get_english_description(cve_item):
    for item in cve_item.get("descriptions", []):
        if item.get("lang") == "en":
            return item.get("value")

    return None


def get_cve_tags(cve_item):
    tags = []
    for item in cve_item.get("cveTags", []):
        if isinstance(item, dict):
            tags.extend(item.get("tags", []))
        elif isinstance(item, str):
            tags.append(item)

    return tags


def get_preferred_cvss_metric(cve_item):
    metrics = cve_item.get("metrics", {})
    metric_sources = [
        ("cvssMetricV31", "CVSS v3.1"),
        ("cvssMetricV30", "CVSS v3.0"),
        ("cvssMetricV40", "CVSS v4.0"),
        ("cvssMetricV2", "CVSS v2.0"),
    ]

    for metric_key, version_label in metric_sources:
        metric_list = metrics.get(metric_key, [])
        if metric_list:
            return metric_list[0], version_label

    return {}, None


def extract_cvss_data(cve_item):
    metric_obj, version_label = get_preferred_cvss_metric(cve_item)
    cvss_data = metric_obj.get("cvssData", {})

    return {
        "metric_type": metric_obj.get("type"),
        "version": cvss_data.get("version") or version_label,
        "vector_string": cvss_data.get("vectorString"),
        "base_score": cvss_data.get("baseScore"),
        "base_severity": cvss_data.get("baseSeverity") or metric_obj.get("baseSeverity"),
        "attack_vector": cvss_data.get("attackVector") or cvss_data.get("accessVector"),
        "attack_complexity": cvss_data.get("attackComplexity") or cvss_data.get("accessComplexity"),
        "privileges_required": cvss_data.get("privilegesRequired") or cvss_data.get("authentication"),
        "user_interaction": cvss_data.get("userInteraction"),
        "scope": cvss_data.get("scope"),
        "confidentiality_impact": cvss_data.get("confidentialityImpact"),
        "integrity_impact": cvss_data.get("integrityImpact"),
        "availability_impact": cvss_data.get("availabilityImpact"),
        "exploitability_score": metric_obj.get("exploitabilityScore"),
        "impact_score": metric_obj.get("impactScore"),
    }


def insert_cve_data(conn, cve_item):
    cursor = conn.cursor()
    cve_id = cve_item.get("id", "UNKNOWN")
    try:
        # Extração das datas
        published = cve_item.get("published")
        last_modified = cve_item.get("lastModified")
        vuln_status = cve_item.get("vulnStatus")
        cve_tags = get_cve_tags(cve_item)
        description = get_english_description(cve_item)
        cvss = extract_cvss_data(cve_item)
        
        sql_insert = """
            INSERT INTO cves (
                id,
                published_date,
                last_modified_date,
                vuln_status,
                cve_tags,
                description,
                cvss_metric_type,
                cvss_version,
                cvss_vector_string,
                cvss_base_score,
                cvss_base_severity,
                cvss_attack_vector,
                cvss_attack_complexity,
                cvss_privileges_required,
                cvss_user_interaction,
                cvss_scope,
                cvss_confidentiality_impact,
                cvss_integrity_impact,
                cvss_availability_impact,
                cvss_exploitability_score,
                cvss_impact_score
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            )
            ON CONFLICT (id) DO UPDATE SET
                published_date = EXCLUDED.published_date,
                last_modified_date = EXCLUDED.last_modified_date,
                vuln_status = EXCLUDED.vuln_status,
                cve_tags = EXCLUDED.cve_tags,
                description = EXCLUDED.description,
                cvss_metric_type = EXCLUDED.cvss_metric_type,
                cvss_version = EXCLUDED.cvss_version,
                cvss_vector_string = EXCLUDED.cvss_vector_string,
                cvss_base_score = EXCLUDED.cvss_base_score,
                cvss_base_severity = EXCLUDED.cvss_base_severity,
                cvss_attack_vector = EXCLUDED.cvss_attack_vector,
                cvss_attack_complexity = EXCLUDED.cvss_attack_complexity,
                cvss_privileges_required = EXCLUDED.cvss_privileges_required,
                cvss_user_interaction = EXCLUDED.cvss_user_interaction,
                cvss_scope = EXCLUDED.cvss_scope,
                cvss_confidentiality_impact = EXCLUDED.cvss_confidentiality_impact,
                cvss_integrity_impact = EXCLUDED.cvss_integrity_impact,
                cvss_availability_impact = EXCLUDED.cvss_availability_impact,
                cvss_exploitability_score = EXCLUDED.cvss_exploitability_score,
                cvss_impact_score = EXCLUDED.cvss_impact_score;
        """
        cursor.execute(sql_insert, (
            cve_id,
            published,
            last_modified,
            vuln_status,
            cve_tags,
            description,
            cvss["metric_type"],
            cvss["version"],
            cvss["vector_string"],
            cvss["base_score"],
            cvss["base_severity"],
            cvss["attack_vector"],
            cvss["attack_complexity"],
            cvss["privileges_required"],
            cvss["user_interaction"],
            cvss["scope"],
            cvss["confidentiality_impact"],
            cvss["integrity_impact"],
            cvss["availability_impact"],
            cvss["exploitability_score"],
            cvss["impact_score"],
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
