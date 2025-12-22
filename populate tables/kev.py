import requests
import psycopg2
from datetime import datetime

#configuracoes de API
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
START_DATE_FILTER = datetime(2020, 1, 1).date()

#funcao de conexao com banco de dados 
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

def insert_kev_data(conn, item):
    cursor = conn.cursor()
    cve_id = item.get("cveID")

    try:
        vendor_project = item.get("vendorProject")
        product = item.get("product")
        vulnerability_name = item.get("vulnerabilityName")
        date_added_str = item.get("dateAdded")
        date_added = datetime.strptime(date_added_str, "%Y-%m-%d").date()
        short_description = item.get("shortDescription")
        required_action = item.get("requiredAction")
        due_date_str = item.get("dueDate")
        due_date = None
        if due_date_str:
            due_date = datetime.strptime(due_date_str, "%Y-%m-%d").date()

        ransom_status_str = item.get("knownRansomwareCampaignUse", "Unknown")
        known_ransomware = True if ransom_status_str == "Known" else False

        if date_added < START_DATE_FILTER:
            return 

        #query de INSERT
        sql = """
            INSERT INTO kev (
                cve_id, vendor_project, product, vulnerability_name, 
                date_added, short_description, required_action, 
                due_date, known_ransomware_usage
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (cve_id) DO UPDATE SET
                known_ransomware_usage = EXCLUDED.known_ransomware_usage,
                required_action = EXCLUDED.required_action,
                due_date = EXCLUDED.due_date;
        """

        cursor.execute(sql, (
            cve_id, vendor_project, product, vulnerability_name,
            date_added, short_description, required_action,
            due_date, known_ransomware
        ))
        
        conn.commit()

    except psycopg2.errors.ForeignKeyViolation:
        conn.rollback()
        print(f"AVISO: CVE {cve_id} existe no KEV mas NÃO está na tabela 'cves'. Ignorado.")
    except Exception as e:
        conn.rollback()
        print(f"Erro ao inserir KEV {cve_id}: {e}")
    finally:
        cursor.close()
        
#conecta no banco e chama a funcao de insert 
def fetch_and_load_kev():
    conn = get_connection()
    if not conn: return

    print(f"--- Baixando catálogo KEV da CISA ---")
    
    try:
        response = requests.get(CISA_KEV_URL)
        if response.status_code != 200:
            print(f"Erro ao baixar arquivo: {response.status_code}")
            return

        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        
        total = len(vulnerabilities)
        print(f"Catálogo baixado. Total de itens: {total}. Filtrando e inserindo...")

        count_inserted = 0
        for item in vulnerabilities:
            insert_kev_data(conn, item)
            count_inserted += 1

            if count_inserted % 100 == 0:
                print(f"Processados: {count_inserted}/{total}...")

        print("--- Carga KEV Finalizada ---")

    except Exception as e:
        print(f"Erro Geral: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    fetch_and_load_kev()