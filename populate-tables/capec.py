# --- IMPORTS ---
import requests
import psycopg2
import zipfile
import io
import os
import xml.etree.ElementTree as ET

# --- CONFIGURACOES DE API ---
# URL oficial do dicionário CAPEC da MITRE
CAPEC_URL = "https://capec.mitre.org/data/xml/views/1000.xml.zip"

# --- CONFIGURACOES DO BANCO ---
raw_pass = os.getenv("DB_PASS")
db_password = raw_pass if raw_pass else "admin_password"

DB_CONFIG = {
    "dbname": os.getenv("DB_NAME", "vuln_db"),
    "user": os.getenv("DB_USER", "admin"),
    "password": db_password,
    "host": os.getenv("DB_HOST", "127.0.0.1"),
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
def fetch_and_load_capec_mapping():
    conn = get_connection()
    if not conn: return
    cursor = conn.cursor()

    print(f"--- Baixando base do CAPEC ---")
    
    try:
        response = requests.get(CAPEC_URL)
        if response.status_code != 200:
            print(f"Erro ao baixar: {response.status_code}")
            return

        with zipfile.ZipFile(io.BytesIO(response.content)) as z:
            xml_filename = z.namelist()[0]
            print(f"Lendo e traduzindo arquivo XML: {xml_filename}")
            
            with z.open(xml_filename) as f:
                tree = ET.parse(f)
                root = tree.getroot()

                # remove namespaces para facilitar a busca
                for elem in root.iter():
                    if '}' in elem.tag:
                        elem.tag = elem.tag.split('}', 1)[1]

                count_mappings = 0
                print("Extraindo cruzamentos CWE <-> MITRE ATT&CK...")

                # para cada CAPEC
                for ap in root.findall('.//Attack_Pattern'):
                    
                    # pega as fraquezas (CWE) ligadas ao ataque
                    cwes = []
                    for rw in ap.findall('.//Related_Weakness'):
                        cwe_id = rw.get('CWE_ID')
                        if cwe_id:
                            cwes.append(f"CWE-{cwe_id}")
                            
                    # pega as tecnicas do MITRE ATT&CK usadas neste ataque
                    mitre_techs = []
                    for tm in ap.findall('.//Taxonomy_Mapping'):
                        if tm.get('Taxonomy_Name') == 'ATTACK':
                            entry = tm.find('Entry_ID')
                            if entry is not None and entry.text:
                                mitre_techs.append(entry.text)
                                
                    # se o ataque liga uma CWE a uma tecnica do MITRE, insert no banco
                    for cwe in cwes:
                        for tech in mitre_techs:
                            sql = """
                                INSERT INTO cwe_mitre_mapping (cwe_id, mitre_id)
                                VALUES (%s, %s)
                                ON CONFLICT DO NOTHING;
                            """
                            cursor.execute(sql, (cwe, tech))
                            count_mappings += 1

                conn.commit()
                print(f"\n--- Sucesso! ---")
                print(f"Total de cruzamentos CWE <-> MITRE inseridos: {count_mappings}")

    except Exception as e:
        print(f"Erro fatal ao processar XML: {e}")
    finally:
        if conn: cursor.close(); conn.close()


if __name__ == "__main__":
    fetch_and_load_capec_mapping()