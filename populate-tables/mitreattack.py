# --- IMPORTS ---
import requests
import psycopg2
import os

# --- CONFIGURACOES DE API ---
# URL oficial do repositorio CTI do MITRE
MITRE_STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

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
def fetch_and_load_mitre():
    conn = get_connection()
    if not conn: return
    cursor = conn.cursor()

    print("--- Baixando base de dados do MITRE ATT&CK ---")
    
    try:
        response = requests.get(MITRE_STIX_URL)
        if response.status_code != 200:
            print(f"Erro ao baixar MITRE: {response.status_code}")
            return

        data = response.json()
        objects = data.get("objects", [])
        
        tactics_count = 0
        techniques_count = 0

        print("Processando objetos STIX...")

        for obj in objects:
            obj_type = obj.get("type")
            
            # O MITRE guarda o ID real dentro de uma lista de referências externas
            external_refs = obj.get("external_references", [])
            mitre_id = None
            url = None
            
            for ref in external_refs:
                if ref.get("source_name") == "mitre-attack":
                    mitre_id = ref.get("external_id")
                    url = ref.get("url")
                    break
            
            # nao adiciona se nao tem id
            if not mitre_id:
                continue

            name = obj.get("name")
            description = obj.get("description")

            # insert das taticas
            if obj_type == "x-mitre-tactic":
                sql = """
                    INSERT INTO mitre_tactics (id, name, description, url)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (id) DO UPDATE SET
                        name = EXCLUDED.name,
                        description = EXCLUDED.description,
                        url = EXCLUDED.url;
                """
                cursor.execute(sql, (mitre_id, name, description, url))
                tactics_count += 1

            # insert das tecnicas
            elif obj_type == "attack-pattern":
                sql = """
                    INSERT INTO mitre_techniques (id, name, description, url)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (id) DO UPDATE SET
                        name = EXCLUDED.name,
                        description = EXCLUDED.description,
                        url = EXCLUDED.url;
                """
                cursor.execute(sql, (mitre_id, name, description, url))
                techniques_count += 1

        conn.commit()
        print("\n--- MITRE ATT&CK Atualizado! ---")
        print(f"Táticas processadas: {tactics_count}")
        print(f"Técnicas processadas: {techniques_count}")

    except Exception as e:
        conn.rollback()
        print(f"Erro fatal ao processar MITRE: {e}")
    finally:
        if conn:
            cursor.close()
            conn.close()


if __name__ == "__main__":
    fetch_and_load_mitre()