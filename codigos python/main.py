import requests
import pandas as pd
import time
import os
# A importação de 'timezone' é a novidade aqui
from datetime import datetime, timedelta, timezone

# --- CONFIGURAÇÃO ---

# URL base da API 2.0 do NVD
BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# (Opcional) Pegue sua API Key de uma variável de ambiente para mais segurança
API_KEY = os.getenv("ed842ef3-5acf-4f2b-aca1-16d14c6fb4f3") 

# Quantos resultados buscar por página (máximo é 2000)
RESULTS_PER_PAGE = 2000

def extrair_cves(start_date, end_date):
    """
    Busca todas as CVEs publicadas em um determinado período de tempo.

    Args:
        start_date (datetime): A data de início para a busca.
        end_date (datetime): A data de fim para a busca.

    Returns:
        list: Uma lista de dicionários, onde cada dicionário representa uma CVE.
    """
    
    headers = {}
    if API_KEY:
        headers['apiKey'] = API_KEY
        print("Usando API Key para requisições.")
        REQUEST_DELAY = 0.6 
    else:
        print("AVISO: Nenhuma API Key encontrada. As requisições serão mais lentas.")
        REQUEST_DELAY = 6.0

    cves_encontradas = []
    start_index = 0
    
    # Formata as datas para o formato exigido pela API
    pub_start_date_str = start_date.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
    pub_end_date_str = end_date.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

    while True:
        params = {
            'resultsPerPage': RESULTS_PER_PAGE,
            'startIndex': start_index,
            'pubStartDate': pub_start_date_str,
            'pubEndDate': pub_end_date_str
        }

        try:
            print(f"Buscando resultados a partir do índice {start_index}...")
            response = requests.get(BASE_URL, headers=headers, params=params, timeout=30)
            response.raise_for_status()

            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])

            if not vulnerabilities:
                print("Nenhuma vulnerabilidade encontrada nesta página. Concluindo.")
                break

            for item in vulnerabilities:
                cve = item.get('cve', {})
                cve_id = cve.get('id')
                published_date = cve.get('published')
                last_modified_date = cve.get('lastModified')
                
                description = ""
                for desc in cve.get('descriptions', []):
                    if desc.get('lang') == 'en':
                        description = desc.get('value')
                        break
                
                base_score = None
                severity = None
                metrics = cve.get('metrics', {})
                if 'cvssMetricV31' in metrics:
                    cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
                    base_score = cvss_data.get('baseScore')
                    severity = cvss_data.get('baseSeverity')

                cves_encontradas.append({
                    'ID': cve_id,
                    'Publicado': published_date,
                    'Modificado': last_modified_date,
                    'Score': base_score,
                    'Severidade': severity,
                    'Descricao': description
                })

            total_results = data.get('totalResults', 0)
            start_index += len(vulnerabilities)

            if start_index >= total_results:
                print("Todos os resultados foram extraídos.")
                break
            
            time.sleep(REQUEST_DELAY)

        except requests.exceptions.RequestException as e:
            print(f"Erro na requisição: {e}")
            break
            
    return cves_encontradas

if __name__ == "__main__":
    # Define o período de busca: dos últimos 30 dias até agora
    # ATUALIZAÇÃO: Usando datetime.now(timezone.utc) em vez de utcnow()
    data_final = datetime.now(timezone.utc)
    data_inicial = data_final - timedelta(days=30)
    
    print(f"Iniciando extração de CVEs de {data_inicial.date()} até {data_final.date()}")
    
    lista_de_cves = extrair_cves(data_inicial, data_final)
    
    if lista_de_cves:
        df_cves = pd.DataFrame(lista_de_cves)
        nome_arquivo = f"cves_{data_inicial.date()}_a_{data_final.date()}.csv"
        df_cves.to_csv(nome_arquivo, index=False, encoding='utf-8-sig')
        
        print("\n--- Extração Concluída ---")
        print(f"{len(df_cves)} CVEs foram salvas no arquivo '{nome_arquivo}'")
        print("\nPré-visualização dos dados:")
        print(df_cves.head())
    else:
        print("\nNenhuma CVE foi encontrada no período especificado.")