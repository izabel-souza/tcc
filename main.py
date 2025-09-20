import pandas as pd

# --- ETAPA 1: Defina os nomes dos arquivos ---
arquivo_original = 'databases/epss_scores-2025-08-28.csv.gz' # Coloque o nome do seu arquivo aqui!
arquivo_novo_filtrado = 'databases/epss_scores-2010-2025.csv' # Nome do novo arquivo que será criado

try:
    # --- ETAPA 2: Carregar o arquivo original completo ---
    print(f"Carregando o arquivo grande: '{arquivo_original}'...")
    df = pd.read_csv(arquivo_original, comment='#')
    print("Arquivo original carregado com sucesso.")
    print(f"Total de CVEs encontradas: {len(df)}")

    # --- ETAPA 3: Filtrar os dados por ano ---
    print("\nIniciando a filtragem para manter apenas dados de 2010 em diante...")
    
    # Extrai o ano da coluna 'cve' e converte para número
    df['ano'] = pd.to_numeric(df['cve'].str.split('-').str[1])
    
    # Cria o novo DataFrame filtrado
    ano_de_corte = 2010
    df_filtrado = df[df['ano'] >= ano_de_corte].copy()
    
    # Remove a coluna 'ano' que criamos, pois ela não é necessária no arquivo final
    df_filtrado = df_filtrado.drop(columns=['ano'])
    
    print(f"Filtragem concluída. Total de CVEs de 2010 em diante: {len(df_filtrado)}")

    # --- ETAPA 4: Salvar o resultado em um novo arquivo CSV ---
    print(f"\nSalvando os dados filtrados em um novo arquivo: '{arquivo_novo_filtrado}'...")
    
    # O parâmetro 'index=False' impede que o pandas adicione uma coluna de índice desnecessária
    df_filtrado.to_csv(arquivo_novo_filtrado, index=False)
    
    print("\n--- SUCESSO! ---")
    print(f"O arquivo '{arquivo_novo_filtrado}' foi criado com sucesso na mesma pasta.")
    print("Ele contém apenas os dados a partir de 2010 e está pronto para sua análise.")

except FileNotFoundError:
    print(f"ERRO: O arquivo original '{arquivo_original}' não foi encontrado.")
    print("Verifique se o nome do arquivo está correto e se ele está na mesma pasta do script.")
except Exception as e:
    print(f"Ocorreu um erro inesperado durante o processo: {e}")