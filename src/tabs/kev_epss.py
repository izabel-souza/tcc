# --- IMPORTS ---
import streamlit as st
import plotly.express as px
from src.utils.database import get_data
from src.utils.components import apply_chart_layout, render_ransomware_icon

#FUNCAO COM OS GRAFICOS
def render_risk_tab(filtro_sql, filtro_estatistico_alias):
    def add_section_spacing():
        st.markdown('<div style="height: 1.2rem;"></div>', unsafe_allow_html=True)

    st.subheader("Inteligência de Ameaças e Priorização")
    
    # QUERY DO PERCENTUAL DE RANSOMWARE
    query_ransom_pct = f"""
        SELECT(
            COUNT(
                CASE WHEN k.known_ransomware_usage THEN 1 END
            ) * 100.0 / NULLIF(COUNT(*), 0)
        ) as porcentagem
        FROM kev k 
        JOIN cves c ON k.cve_id = c.id
        WHERE {filtro_sql}
    """
    df_ransom_pct = get_data(query_ransom_pct)
    valor_ransomware = df_ransom_pct['porcentagem'].iloc[0] if not df_ransom_pct.empty else 0

    #RENDERIZA ICONE
    st.markdown('<div style="height: 0.8rem;"></div>', unsafe_allow_html=True)
    render_ransomware_icon(valor_ransomware)
    
    add_section_spacing()

    col_k1, col_k2 = st.columns(2)

    # RANKING DOS TOP VENDORS (EMPRESAS) COM MAIS VULNERABILIDADES EXPLORADAS COM LOGOS E BARRAS CUSTOMIZADAS
    with col_k1:
        with st.container(border=True):
            st.subheader("Top 10 Empresas com Exploração Ativa")
            
            vendor_q = f"""
                SELECT 
                    k.vendor_project as vendor, 
                    COUNT(k.cve_id) as qtd 
                FROM kev k 
                JOIN cves c ON k.cve_id = c.id 
                WHERE {filtro_sql} 
                GROUP BY 1 ORDER BY 2 DESC LIMIT 10
            """

            df_v = get_data(vendor_q)
            
            if not df_v.empty:
                max_qtd = df_v['qtd'].max()
                
                for _, row in df_v.iterrows():
                    vendor_name = row['vendor'].lower()
                    qtd = row['qtd']
                    largura_barra = (qtd / max_qtd) * 100
                    
                    # Logo: Google Favicons
                    logo_url = f"https://www.google.com/s2/favicons?domain={vendor_name}.com&sz=128"
                    
                    st.markdown(f"""
                    <div style="display: flex; align-items: center; margin-bottom: 12px; height: 50px;">
                        <div style="width: 40px; display: flex; justify-content: center; margin-right: 15px;">
                            <img src="{logo_url}" width="30" style="border-radius: 4px; filter: drop-shadow(0px 0px 2px rgba(255,255,255,0.2));">
                        </div>
                        <div style="flex-grow: 1;">
                            <div style="display: flex; justify-content: space-between; margin-bottom: 4px;">
                                <span style="font-size: 14px; font-weight: 600; color: #F9FAFB;">{row['vendor'].capitalize()}</span>
                                <span style="font-size: 12px; color: white;">{qtd:,} CVEs</span>
                            </div>
                            <div style="background-color: #374151; border-radius: 10px; height: 8px; width: 100%;">
                                <div style="background-color: #1f77b4; width: {largura_barra}%; height: 100%; border-radius: 10px; transition: width 0.6s ease-in-out;"></div>
                            </div>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)


    # RANKING DOS TOP PRODUTOS COM MAIS VULNERABILIDADES EXPLORADAS COM LOGOS DE SUA RESPECTIVA EMPRESA E BARRAS CUSTOMIZADAS
    with col_k2:
        with st.container(border=True):
            st.subheader("Top 10 Produtos com Exploração Ativa")

            # QUERY
            prod_q = f"""
                SELECT 
                    k.vendor_project,
                    k.product as produto, 
                    COUNT(k.cve_id) as qtd 
                FROM kev k 
                JOIN cves c ON k.cve_id = c.id 
                WHERE {filtro_sql} 
                GROUP BY 1, 2 
                ORDER BY 3 
                DESC LIMIT 10
            """
            df_p = get_data(prod_q)

            if not df_p.empty:
                max_p = df_p['qtd'].max()
                
                for _, row in df_p.iterrows():
                    largura = (row['qtd'] / max_p) * 100
                    #logo do FABRICANTE para representar o PRODUTO
                    vendor_nome = row['vendor_project'].lower()
                    logo_url = f"https://www.google.com/s2/favicons?domain={vendor_nome}.com&sz=128"
                    
                    st.markdown(f"""
                    <div style="display: flex; align-items: center; margin-bottom: 12px; height: 50px;">
                        <div style="width: 40px; margin-right: 15px; display: flex; justify-content: center;">
                            <img src="{logo_url}" width="30" style="border-radius: 4px; filter: drop-shadow(0px 0px 2px rgba(255,255,255,0.2));">
                        </div>
                        <div style="flex-grow: 1;">
                            <div style="display: flex; justify-content: space-between; margin-bottom: 4px;">
                                <span style="font-size: 14px; font-weight: 600; color: #F9FAFB;">{row['produto']}</span>
                                <span style="font-size: 12px; color: white;">{row['qtd']} CVEs</span>
                            </div>
                            <div style="background-color: #374151; border-radius: 10px; height: 8px; width: 100%;">
                                <div style="background-color: #1f77b4; width: {largura}%; height: 100%; border-radius: 10px; transition: width 0.8s ease-in-out;"></div>
                            </div>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
            
    add_section_spacing()

    # ==============================================================================
    # CASO DE USO 1: PRIORIZAÇÃO DE CORREÇÃO DE VULNERABILIDADES
    # ==============================================================================
    with st.container(border=True): # envolve o gráfico no card
        st.subheader("Priorização de Correção de Vulnerabilidades")

        with st.expander("Guia de análise:"):
            st.markdown("""
                ### Objetivo: priorizar vulnerabilidades pelo risco observado.
                        
                Nem toda vulnerabilidade crítica representa a mesma urgência operacional. Este gráfico cruza a severidade técnica da CVE com a probabilidade de exploração estimada pelo EPSS e a presença no catálogo CISA KEV, ajudando a identificar quais falhas exigem resposta mais rápida.

                * **Eixo X (CVSS):** severidade técnica da vulnerabilidade.
                * **Eixo Y (EPSS):** probabilidade estimada de exploração.
                * **Cor:** categoria de prioridade calculada a partir de CVSS, EPSS e KEV.
                * **Símbolo:** indica se a CVE está presente no catálogo KEV.

                #### Como interpretar:
                1. **Prioridade máxima:** vulnerabilidades presentes no KEV e com alta severidade ou probabilidade relevante de exploração.
                2. **Risco subestimado:** vulnerabilidades presentes no KEV, mas que podem não parecer críticas apenas por CVSS ou EPSS.
                3. **Atenção:** vulnerabilidades fora do KEV, mas com CVSS alto ou EPSS relevante.
                4. **Monitoramento:** vulnerabilidades fora do KEV com menor severidade e menor probabilidade estimada de exploração.
            """)

        #QUERY
        query_prioridade = f"""
            WITH vulnerabilidades_classificadas AS (
                SELECT
                    c.id,
                    c.cvss_base_score,
                    c.cvss_base_severity,
                    e.epss_score,
                    CASE
                        WHEN k.cve_id IS NOT NULL THEN TRUE
                        ELSE FALSE
                    END as is_kev,
                    CASE
                        WHEN k.cve_id IS NOT NULL AND
                        (c.cvss_base_score >= 7.0 OR e.epss_score >= 0.1) THEN 'Prioridade máxima'
                        WHEN k.cve_id IS NOT NULL THEN 'Risco subestimado'
                        WHEN c.cvss_base_score >= 7.0 OR e.epss_score >= 0.1 THEN 'Atenção'
                        ELSE 'Monitoramento'
                    END as categoria_prioridade
                FROM cves c
                JOIN epss_scores e ON c.id = e.cve_id
                LEFT JOIN kev k ON c.id = k.cve_id
                WHERE {filtro_sql}
            ),
            amostra_balanceada AS (
                SELECT
                    *,
                    ROW_NUMBER() OVER (
                        PARTITION BY categoria_prioridade
                        ORDER BY is_kev DESC, e.epss_score DESC, cvss_base_score DESC
                    ) as posicao_categoria
                FROM vulnerabilidades_classificadas e
            )
            SELECT
                id,
                cvss_base_score,
                cvss_base_severity,
                epss_score,
                is_kev,
                categoria_prioridade
            FROM amostra_balanceada
            WHERE posicao_categoria <= 1250
            ORDER BY 
                is_kev DESC, 
                epss_score DESC, 
                cvss_base_score DESC
        """
        df_prioridade = get_data(query_prioridade)

        if not df_prioridade.empty:
            fig_scatter = px.scatter(
                df_prioridade,
                x='cvss_base_score',
                y='epss_score',
                color='categoria_prioridade',
                symbol='is_kev',
                hover_data=['id', 'cvss_base_severity'],
                labels={
                    'cvss_base_score': 'Severidade técnica (CVSS)',
                    'epss_score': 'Probabilidade de exploração - EPSS (0-1)',
                    'categoria_prioridade': 'Classificação de risco',
                    'is_kev': 'No KEV'
                },
                color_discrete_map={
                    'Prioridade máxima': 'darkred',
                    'Risco subestimado': 'orange',
                    'Atenção': 'yellow',
                    'Monitoramento': 'gray'
                },
                title="Relação entre CVSS, EPSS e KEV")

            # linhas de quadrante para facilitar a leitura
            fig_scatter.add_hline(
                y=0.5,
                line_dash="dot",
                line_color="red",
                annotation_text="Alta probabilidade (EPSS > 0.5)")
            fig_scatter.add_vline(x=7.0,
                                line_dash="dot",
                                line_color="orange",
                                annotation_text="Alta severidade (CVSS > 7.0)")
            
            # AJUSTE DE TRANSPARÊNCIA PARA O CARD
            fig_scatter.update_layout(
                legend_itemclick="toggleothers",
                xaxis=dict(dtick=1)
            )
            apply_chart_layout(fig_scatter, margin=dict(l=75, r=55, t=70, b=75))

            st.plotly_chart(fig_scatter, width='stretch', key=f"scatter_prioridade_{filtro_sql}")

    add_section_spacing()

    # ==============================================================================
    # CASO DE USO 4: PERFIL DAS VULNERABILIDADES EXPLORADAS EM CAMPANHAS REAIS (KEV VS. GERAL)
    # ==============================================================================
    with st.container(border=True):
        st.subheader("Perfil das Vulnerabilidades Exploradas")
        st.write("Comparativo de médias: severidade técnica vs. probabilidade real")

        with st.expander("Guia de análise:"):
            st.markdown("""
                ### Objetivo: Comparar risco técnico e risco observado
                Esta análise compara vulnerabilidades presentes no catálogo KEV com o restante da base para verificar se falhas exploradas ativamente apresentam um perfil diferente.

                #### Como interpretar:
                1. **CVSS médio:** mostra se as vulnerabilidades exploradas tendem a ter maior severidade técnica.
                2. **EPSS médio:** mostra se as vulnerabilidades exploradas também têm maior probabilidade estimada de exploração.
                3. **Diferença entre os grupos:** quanto maior a distância entre KEV e base geral, mais forte é o indício de que a exploração real não depende apenas da severidade CVSS.

                #### Leitura prática:
                Se o EPSS médio das vulnerabilidades no KEV for muito superior ao restante da base, isso indica que priorizar correções combinando KEV e EPSS é mais eficiente do que ordenar vulnerabilidades apenas pelo CVSS.
            """)

        q_perfil_estatistico = f"""
            SELECT 
                CASE 
                    WHEN k.cve_id IS NOT NULL THEN 'No catálogo KEV' 
                    ELSE 'Fora do catálogo KEV' 
                END as status_exploracao,
                ROUND(AVG(c.cvss_base_score)::numeric, 2) as media_score_cvss,
                ROUND(AVG(e.epss_score)::numeric, 4) as media_probabilidade_epss
            FROM cves c
            LEFT JOIN kev k ON c.id = k.cve_id
            LEFT JOIN epss_scores e ON c.id = e.cve_id
            WHERE {filtro_sql}
            GROUP BY 1
        """

        df_perfil = get_data(q_perfil_estatistico)

        if not df_perfil.empty:
            col_est1, col_est2 = st.columns(2)

            # GRAFICO DE BARRAS 1 - Diferença de Severidade Média (CVSS)
            with col_est1:
                fig_cvss_comp = px.bar(
                    df_perfil,
                    x='status_exploracao',
                    y='media_score_cvss',
                    labels={
                        'media_score_cvss': 'Média do score CVSS', 
                        'status_exploracao': 'Grupo de análise'
                    },
                    title="Severidade Média: KEV vs. Base Geral",
                    color='status_exploracao',
                    color_discrete_sequence=['#1f77b4', '#8b0000']
                )

                # AJUSTE DE TRANSPARÊNCIA PARA O CARD
                fig_cvss_comp.update_layout(
                    legend_itemclick="toggleothers"
                )
                apply_chart_layout(fig_cvss_comp)
            
                st.plotly_chart(fig_cvss_comp, width='stretch', key=f"cvss_perfil_{filtro_sql}")

            # GRAFICO DE BARRAS 2 - Diferença de Probabilidade Média (EPSS)
            with col_est2:
                fig_epss_comp = px.bar(
                    df_perfil,
                    x='status_exploracao',
                    y='media_probabilidade_epss',
                    labels={
                        'media_probabilidade_epss': 'Média de probabilidade EPSS',
                        'status_exploracao': 'Grupo de análise'
                    },
                    title="Probabilidade Média de Exploração: KEV vs. Base Geral",
                    color='status_exploracao',
                    color_discrete_sequence=['#1f77b4', '#8b0000'])
                
                # AJUSTE DE TRANSPARÊNCIA PARA O CARD
                fig_epss_comp.update_layout(
                    legend_itemclick="toggleothers",
                    yaxis_tickformat=".0%"
                )
                apply_chart_layout(fig_epss_comp)
            
                st.plotly_chart(fig_epss_comp, width='stretch', key=f"epss_perfil_{filtro_sql}")

    add_section_spacing()

    with st.container(border=True):
        # Comparação de Tipos de Fraqueza (CWE) - Top 5 de cada grupo
        st.subheader("Comparativo de Fraquezas (CWE): KEV vs. Geral")
        st.write("Perfil das vulnerabilidades que efetivamente viram problema no mundo real.")

        with st.expander("Guia de análise:"):
            st.markdown("""
            ### Objetivo: 
            Comparar o perfil das vulnerabilidades que entraram no catálogo KEV contra o restante da base de dados, validando a hipótese de que vulnerabilidades exploradas apresentam padrões distintos de severidade e probabilidade.

            *  **Perfil de fraquezas (CWE):** Compara os tipos de erros de programação. Certas falhas (como injeção de código) aparecem com mais frequência no KEV do que na base geral, indicando que são os métodos preferidos para invasões.

            #### Interpretação das cores:
            - **Vermelho (no catálogo KEV):** O perfil das ameaças concretas e confirmadas pela CISA.
            - **Azul (fora do catálogo):** O perfil do "ruído de fundo" da segurança (vulnerabilidades teóricas que ainda não foram ou não serão exploradas).
            """)

        # QUERY
        q_cwe_perfil = f"""
            (
                SELECT 
                    'No catálogo KEV' as grupo,
                    cw.id as identificador_fraqueza,
                    COUNT(c.id) as quantidade_vulnerabilidades
                FROM cves c
                JOIN kev k ON c.id = k.cve_id
                JOIN cve_cwe_mapping m ON c.id = m.cve_id
                JOIN cwes cw ON m.cwe_id = cw.id
                WHERE {filtro_estatistico_alias}
                GROUP BY 2 
                ORDER BY 3 
                DESC LIMIT 5
            )
            UNION ALL
            (
                SELECT 
                    'Fora do catálogo KEV' as grupo,
                    cw.id as identificador_fraqueza,
                    COUNT(c.id) as quantidade_vulnerabilidades
                FROM cves c
                LEFT JOIN kev k ON c.id = k.cve_id
                JOIN cve_cwe_mapping m ON c.id = m.cve_id
                JOIN cwes cw ON m.cwe_id = cw.id
                WHERE k.cve_id IS NULL AND {filtro_estatistico_alias}
                GROUP BY 2 
                ORDER BY 3 
                DESC LIMIT 5
            )
        """

        df_cwe_perfil = get_data(q_cwe_perfil)

        if not df_cwe_perfil.empty:
            fig_cwe_perfil = px.bar(
                df_cwe_perfil,
                x='identificador_fraqueza',
                y='quantidade_vulnerabilidades',
                color='grupo',
                barmode='group',
                labels={
                    'identificador_fraqueza': 'Tipo de fraqueza (CWE)',
                    'quantidade_vulnerabilidades': 'Quantidade de CVEs'
                },
                title="Top 5 Fraquezas em cada Grupo (KEV vs. Restante da Base)",
                color_discrete_map={
                    'No catálogo KEV': '#8b0000',
                    'Fora do catálogo KEV': '#1f77b4'
                })
            
            # AJUSTE DE TRANSPARÊNCIA PARA O CARD
            fig_cwe_perfil.update_layout(
                legend_itemclick="toggleothers"
            )
            apply_chart_layout(fig_cwe_perfil)

            st.plotly_chart(fig_cwe_perfil,
                            width='stretch',
                            key=f"cwe_perfil_bar_{filtro_estatistico_alias}")

    add_section_spacing()

    # ==============================================================================
    # CASO DE USO 5: TENDÊNCIA TEMPORAL DA EXPLORAÇÃO (VOLUME VS. RISCO)
    # ==============================================================================
    q_tendencia_temporal = f"""
        SELECT 
            EXTRACT(YEAR FROM c.published_date) as ano_publicacao,
            COUNT(c.id) as quantidade_total_cves,
            COUNT(CASE WHEN c.cvss_base_severity = 'CRITICAL' THEN 1 END) as quantidade_criticas,
            COUNT(k.cve_id) as quantidade_exploradas_kev,
            ROUND(AVG(e.epss_score)::numeric, 4) as media_probabilidade_epss
        FROM cves c
        LEFT JOIN kev k ON c.id = k.cve_id
        LEFT JOIN epss_scores e ON c.id = e.cve_id
        WHERE {filtro_estatistico_alias}
        GROUP BY 1
        ORDER BY 1
    """

    df_tendencia = get_data(q_tendencia_temporal)

    with st.container(border=True):
        st.subheader("Tendência Temporal: O Volume Implica em Mais Risco?")

        st.markdown("""Esta análise investiga se o crescimento anual no registro de vulnerabilidades reflete um aumento real na superfície de exploração ou se representa uma inflação de registros de baixo risco operacional.""")

        with st.expander("Guia de análise:"):
            st.markdown("""
                ### Objetivo: Volume de falhas vs. Risco real
                Este caso de uso investiga a relação entre a quantidade massiva de registros anuais e a periculosidade real observada no histórico de ataques.

                #### Como interpretar os gráficos:
                *  **Volume Total vs. KEV:** Observe a diferença entre a linha azul (Total de CVEs) e a linha vermelha (KEV). Se a linha azul sobe rapidamente, mas a vermelha permanece estável, isso sugere que estamos descobrindo mais falhas "irrelevantes" ou teóricas do que novas ameaças práticas.

                #### A conclusão prática:
                Esta visualização sustenta a hipótese de que o **aumento na superfície de detecção não é sinônimo de aumento na superfície de ataque**. Para as equipes de segurança, isso destrói o mito de que é preciso corrigir tudo. A estratégia moderna não é tentar zerar a fila de vulnerabilidades, mas usar inteligência para atacar cirurgicamente apenas as falhas que os criminosos realmente usam.
            """)

        # Grafico 1: Comparativo de Volume (Total vs. Criticas vs. KEV)
        if not df_tendencia.empty:
            fig_vol_evolucao = px.line(
                df_tendencia,
                x='ano_publicacao',
                y=['quantidade_total_cves', 'quantidade_criticas', 'quantidade_exploradas_kev'],
                labels={
                    'ano_publicacao': 'Ano de publicação',
                    'value': 'Quantidade de vulnerabilidades',
                    'variable': 'Métrica de análise'
                },
                title="Evolução Temporal: Volume Total vs. Severidade Crítica vs. Exploração Ativa", markers=True)

            # renomeia as legendas no gráfico
            new_names = {
                'quantidade_total_cves': 'Total de vulnerabilidades registradas',
                'quantidade_criticas': 'Vulnerabilidades de severidade crítica',
                'quantidade_exploradas_kev': 'Vulnerabilidades em exploração ativa (KEV)'
            }

            fig_vol_evolucao.for_each_trace(lambda t: t.update(name=new_names[t.name]))

             # AJUSTE DE TRANSPARÊNCIA PARA O CARD
            fig_vol_evolucao.update_layout(
                legend_itemclick="toggleothers"
            )
            apply_chart_layout(fig_vol_evolucao)

            st.plotly_chart(fig_vol_evolucao, width='stretch', key=f"trend_vol_{filtro_estatistico_alias}")

    add_section_spacing()

    with st.container(border=True):
        # Grafico 2: Evolução da Probabilidade Média (EPSS) ao longo dos anos
        st.subheader("Evolução da Probabilidade Média de Exploração (EPSS)")

        with st.expander("Guia de análise:"):
            st.markdown("""
                ### Objetivo: Volume de falhas vs. Risco real
                Este caso de uso investiga a relação entre a quantidade massiva de registros anuais e a periculosidade real observada no histórico de ataques.

                #### Como interpretar os gráficos:
                
                *  **Média EPSS (Gráfico de Área):** Este indicador mostra a "temperatura" da base. Se a probabilidade média (EPSS) está caindo enquanto o volume sobe, estamos vivendo uma inflação de registros de baixo risco. Se o EPSS sobe, as falhas novas estão vindo mais "armaenizáveis".

                #### O que isso prova:
                Esta visualização sustenta a hipótese de que o **aumento na superfície de detecção não é sinônimo de aumento na superfície de ataque**. Para um gestor de segurança, isso justifica focar recursos na inteligência de ameaças (KEV/EPSS) em vez de tentar "corrigir tudo" apenas pelo volume.
            """)

        if not df_tendencia.empty:
            fig_epss_trend = px.area(
                df_tendencia,
                x='ano_publicacao',
                y='media_probabilidade_epss',
                labels={
                    'ano_publicacao': 'Ano de publicação',
                    'media_probabilidade_epss': 'Média de probabilidade (EPSS)'
                },
                title="Tendência de Probabilidade Média de Exploração por Ano", 
                color_discrete_sequence=['red']
            )
            
            # AJUSTE DE TRANSPARÊNCIA PARA O CARD
            fig_epss_trend.update_layout(
            )
            apply_chart_layout(fig_epss_trend)
            
            st.plotly_chart(fig_epss_trend, width='stretch', key=f"trend_epss_{filtro_estatistico_alias}")
