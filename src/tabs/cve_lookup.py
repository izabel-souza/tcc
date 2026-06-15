import pandas as pd
import streamlit as st

from src.utils.database import get_data


def formatar_data(valor):
    if pd.isna(valor):
        return "Não informado"

    return pd.to_datetime(valor).strftime("%d/%m/%Y")


def formatar_decimal(valor, casas=2):
    if pd.isna(valor):
        return "Não informado"

    return f"{float(valor):.{casas}f}"


def formatar_percentual(valor):
    if pd.isna(valor):
        return "Não informado"

    return f"{float(valor) * 100:.1f}%"


def formatar_booleano(valor):
    if pd.isna(valor):
        return "Não"

    return "Sim" if bool(valor) else "Não"


def formatar_texto(valor):
    if pd.isna(valor) or not str(valor).strip():
        return "Não informado"

    return str(valor)


def formatar_texto_kev(valor, is_kev):
    if not bool(is_kev):
        return "Não aplicável ao KEV"

    return formatar_texto(valor)


def formatar_tags(valor):
    if valor is None:
        return "Não informado"

    if isinstance(valor, list):
        return ", ".join(valor) if valor else "Não informado"

    if pd.isna(valor):
        return "Não informado"

    return str(valor)


def formatar_percentual_com_mensagem(valor, mensagem):
    if pd.isna(valor):
        return mensagem

    return f"{float(valor) * 100:.1f}%"


def buscar_cves(filtro_sql_alias, busca_cve=""):
    condicao_busca = "1=1"
    if busca_cve:
        busca_sanitizada = busca_cve.strip().replace("'", "''")
        condicao_busca = f"c.id ILIKE '%{busca_sanitizada}%'"

    query = f"""
        SELECT
            c.id AS cve_id,
            c.published_date,
            c.last_modified_date,
            c.vuln_status,
            c.cve_tags,
            c.description,
            c.cvss_metric_type,
            c.cvss_version,
            c.cvss_vector_string,
            c.cvss_base_score,
            c.cvss_base_severity,
            c.cvss_attack_vector,
            c.cvss_attack_complexity,
            c.cvss_privileges_required,
            c.cvss_user_interaction,
            c.cvss_scope,
            c.cvss_confidentiality_impact,
            c.cvss_integrity_impact,
            c.cvss_availability_impact,
            c.cvss_exploitability_score,
            c.cvss_impact_score,
            e.epss_score,
            e.percentile AS epss_percentile,
            CASE WHEN k.cve_id IS NOT NULL THEN TRUE ELSE FALSE END AS is_kev,
            k.vendor_project,
            k.product,
            k.date_added,
            k.due_date,
            COALESCE(k.known_ransomware_usage, FALSE) AS known_ransomware_usage,
            COALESCE(
                STRING_AGG(DISTINCT cw.id, ', ') FILTER (WHERE cw.id IS NOT NULL),
                ''
            ) AS cwes,
            COALESCE(
                STRING_AGG(DISTINCT mt.id || ' - ' || mt.name, ', ') FILTER (WHERE mt.id IS NOT NULL),
                ''
            ) AS mitre_techniques,
            COALESCE(
                STRING_AGG(DISTINCT mta.id || ' - ' || mta.name, ', ') FILTER (WHERE mta.id IS NOT NULL),
                ''
            ) AS mitre_tactics
        FROM cves c
        LEFT JOIN epss_scores e ON c.id = e.cve_id
        LEFT JOIN kev k ON c.id = k.cve_id
        LEFT JOIN cve_cwe_mapping ccm ON c.id = ccm.cve_id
        LEFT JOIN cwes cw ON ccm.cwe_id = cw.id
        LEFT JOIN cwe_mitre_mapping cmm ON cw.id = cmm.cwe_id
        LEFT JOIN mitre_techniques mt ON cmm.mitre_id = mt.id
        LEFT JOIN mitre_tactic_technique mtt ON mt.id = mtt.technique_id
        LEFT JOIN mitre_tactics mta ON mtt.tactic_id = mta.id
        WHERE {filtro_sql_alias}
          AND {condicao_busca}
        GROUP BY
            c.id,
            c.published_date,
            c.last_modified_date,
            c.vuln_status,
            c.cve_tags,
            c.description,
            c.cvss_metric_type,
            c.cvss_version,
            c.cvss_vector_string,
            c.cvss_base_score,
            c.cvss_base_severity,
            c.cvss_attack_vector,
            c.cvss_attack_complexity,
            c.cvss_privileges_required,
            c.cvss_user_interaction,
            c.cvss_scope,
            c.cvss_confidentiality_impact,
            c.cvss_integrity_impact,
            c.cvss_availability_impact,
            c.cvss_exploitability_score,
            c.cvss_impact_score,
            e.epss_score,
            e.percentile,
            k.cve_id,
            k.vendor_project,
            k.product,
            k.date_added,
            k.due_date,
            k.known_ransomware_usage
        ORDER BY c.published_date DESC NULLS LAST
        LIMIT 1000
    """

    return get_data(query)


def montar_tabela(df):
    tabela = pd.DataFrame({
        "CVE ID": df["cve_id"],
        "Publicação": df["published_date"].apply(formatar_data),
        "Status": df["vuln_status"].fillna("Não informado"),
        "Severidade": df["cvss_base_severity"].fillna("Sem métrica CVSS"),
        "CVSS": df["cvss_base_score"].apply(
            lambda valor: formatar_decimal(valor, 1) if not pd.isna(valor) else "Sem métrica CVSS"
        ),
        "EPSS": df["epss_score"].apply(lambda valor: formatar_percentual_com_mensagem(valor, "Sem score EPSS")),
        "Percentil EPSS": df["epss_percentile"].apply(lambda valor: formatar_percentual_com_mensagem(valor, "Sem percentil EPSS")),
        "KEV": df["is_kev"].apply(formatar_booleano),
        "Ransomware": df["known_ransomware_usage"].apply(formatar_booleano),
        "Fornecedor/projeto KEV": df.apply(
            lambda linha: formatar_texto_kev(linha["vendor_project"], linha["is_kev"]),
            axis=1
        ),
        "Produto KEV": df.apply(
            lambda linha: formatar_texto_kev(linha["product"], linha["is_kev"]),
            axis=1
        ),
        "CWEs": df["cwes"].replace("", "Sem CWE associado"),
    })

    return tabela


def obter_linha_selecionada(evento):
    selecao = getattr(evento, "selection", None)

    if selecao is None:
        return None

    linhas = selecao.get("rows", []) if isinstance(selecao, dict) else selecao.rows
    return linhas[0] if linhas else None


def renderizar_lista_rotulada(titulo, valor):
    texto = valor if isinstance(valor, str) and valor.strip() else "Não informado"
    st.markdown(f"**{titulo}**")
    st.write(texto)


def renderizar_detalhe_cve(cve):
    st.divider()
    st.markdown("""
        <style>
        [data-testid="stVerticalBlockBorderWrapper"] {
            background-color: #1B3555 !important;
            background-image: none !important;
            border-color: rgba(56, 182, 255, 0.34) !important;
            box-shadow: 0 14px 30px rgba(0, 0, 0, 0.22) !important;
        }

        [data-testid="stVerticalBlockBorderWrapper"] > div,
        [data-testid="stVerticalBlockBorderWrapper"] [data-testid="stVerticalBlock"],
        [data-testid="stVerticalBlockBorderWrapper"] [data-testid="stVerticalBlock"] > div,
        [data-testid="stVerticalBlockBorderWrapper"] [data-testid="stVerticalBlock"] [data-testid="stElementContainer"] {
            background-color: #1B3555 !important;
            background-image: none !important;
        }

        [data-testid="stMarkdownContainer"] h4 {
            color: #38b6ff !important;
        }

        [data-testid="stMetricValue"] {
            color: #F8FAFC !important;
            font-size: 1.75rem !important;
            line-height: 1.2 !important;
        }

        [data-testid="stMetricLabel"] {
            color: #F8FAFC !important;
            font-size: 0.82rem !important;
        }

        [data-testid="stCaptionContainer"],
        [data-testid="stMarkdownContainer"] p {
            color: #CBD5E1 !important;
        }

        [data-testid="stMarkdownContainer"] strong {
            color: #93C5FD !important;
        }

        [data-testid="stMetric"] {
            margin-bottom: 0.55rem !important;
        }
        </style>
    """, unsafe_allow_html=True)
    st.subheader(f"Detalhes da {cve['cve_id']}")

    descricao = cve.get("description")
    if not isinstance(descricao, str) or not descricao.strip():
        descricao = "Descrição ainda não disponível na base atual."

    with st.container(border=True):
        st.markdown("#### Identificação")
        col1, col2, col3 = st.columns(3)
        col1.metric("CVE ID", cve["cve_id"])
        col2.metric("Publicação", formatar_data(cve["published_date"]))
        col3.metric("Última modificação", formatar_data(cve["last_modified_date"]))
        col4, col5 = st.columns(2)
        col4.metric("Status NVD", formatar_texto(cve["vuln_status"]))
        col5.metric("Tags CVE", formatar_tags(cve["cve_tags"]))
        st.markdown("#### Descrição")
        st.write(descricao)

    col1, col2, col3 = st.columns(3)

    with col1:
        with st.container(border=True):
            st.markdown("#### Severidade CVSS")
            st.metric(
                "Score CVSS",
                formatar_decimal(cve["cvss_base_score"], 1)
                if not pd.isna(cve["cvss_base_score"])
                else "Sem métrica CVSS"
            )
            st.metric("Severidade", formatar_texto(cve["cvss_base_severity"]))
            st.caption(f"Versão: {formatar_texto(cve['cvss_version'])}")
            st.caption(f"Tipo de métrica: {formatar_texto(cve['cvss_metric_type'])}")

    with col2:
        with st.container(border=True):
            st.markdown("#### Probabilidade EPSS")
            st.metric("Score EPSS", formatar_percentual_com_mensagem(cve["epss_score"], "Sem score EPSS"))
            st.metric(
                "Percentil EPSS",
                formatar_percentual_com_mensagem(cve["epss_percentile"], "Sem percentil EPSS")
            )

    with col3:
        with st.container(border=True):
            st.markdown("#### Catálogo KEV/CISA")
            st.metric("Presente no KEV", formatar_booleano(cve["is_kev"]))
            st.metric("Ransomware", formatar_booleano(cve["known_ransomware_usage"]))
            if bool(cve["is_kev"]):
                st.caption(f"Adicionada ao KEV: {formatar_data(cve['date_added'])}")
                st.caption(f"Prazo CISA: {formatar_data(cve['due_date'])}")

    if bool(cve["is_kev"]):
        col4, col5 = st.columns(2)
    else:
        col4 = None
        col5 = st.container()

    if bool(cve["is_kev"]):
        with col4:
            with st.container(border=True):
                st.markdown("#### Produto no KEV")
                renderizar_lista_rotulada(
                    "Fornecedor/projeto KEV",
                    formatar_texto(cve["vendor_project"])
                )
                renderizar_lista_rotulada(
                    "Produto KEV",
                    formatar_texto(cve["product"])
                )

    with col5:
        with st.container(border=True):
            st.markdown("#### Causa raiz e padrões de ataque")
            renderizar_lista_rotulada("CWEs associados", cve["cwes"] or "Sem CWE associado")
            renderizar_lista_rotulada(
                "Táticas MITRE ATT&CK",
                cve["mitre_tactics"] or "Sem tática MITRE associada"
            )
            renderizar_lista_rotulada(
                "Técnicas MITRE ATT&CK",
                cve["mitre_techniques"] or "Sem técnica MITRE associada"
            )

    with st.container(border=True):
        st.markdown("#### Detalhamento técnico CVSS")
        renderizar_lista_rotulada("Vetor CVSS", cve["cvss_vector_string"])

        col6, col7, col8 = st.columns(3)
        with col6:
            renderizar_lista_rotulada("Vetor de ataque", cve["cvss_attack_vector"])
            renderizar_lista_rotulada("Complexidade de ataque", cve["cvss_attack_complexity"])
            renderizar_lista_rotulada("Privilégios requeridos", cve["cvss_privileges_required"])

        with col7:
            renderizar_lista_rotulada("Interação do usuário", cve["cvss_user_interaction"])
            renderizar_lista_rotulada("Escopo", cve["cvss_scope"])
            renderizar_lista_rotulada("Impacto em confidencialidade", cve["cvss_confidentiality_impact"])

        with col8:
            renderizar_lista_rotulada("Impacto em integridade", cve["cvss_integrity_impact"])
            renderizar_lista_rotulada("Impacto em disponibilidade", cve["cvss_availability_impact"])
            renderizar_lista_rotulada(
                "Subscore de explorabilidade",
                formatar_decimal(cve["cvss_exploitability_score"])
            )
            renderizar_lista_rotulada("Subscore de impacto", formatar_decimal(cve["cvss_impact_score"]))


def limpar_busca_cve():
    st.session_state["consulta_cve_busca_id"] = ""


def render_cve_lookup_tab(filtro_sql_alias):
    st.header("Consulta CVE")
    st.caption(
        "Consulte vulnerabilidades individuais combinando dados de CVE, CVSS, EPSS, KEV, CWE e MITRE ATT&CK."
    )

    col_busca, col_limpar = st.columns([0.96, 0.04], vertical_alignment="bottom")
    with col_busca:
        busca_cve = st.text_input(
            "Buscar CVE por ID",
            placeholder="Ex: CVE-2024-1234",
            key="consulta_cve_busca_id",
            help="Digite o ID completo ou parcial para filtrar a tabela abaixo."
        )
    with col_limpar:
        st.button(
            "×",
            help="Limpar busca",
            on_click=limpar_busca_cve,
            disabled=not bool(st.session_state.get("consulta_cve_busca_id")),
            use_container_width=True
        )

    df_cves = buscar_cves(filtro_sql_alias, busca_cve)

    if df_cves.empty:
        st.info("Nenhuma CVE encontrada para os filtros selecionados.")
        return

    st.caption("Exibindo até 1.000 CVEs mais recentes dentro dos filtros globais.")
    tabela = montar_tabela(df_cves)
    evento = st.dataframe(
        tabela,
        hide_index=True,
        width="stretch",
        height=430,
        on_select="rerun",
        selection_mode="single-row",
        key=f"consulta_cve_{filtro_sql_alias}_{busca_cve}",
    )

    indice_selecionado = obter_linha_selecionada(evento)
    if indice_selecionado is None:
        st.info("Selecione uma linha da tabela para visualizar os detalhes da CVE.")
        return

    renderizar_detalhe_cve(df_cves.iloc[indice_selecionado])
