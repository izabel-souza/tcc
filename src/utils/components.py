# --- IMPORT ---
import streamlit as st

def render_ransomware_icon(percentual):
    # Definindo a cor de preenchimento baseada na paleta (CRITICAL #EF4444)
    fill_color = "#EF4444"
    background_icon = "#374151" # Cinza escuro para a parte não preenchida
    
    st.markdown(f"""
    <div style="display: flex; flex-direction: column; align-items: center; justify-content: center; background-color: #1F2937; padding: 25px; border-radius: 15px; border: 1px solid #374151;">
        <div style="position: relative; width: 120px; height: 120px;">
            <svg viewBox="0 0 24 24" fill="{background_icon}" style="width: 100%; height: 100%; position: absolute;">
                <path d="M21 2H3c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h7l-2 3v1h8v-1l-2-3h7c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm0 14H3V4h18v12zm-9-9c-1.66 0-3 1.34-3 3v2H8v6h8v-6h-1v-2c0-1.66-1.34-3-3-3zm1 5h-2v-2c0-.55.45-1 1-1s1 .45 1 1v2z"/>
            </svg>
            <div style="position: absolute; bottom: 0; left: 0; width: 100%; height: {percentual}%; overflow: hidden; transition: height 1s ease-in-out;">
                <svg viewBox="0 0 24 24" fill="{fill_color}" style="width: 120px; height: 120px; position: absolute; bottom: 0;">
                    <path d="M21 2H3c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h7l-2 3v1h8v-1l-2-3h7c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm0 14H3V4h18v12zm-9-9c-1.66 0-3 1.34-3 3v2H8v6h8v-6h-1v-2c0-1.66-1.34-3-3-3zm1 5h-2v-2c0-.55.45-1 1-1s1 .45 1 1v2z"/>
                </svg>
            </div>
        </div>
        <div style="margin-top: 15px; font-size: 28px; font-weight: bold; color: #F9FAFB;">{percentual:.1f}%</div>
        <div style="color: #9CA3AF; font-size: 14px; text-transform: uppercase; letter-spacing: 1px;">Presença de Ransomware</div>
    </div>
    """, unsafe_allow_html=True)

def render_kpi_card(titulo, valor):
    """
    layout do card dos kpis na aba vision: valor em destaque em cima e texto embaixo.
    """
    st.markdown(f"""
    <div style="
        background-color: #1F2937; 
        border: 1px solid #374151; 
        padding: 25px; 
        border-radius: 20px; 
        text-align: center; 
        box-shadow: 2px 2px 10px rgba(0,0,0,0.3);
        margin-bottom: 10px;
    ">
        <div style="font-size: 47px; font-weight: bold; color: #F9FAFB; margin-bottom: 5px;">
            {valor}
        </div>
        <div style="font-size: 14px; color: white; font-weight: 700; text-transform: uppercase; letter-spacing: 1.2px;">
            {titulo}
        </div>
    </div>
    """, unsafe_allow_html=True)

