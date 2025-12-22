-- CVEs 
CREATE TABLE cves (
    id VARCHAR(50) PRIMARY KEY,
    published_date TIMESTAMP,
    last_modified_date TIMESTAMP, 
    vuln_status VARCHAR(50), 
    cve_tags TEXT[],
    description TEXT,                        

    -- Métricas CVSS
    cvss_metric_type VARCHAR(20), 
    cvss_version VARCHAR(10),        
    cvss_vector_string VARCHAR(100),      
    cvss_base_score DECIMAL(4,1),           
    cvss_base_severity VARCHAR(20),        
    
    -- Vetores de Ataque
    cvss_attack_vector VARCHAR(50),       
    cvss_attack_complexity VARCHAR(50),     
    cvss_privileges_required VARCHAR(50),    
    cvss_user_interaction VARCHAR(50),       
    cvss_scope VARCHAR(50),                  
    
    -- Impactos
    cvss_confidentiality_impact VARCHAR(20), 
    cvss_integrity_impact VARCHAR(20),      
    cvss_availability_impact VARCHAR(20),    
    
    -- Scores Adicionais 
    cvss_exploitability_score DECIMAL(4,1), 
    cvss_impact_score DECIMAL(4,1)       
);

-- KEV
CREATE TABLE kev (
    cve_id VARCHAR(50) PRIMARY KEY,
    vendor_project VARCHAR(255),
    product VARCHAR(255),
    vulnerability_name VARCHAR(255),
    date_added DATE,
    short_description TEXT,
    required_action TEXT,
    due_date DATE,
    known_ransomware_usage BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (cve_id) REFERENCES cves(id)
);

-- EPSS
CREATE TABLE epss_scores (
    cve_id VARCHAR(50) PRIMARY KEY,
    epss_score DECIMAL(6,5),
    percentile DECIMAL(6,5),
    FOREIGN KEY (cve_id) REFERENCES cves(id)
);

-- CWEs
CREATE TABLE cwes (
    id VARCHAR(20) PRIMARY KEY, 
    description TEXT
);

-- CVE <-> CWE (Muitos para Muitos)
CREATE TABLE cve_cwe_mapping (
    cve_id VARCHAR(50),
    cwe_id VARCHAR(20),
    PRIMARY KEY (cve_id, cwe_id),
    FOREIGN KEY (cve_id) REFERENCES cves(id),
    FOREIGN KEY (cwe_id) REFERENCES cwes(id)
);

-- Índices para melhorar a performance dos Dashboards no Streamlit
CREATE INDEX idx_cve_published ON cves(published_date);
CREATE INDEX idx_cvss_severity ON cves(cvss_v3_severity);
CREATE INDEX idx_kev_ransomware ON kev_entries(known_ransomware_usage);
CREATE INDEX idx_epss_score ON epss_scores(epss_score);