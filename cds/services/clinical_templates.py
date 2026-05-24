import json
import logging
from typing import Any
import time

LOGGER = logging.getLogger("clinical-data-studio")

def now() -> int:
    return int(time.time())

CLINICAL_TEMPLATES = {
    "staph_bacteremia": {
        "name": "Staphylococcus aureus bacteremia registry",
        "description": "Registry for tracking S. aureus bacteremia demographics, resistance, source of infection, and 30-day outcomes.",
        "forms": [
            {
                "code": "demographics",
                "name": "Demographics and Baseline",
                "fields": [
                    {"code": "age", "label": "Age", "type": "integer", "min": 0, "max": 120, "units": "years", "phi": False, "export_label": "age"},
                    {"code": "sex", "label": "Sex", "type": "radio", "choices": "1, Male | 2, Female | 3, Other", "phi": False, "export_label": "sex"},
                    {"code": "patient_name", "label": "Patient Name", "type": "text", "phi": True, "export_label": "patient_name_redacted"},
                    {"code": "admission_date", "label": "Admission Date", "type": "date", "phi": True, "export_label": "admission_date_deidentified"}
                ]
            },
            {
                "code": "clinical",
                "name": "Clinical Details & Outcomes",
                "fields": [
                    {"code": "source", "label": "Primary Source of Bacteremia", "type": "radio", "choices": "1, Vascular Access | 2, Skin/Soft Tissue | 3, Osteoarticular | 4, Endocarditis | 5, Unknown", "phi": False, "export_label": "primary_source"},
                    {"code": "mrsa", "label": "Methicillin Resistance (MRSA)", "type": "yesno", "phi": False, "export_label": "mrsa_status"},
                    {"code": "echocardiogram", "label": "Echocardiogram Done", "type": "yesno", "phi": False, "export_label": "echo_done"},
                    {"code": "mortality_30d", "label": "30-Day Mortality", "type": "yesno", "phi": False, "export_label": "mortality_30d"}
                ]
            }
        ]
    },
    "opat": {
        "name": "Outpatient Parenteral Antimicrobial Therapy (OPAT) registry",
        "description": "Registry for tracking patients discharged on outpatient intravenous antibiotics, monitoring compliance, and complications.",
        "forms": [
            {
                "code": "opat_baseline",
                "name": "OPAT Baseline & Antibiotics",
                "fields": [
                    {"code": "indication", "label": "Infectious Indication", "type": "radio", "choices": "1, Bone/Joint | 2, Endocarditis | 3, Skin/Soft Tissue | 4, Intra-abdominal | 5, Other", "phi": False, "export_label": "opat_indication"},
                    {"code": "antibiotic", "label": "Prescribed IV Antibiotic", "type": "radio", "choices": "1, Ceftriaxone | 2, Ertapenem | 3, Teicoplanin | 4, Daptomycin | 5, Other", "phi": False, "export_label": "opat_antibiotic"},
                    {"code": "duration_weeks", "label": "Planned Duration (weeks)", "type": "integer", "min": 1, "max": 24, "phi": False, "export_label": "planned_duration_weeks"}
                ]
            },
            {
                "code": "opat_monitoring",
                "name": "Complications & Outcomes",
                "fields": [
                    {"code": "vascular_line_complication", "label": "Line Complication (e.g. PICC occlusion/infection)", "type": "yesno", "phi": False, "export_label": "line_complication"},
                    {"code": "readmission_30d", "label": "30-Day Readmission", "type": "yesno", "phi": False, "export_label": "readmission_30d"},
                    {"code": "cure_rate", "label": "Clinical Cure at End of Therapy", "type": "yesno", "phi": False, "export_label": "clinical_cure"}
                ]
            }
        ]
    },
    "tb_outcome": {
        "name": "Tuberculosis treatment outcome registry",
        "description": "Registry tracking pulmonary and extrapulmonary TB treatment progression, drug susceptibility, and standard WHO outcomes.",
        "forms": [
            {
                "code": "tb_baseline",
                "name": "TB Diagnostic Baseline",
                "fields": [
                    {"code": "tb_site", "label": "Site of Tuberculosis", "type": "radio", "choices": "1, Pulmonary | 2, Extrapulmonary | 3, Both", "phi": False, "export_label": "tb_site"},
                    {"code": "dst_status", "label": "Drug Susceptibility Test (DST)", "type": "radio", "choices": "1, Sensitive | 2, MDR-TB | 3, XDR-TB | 4, Not Done", "phi": False, "export_label": "dst_status"},
                    {"code": "hiv_status", "label": "Co-infection (HIV)", "type": "yesno", "phi": False, "export_label": "hiv_status"}
                ]
            },
            {
                "code": "tb_outcome",
                "name": "Treatment Outcome",
                "fields": [
                    {"code": "outcome", "label": "WHO Outcome Classification", "type": "radio", "choices": "1, Cured | 2, Treatment Completed | 3, Treatment Failed | 4, Died | 5, Lost to Follow-up", "phi": False, "export_label": "treatment_outcome"},
                    {"code": "adverse_events", "label": "Significant Drug-Induced Side Effects", "type": "yesno", "phi": False, "export_label": "adverse_events"}
                ]
            }
        ]
    },
    "amr_stewardship": {
        "name": "Antimicrobial stewardship audit template",
        "description": "Template for point-prevalence surveys and stewardship audits evaluating antibiotic appropriateness and guideline adherence.",
        "forms": [
            {
                "code": "audit_details",
                "name": "Antibiotic Audit Data",
                "fields": [
                    {"code": "antibiotic_name", "label": "Prescribed Antibiotic", "type": "text", "phi": False, "export_label": "antibiotic_name"},
                    {"code": "guideline_adherent", "label": "Adherence to Institutional Guidelines", "type": "yesno", "phi": False, "export_label": "guideline_compliance"},
                    {"code": "indication_documented", "label": "Indication Documented in Case Notes", "type": "yesno", "phi": False, "export_label": "indication_documented"},
                    {"code": "stop_review_date", "label": "48-72h Review/Stop Date Documented", "type": "yesno", "phi": False, "export_label": "review_documented"}
                ]
            }
        ]
    },
    "fungal_infection": {
        "name": "Invasive fungal infection registry",
        "description": "Registry for tracking diagnostic evidence, risk factors, and antifungal treatments for invasive aspergillosis, candidiasis, etc.",
        "forms": [
            {
                "code": "fungal_baseline",
                "name": "Risk Factors & Diagnosis",
                "fields": [
                    {"code": "neutropenic", "label": "Neutropenia at Diagnosis (<500/mm3)", "type": "yesno", "phi": False, "export_label": "neutropenia_status"},
                    {"code": "organism", "label": "Identified Organism", "type": "radio", "choices": "1, Aspergillus fumigatus | 2, Candida albicans | 3, Candida auris | 4, Mucorales | 5, Other", "phi": False, "export_label": "fungal_organism"},
                    {"code": "diagnostic_evidence", "label": "Diagnostic Certainty", "type": "radio", "choices": "1, Proven | 2, Probable | 3, Possible", "phi": False, "export_label": "diagnostic_certainty"}
                ]
            },
            {
                "code": "fungal_treatment",
                "name": "Antifungal Therapy & Outcome",
                "fields": [
                    {"code": "antifungal", "label": "Primary Antifungal Agent", "type": "radio", "choices": "1, Voriconazole | 2, Amphotericin B | 3, Caspofungin | 4, Posaconazole | 5, Other", "phi": False, "export_label": "antifungal_agent"},
                    {"code": "renal_toxicity", "label": "Antifungal-Related Renal Toxicity", "type": "yesno", "phi": False, "export_label": "renal_toxicity"},
                    {"code": "survival_6_weeks", "label": "Survival at 6 Weeks", "type": "yesno", "phi": False, "export_label": "survival_6w"}
                ]
            }
        ]
    },
    "hai_surveillance": {
        "name": "Hospital-acquired infection surveillance",
        "description": "Surveillance system mapping CAUTI, CLABSI, and VAP rates in ICU/wards.",
        "forms": [
            {
                "code": "infection_details",
                "name": "Infection Details",
                "fields": [
                    {"code": "hai_type", "label": "Infection Type", "type": "radio", "choices": "1, CLABSI (Central Line) | 2, CAUTI (Urinary Catheter) | 3, VAP (Ventilator-Associated) | 4, SSI (Surgical Site)", "phi": False, "export_label": "hai_type"},
                    {"code": "device_days", "label": "Device Duration (days)", "type": "integer", "min": 1, "max": 180, "phi": False, "export_label": "device_duration_days"},
                    {"code": "icu_stay", "label": "Acquired in ICU", "type": "yesno", "phi": False, "export_label": "acquired_in_icu"}
                ]
            }
        ]
    },
    "febrile_neutropenia": {
        "name": "Febrile neutropenia registry",
        "description": "Registry for tracking febrile neutropenia risk stratification (MASCC), bacteremia occurrence, and outcomes.",
        "forms": [
            {
                "code": "neutropenia_baseline",
                "name": "Risk Stratification",
                "fields": [
                    {"code": "mascc_score", "label": "MASCC Risk Index Score", "type": "integer", "min": 0, "max": 26, "phi": False, "export_label": "mascc_score"},
                    {"code": "bacteremia", "label": "Bacteremia Confirmed", "type": "yesno", "phi": False, "export_label": "bacteremia_confirmed"},
                    {"code": "gcsf_used", "label": "G-CSF Support Provided", "type": "yesno", "phi": False, "export_label": "gcsf_support"}
                ]
            }
        ]
    }
}

def apply_template_to_study(conn: Any, study_id: int, template_name: str) -> None:
    if template_name not in CLINICAL_TEMPLATES:
        raise ValueError(f"Unknown clinical template: {template_name}")
        
    template = CLINICAL_TEMPLATES[template_name]
    timestamp = now()
    
    # Iterate and create the forms
    for form_data in template["forms"]:
        # Normalize fields to schema
        schema = {
            "fields": form_data["fields"]
        }
        schema_json = json.dumps(schema)
        
        # Insert the form
        conn.execute(
            """
            INSERT INTO forms (study_id, name, code, schema_json, version, active, lifecycle_state, created_at, updated_at)
            VALUES (?, ?, ?, ?, 1, 1, 'published', ?, ?)
            """,
            (study_id, form_data["name"], form_data["code"], schema_json, timestamp, timestamp)
        )
        
    LOGGER.info(f"Successfully applied template '{template_name}' to study {study_id}.")
