import json
from fpdf import FPDF

class Report:
    def __init__(self):
        self.evidence = {
            "file_info": {},
            "obfuscation": {},
            "strings": {
                "urls": [],
                "emails": [],
                "base64": [],
                "hex": [],
                "other": []
            },
            "suspicious_functions": [],
            "embedded_files": [],
            "sections": [],
            "risk_score": 0,
            "risk_factors": []
        }

    def add_evidence(self, category, data):
        self.evidence[category] = data

    def export_pdf(self, output_path):
        pdf = FPDF()
        pdf.add_page()
        
        # Title
        pdf.set_font('Arial', 'B', 16)
        pdf.cell(0, 10, 'Binary Analysis Report', 0, 1, 'C')
        
        # Risk Score
        pdf.set_font('Arial', 'B', 14)
        pdf.cell(0, 10, f'Risk Score: {self.evidence["risk_score"]}', 0, 1)
        
        # Risk Factors
        if self.evidence["risk_factors"]:
            pdf.set_font('Arial', 'B', 12)
            pdf.cell(0, 10, 'Risk Factors:', 0, 1)
            pdf.set_font('Arial', '', 10)
            for factor in self.evidence["risk_factors"]:
                pdf.cell(0, 10, f'- {factor}', 0, 1)
        
        # Add other sections based on evidence
        for category, data in self.evidence.items():
            if data and category not in ['risk_score', 'risk_factors']:
                pdf.add_page()
                pdf.set_font('Arial', 'B', 14)
                pdf.cell(0, 10, category.replace('_', ' ').title(), 0, 1)
                pdf.set_font('Arial', '', 10)
                
                if isinstance(data, list):
                    for item in data:
                        pdf.cell(0, 10, f'- {item}', 0, 1)
                elif isinstance(data, dict):
                    for key, value in data.items():
                        pdf.cell(0, 10, f'{key}: {value}', 0, 1)
                else:
                    pdf.cell(0, 10, str(data), 0, 1)
        
        pdf.output(output_path)

    def export_json(self, output_path):
        with open(output_path, 'w') as f:
            json.dump(self.evidence, f, indent=4)
