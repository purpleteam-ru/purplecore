import os
import re
import json
import yaml
import sqlite3
import hashlib
import argparse
from datetime import datetime
from pathlib import Path
from transformers import AutoModelForCausalLM, AutoTokenizer
import torch

class SecurityScanner:
    def __init__(self, config_path="scanner_config.yaml"):
        self.config = self.load_config(config_path)
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self.init_models()
        self.init_database()
        self.init_dataset()
        self.load_custom_rules()

    def load_config(self, path):
        with open(path) as f:
            config = yaml.safe_load(f)
        
        defaults = {
            'exclude_dirs': ['.git', 'node_modules'],
            'min_severity': 0.3,
            'database': 'scan_results.db',
            'dataset': 'training_data.jsonl',
            'model': 'deepseek-ai/DeepSeek-R1',
            'languages': ['php', 'js', 'py', 'java', 'pl'],
            'max_code_length': 500,
            'max_ai_tokens': 1000
        }
        
        return {**defaults, **config}

    def init_models(self):
        self.tokenizer = AutoTokenizer.from_pretrained(self.config['model'])
        self.model = AutoModelForCausalLM.from_pretrained(
            self.config['model'],
            torch_dtype=torch.float16,
            device_map="auto"
        )

    def init_database(self):
        self.conn = sqlite3.connect(self.config['database'])
        self.cur = self.conn.cursor()
        self.cur.execute('''CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY,
            file_path TEXT,
            language TEXT,
            vulnerability TEXT,
            severity REAL,
            code TEXT,
            confirmed INTEGER DEFAULT 0,
            hash TEXT
        )''')

    def init_dataset(self):
        Path(self.config['dataset']).touch(exist_ok=True)

    def load_custom_rules(self):
        self.custom_rules = []
        for rule_file in self.config.get('custom_rules', []):
            try:
                with open(rule_file) as f:
                    rules = yaml.safe_load(f)
                    for rule in rules:
                        if self.validate_rule(rule):
                            self.custom_rules.append(rule)
            except Exception as e:
                print(f"Error loading {rule_file}: {str(e)}")

    def validate_rule(self, rule):
        required = ['id', 'name', 'pattern', 'languages']
        for key in required:
            if key not in rule:
                raise ValueError(f"Rule {rule.get('id')} missing {key}")
        
        try:
            re.compile(rule['pattern'])
            return True
        except re.error as e:
            print(f"Invalid regex in rule {rule['id']}: {str(e)}")
            return False

    def scan_directory(self, path):
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in self.config['exclude_dirs']]
            for file in files:
                file_path = os.path.join(root, file)
                if self.is_supported(file_path):
                    self.process_file(file_path)

    def is_supported(self, file_path):
        ext = file_path.split('.')[-1].lower()
        return ext in self.config['languages']

    def process_file(self, path):
        with open(path, 'r', errors='ignore') as f:
            content = f.read()
        
        file_hash = hashlib.sha256(content.encode()).hexdigest()
        if self.is_processed(path, file_hash):
            return

        findings = []
        findings += self.apply_custom_rules(content, path)
        findings += self.ai_analysis(content, path)
        
        for finding in findings:
            if finding['severity'] >= self.config['min_severity']:
                self.save_finding(path, finding, file_hash)

    def apply_custom_rules(self, content, path):
        findings = []
        for rule in self.custom_rules:
            try:
                if re.search(rule['pattern'], content, flags=re.DOTALL):
                    findings.append({
                        'type': rule['name'],
                        'severity': rule.get('severity', 0.5),
                        'code': content,
                        'rule': rule['id']
                    })
            except re.error as e:
                print(f"Regex error in rule {rule['id']}: {str(e)}")
        return findings

    def ai_analysis(self, content, path):
        prompt = f"""Analyze {Path(path).suffix[1:]} code for vulnerabilities. 
        Return ONLY valid JSON array: [{{"type": "...", "severity": 0.0, "code": "..."}}]
        {content[:5000]}
        """
        
        try:
            inputs = self.tokenizer(prompt, return_tensors="pt").to(self.device)
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=self.config['max_ai_tokens'],
                temperature=0.1,
                do_sample=False,
                eos_token_id=self.tokenizer.eos_token_id
            )
            
            raw_output = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
            json_str = self.extract_json(raw_output)
            
            findings = json.loads(json_str)
            return self.validate_findings(findings)
            
        except json.JSONDecodeError:
            print(f"JSON Error: {raw_output}")
            return []
        except Exception as e:
            print(f"AI analysis failed: {str(e)}")
            return []

    def extract_json(self, raw_output):
        start = raw_output.find('[')
        end = raw_output.rfind(']') + 1
        return raw_output[start:end] if start != -1 and end != 0 else '[]'

    def validate_findings(self, findings):
        valid = []
        for f in findings:
            if isinstance(f, dict) and all(k in f for k in ['type', 'severity', 'code']):
                f['code'] = str(f['code'])[:self.config['max_code_length']]
                valid.append(f)
        return valid

    def save_finding(self, path, finding, file_hash):
        self.cur.execute('''INSERT INTO findings 
            (file_path, language, vulnerability, severity, code, hash)
            VALUES (?, ?, ?, ?, ?, ?)''',
            (path, Path(path).suffix[1:], finding['type'], 
             finding['severity'], finding['code'], file_hash))
        self.conn.commit()

    def interactive_review(self):
        self.cur.execute('SELECT * FROM findings WHERE confirmed = 0')
        for row in self.cur.fetchall():
            print(f"\nFile: {row[1]}")
            print(f"Type: {row[3]} Severity: {row[4]}")
            print(f"Code:\n{row[5][:200]}...\n")
            
            action = input("[C]onfirm [F]alse [S]kip: ").lower()
            if action == 'c':
                self.mark_confirmed(row[0])
            elif action == 'f':
                self.mark_false_positive(row[0])

    def mark_confirmed(self, finding_id):
        self.cur.execute('UPDATE findings SET confirmed = 1 WHERE id = ?', (finding_id,))
        self.save_to_dataset(finding_id, True)

    def mark_false_positive(self, finding_id):
        self.cur.execute('DELETE FROM findings WHERE id = ?', (finding_id,))

    def save_to_dataset(self, finding_id, is_vulnerability):
        self.cur.execute('SELECT * FROM findings WHERE id = ?', (finding_id,))
        row = self.cur.fetchone()
        
        entry = {
            'meta': {
                'timestamp': datetime.now().isoformat(),
                'source': self.config.get('scanner_id', 'default'),
                'language': row[2],
                'label': is_vulnerability
            },
            'data': {
                'code': self.anonymize_code(row[5], row[2]),
                'type': row[3],
                'severity': row[4]
            }
        }
        
        with open(self.config['dataset'], 'a') as f:
            json.dump(entry, f, ensure_ascii=False)
            f.write('\n')

    def anonymize_code(self, code, lang):
        replacements = {
            'php': [(r'\$_(GET|POST)\[".+?"\]', '$_INPUT')],
            'js': [(r'process\.env\..+', 'ENV_VAR')],
            'py': [(r'os\.environ\[".+?"\]', 'ENV_VAR')],
            'java': [(r'System\.getProperty\(".+?"\)', 'SYSTEM_PROP')],
            'pl': [(r'param\(\s*".+?"\s*\)', 'PARAM_INPUT')]
        }
        for pattern, repl in replacements.get(lang, []):
            code = re.sub(pattern, repl, code)
        return code

    def is_processed(self, path, file_hash):
        self.cur.execute('SELECT hash FROM findings WHERE file_path = ?', (path,))
        result = self.cur.fetchone()
        return result and result[0] == file_hash

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced Code Scanner")
    parser.add_argument("directory", help="Directory to scan")
    parser.add_argument("--review", action="store_true", help="Interactive review mode")
    args = parser.parse_args()
    
    scanner = SecurityScanner()
    
    if args.review:
        scanner.interactive_review()
    else:
        if not Path(args.directory).exists():
            print(f"Error: {args.directory} not found")
            exit(1)
            
        scanner.scan_directory(args.directory)
        print(f"Scan completed. Results saved to {scanner.config['database']}")
