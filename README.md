# PurpleCore
An advanced static application security testing (SAST) tool for automated vulnerability detection in source code (PHP, Java, Python, JavaScript) utilizing AI and customizable rule sets.

## Key Features
- Detection of 50+ vulnerability types (SQLi, XSS, RCE, etc.)
- Integrated DeepSeek and GraphCodeBERT AI models
- Training dataset generation
- Interactive code review

## Installation
```bash
pip install transformers torch pyyaml
git clone https://github.com/purpleteam-ru/purplecore
cd purplecore
```

Usage
Project Scanning
```bash
python analyzer.py /path/to/project
```

Interactive Review
```bash
python analyzer.py --review
```
Configuration

Create scanner_config.yaml:
```yaml
exclude_dirs: ['.git', 'node_modules']
model: deepseek-ai/DeepSeek-R1
rules:
  - security.yaml
  - custom_rules.yaml
```

Sample Findings
```bash

SQL Injection:
    Code: stmt.execute("SELECT * FROM users WHERE id = " + request.getParameter("id"))

Log Forging:
    Code: logger.info("User action: " + userInput)

Path Traversal:
    Code: FileUtils.readFile(request.getParameter("file"))

```

Model Training

To train the model using generated datasets:
```bash
docker run --gpus all -v /data:/data purplecore-trainer
```
