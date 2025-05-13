# Semgrep Scan Findings

A Python utility for retrieving and formatting security findings from Semgrep's API. This tool helps you export SAST (Static Application Security Testing), SCA (Software Composition Analysis), and Secret scanning findings into organized CSV files.

## Features

- Retrieves security findings from Semgrep's API
- Supports three types of findings:
  - SAST (Static Application Security Testing)
  - SCA (Software Composition Analysis)
  - Secret scanning
- Exports findings to well-formatted CSV files
- Handles pagination automatically
- Includes retry logic for API requests

## Prerequisites

- Python 3.x
- Semgrep API key

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/semgrep-scan-findings.git
cd semgrep-scan-findings
```

2. Create and activate a virtual environment:
```bash
python -m venv .venv
source .venv/bin/activate

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Configuration

Set your Semgrep API key as an environment variable:

```bash
export SEMGREP_API_KEY='your-api-key-here'
```

## Usage

Run the main script:

```bash
python main.py
```

The script will:
1. Connect to Semgrep's API
2. Retrieve your deployment information
3. Fetch all SAST, SCA, and Secret findings
4. Save the findings to CSV files in the `data` directory:
   - `data/sast_findings.csv`
   - `data/sca_findings.csv`
   - `data/secret_findings.csv`

## Output Format

### SAST Findings CSV
Contains columns for:
- id
- ref
- repository_name
- line_of_code_url
- status
- confidence
- rule_name
- rule_message
- severity

### SCA Findings CSV
Contains columns for:
- id
- ref
- repository_name
- line_of_code_url
- status
- confidence
- rule_name
- rule_message
- severity
- vulnerability_identifier
- reachability
- reachable_condition
- epss_score
- epss_percentile
- fix_recommendations
- package
- version
- ecosystem
- transitivity
- lockfile_line_url

### Secret Findings CSV
Contains columns for:
- id
- type
- findingPathUrl
- repository_name
- ref
- refUrl
- severity
- confidence
- validationState
- status
