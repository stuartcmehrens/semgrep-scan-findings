import pandas as pd

def __extract_repository_name(df: pd.DataFrame) -> pd.DataFrame:
    df['repository_name'] = df['repository'].apply(lambda x: x.get('name') if isinstance(x, dict) else None)
    return df

def format_sast_csv(sast_findings: list, output_file: str):
    df = pd.DataFrame(sast_findings)
    df = __extract_repository_name(df)
    
    columns = [
        'id',
        'ref',
        'repository_name',
        'line_of_code_url',
        'status',
        'confidence',
        'rule_name',
        'rule_message',
        'severity'
    ]
    
    df = df[columns]
    df.to_csv(output_file, index=False)
    return df

def format_sca_csv(sca_findings: list, output_file: str):
    df = pd.DataFrame(sca_findings)
    df = __extract_repository_name(df)
    df['epss_score'] = df['epss_score'].apply(lambda x: x.get('score') if isinstance(x, dict) else None)
    df['epss_percentile'] = df['epss_score'].apply(lambda x: x.get('percentile') if isinstance(x, dict) else None)
    
    df['fix_recommendations'] = df['fix_recommendations'].apply(
        lambda x: ';'.join([f"{rec.get('package', '')}:{rec.get('version', '')}" for rec in x]) 
        if isinstance(x, list) else None
    )
    
    df['package'] = df['found_dependency'].apply(lambda x: x.get('package') if isinstance(x, dict) else None)
    df['version'] = df['found_dependency'].apply(lambda x: x.get('version') if isinstance(x, dict) else None)
    df['ecosystem'] = df['found_dependency'].apply(lambda x: x.get('ecosystem') if isinstance(x, dict) else None)
    df['transitivity'] = df['found_dependency'].apply(lambda x: x.get('transitivity') if isinstance(x, dict) else None)
    df['lockfile_line_url'] = df['found_dependency'].apply(lambda x: x.get('lockfile_line_url') if isinstance(x, dict) else None)
    
    columns = [
        'id',
        'ref',
        'repository_name',
        'line_of_code_url',
        'status',
        'confidence',
        'rule_name',
        'rule_message',
        'severity',
        'vulnerability_identifier',
        'reachability',
        'reachable_condition',
        'epss_score',
        'epss_percentile',
        'fix_recommendations',
        'package',
        'version',
        'ecosystem',
        'transitivity',
        'lockfile_line_url'
    ]
    
    df = df[columns]
    df.to_csv(output_file, index=False)
    return df

def format_secrets_csv(secret_findings: list, output_file: str):
    df = pd.DataFrame(secret_findings)
    df = __extract_repository_name(df)
    
    columns = [
        'id',
        'type',
        'findingPathUrl',
        'repository_name',
        'ref',
        'refUrl',
        'severity',
        'confidence',
        'validationState',
        'status'
    ]
    
    df = df[columns]
    
    df.to_csv(output_file, index=False)
    return df