#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Patch Generator - Auto-generate fixes for vulnerabilities
"""

import os
import json
import logging
from typing import Dict, Any, Optional

# Try to import Groq for patch generation
try:
    from vulnscanner import ask_groq, GROQ_API_KEY
except ImportError:
    # Fallback if run standalone
    from dotenv import load_dotenv
    load_dotenv()
    GROQ_API_KEY = os.getenv("GROQ_API_KEY")

# Set up logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')


def generate_patch(vulnerability: Dict[str, Any], target: str) -> Optional[str]:
    """
    Generate a code patch for a given vulnerability.
    
    Args:
        vulnerability: Dict with vulnerability details
        target: Target system info
    
    Returns:
        Patch code or None if generation fails
    """
    if not GROQ_API_KEY:
        logging.error("Groq API key not configured for patch generation")
        return None
    
    # Extract vulnerability details
    vuln_type = vulnerability.get('type', 'unknown')
    severity = vulnerability.get('severity', 'medium')
    description = vulnerability.get('description', '')
    remediation = vulnerability.get('remediation', '')
    cwe = vulnerability.get('cwe', '')
    owasp = vulnerability.get('owasp', '')
    
    # Build prompt using string concatenation (safer than f-string for multi-line)
    prompt_lines = [
        "You are a senior security engineer. Generate a fix for the following vulnerability.",
        "",
        "Target System: " + target,
        "",
        "Vulnerability Details:",
        "- Type: " + vuln_type,
        "- Severity: " + severity,
        "- Description: " + description,
        "- OWASP: " + owasp,
        "- CWE: " + cwe,
        "",
        "Remediation Suggestion: " + remediation,
        "",
        "Task:",
        "1. Generate a fix in the appropriate language (Python/JavaScript/Go/etc.)",
        "2. Include a brief explanation of the fix",
        "3. Output only the code and explanation",
        "",
        "Format:",
        "## Explanation",
        "[Brief explanation of the fix]",
        "",
        "## Code",
        "```[language]",
        "[Fixed code]",
        "```"
    ]
    
    prompt = "\n".join(prompt_lines)
    
    try:
        # Use Groq for patch generation
        logging.info("Generating patch for vulnerability: %s", vuln_type)
        patch = ask_groq(prompt, timeout=60)
        return patch
    except Exception as e:
        logging.error("Patch generation failed: %s", e)
        return None


def create_github_issue(patch: str, vulnerability: Dict[str, Any]) -> str:
    """
    Create a GitHub issue with the patch.
    (Placeholder - actual implementation would use GitHub API)
    """
    issue_lines = [
        "## Security Vulnerability Found",
        "",
        "**Vulnerability:** " + vulnerability.get('type', 'unknown'),
        "**Severity:** " + vulnerability.get('severity', 'medium'),
        "**OWASP:** " + vulnerability.get('owasp', 'N/A'),
        "**CWE:** " + vulnerability.get('cwe', 'N/A'),
        "",
        "## Auto-Generated Fix",
        "",
        patch,
        "",
        "## Manual Review Required",
        "",
        "This is an automatically generated patch. Please review before applying."
    ]
    
    return "\n".join(issue_lines)


def test_patch_generator():
    """Test patch generation with sample vulnerability"""
    
    sample_vuln = {
        'type': 'SQL Injection',
        'severity': 'High',
        'description': 'User input is not sanitized before database query',
        'remediation': 'Use parameterized queries or prepared statements',
        'owasp': 'A3:2021-Injection',
        'cwe': 'CWE-89: SQL Injection'
    }
    
    print("\n" + "="*60)
    print("Testing Patch Generator")
    print("="*60)
    print("Vulnerability:", sample_vuln['type'])
    print("Severity:", sample_vuln['severity'])
    print("-"*60)
    
    patch = generate_patch(sample_vuln, 'test.example.com')
    
    if patch:
        print("\n" + "="*60)
        print("Generated Patch:")
        print("="*60)
        print(patch)
        print("="*60)
    else:
        print("Patch generation failed - check Groq API key")


if __name__ == "__main__":
    test_patch_generator()
