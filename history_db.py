#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
History Database - Store and track scan results over time
"""

import sqlite3
import json
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional

DB_PATH = "cybershield_history.db"


def init_db():
    """Initialize the database with required tables"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Scans table
    c.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            scan_date TIMESTAMP,
            tci_score INTEGER,
            severity TEXT,
            open_ports TEXT,
            services TEXT,
            vulnerabilities TEXT,
            report_file TEXT,
            provider TEXT
        )
    ''')
    
    # Trends table (for historical analysis)
    c.execute('''
        CREATE TABLE IF NOT EXISTS trends (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            date TIMESTAMP,
            metric_name TEXT,
            old_value TEXT,
            new_value TEXT,
            change_type TEXT
        )
    ''')
    
    conn.commit()
    conn.close()
    logging.debug("Database initialized")


def store_scan_result(scan_data: Dict[str, Any], meta: Dict[str, Any]):
    """
    Store scan results in database
    
    Args:
        scan_data: Parsed scan results
        meta: Metadata (target, provider, etc.)
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Extract data
    target = meta.get('target', 'unknown')
    provider = meta.get('provider', 'unknown')
    report_file = meta.get('report_file', '')
    tci_score = meta.get('tci_score', 0)
    severity = meta.get('tci_severity', 'unknown')
    
    # Extract open ports and services
    ports = []
    services = []
    for host in scan_data.get('hosts', []):
        for p in host.get('ports', []):
            if p.get('state') == 'open':
                ports.append(str(p.get('portid')))
                services.append(p.get('service', {}).get('name', 'unknown'))
    
    # Extract vulnerabilities (from AI output if available)
    vulns = meta.get('vulnerabilities', [])
    
    # Insert into database
    c.execute('''
        INSERT INTO scans 
        (target, scan_date, tci_score, severity, open_ports, services, vulnerabilities, report_file, provider)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        target,
        datetime.now().isoformat(),
        tci_score,
        severity,
        json.dumps(ports),
        json.dumps(services),
        json.dumps(vulns),
        report_file,
        provider
    ))
    
    conn.commit()
    conn.close()
    logging.debug("Scan result stored in database")


def get_scan_history(target: str, limit: int = 10) -> List[Dict[str, Any]]:
    """
    Get scan history for a target
    
    Args:
        target: Target to query
        limit: Number of recent scans
    
    Returns:
        List of scan records
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    c.execute('''
        SELECT * FROM scans 
        WHERE target = ? 
        ORDER BY scan_date DESC 
        LIMIT ?
    ''', (target, limit))
    
    results = [dict(row) for row in c.fetchall()]
    conn.close()
    return results


def detect_trends(target: str) -> Dict[str, Any]:
    """
    Detect security trends for a target
    
    Args:
        target: Target to analyze
    
    Returns:
        Dict with trend analysis
    """
    history = get_scan_history(target, 5)
    
    if len(history) < 2:
        return {"status": "insufficient_data", "message": "Need at least 2 scans for trend analysis"}
    
    trends = {
        "target": target,
        "scan_count": len(history),
        "first_scan": history[-1]['scan_date'],
        "last_scan": history[0]['scan_date'],
        "tci_trend": [],
        "port_trend": [],
        "severity_trend": []
    }
    
    # Analyze TCI trend
    tci_scores = []
    for record in reversed(history):  # Oldest to newest
        tci_scores.append(record['tci_score'])
        trends['tci_trend'].append({
            'date': record['scan_date'],
            'score': record['tci_score']
        })
    
    # Check if TCI is increasing (security getting worse)
    if len(tci_scores) >= 2:
        if tci_scores[-1] > tci_scores[0]:
            trends['tci_direction'] = 'increasing (complexity up)'
            trends['alert'] = '⚠️ Target complexity is increasing'
        elif tci_scores[-1] < tci_scores[0]:
            trends['tci_direction'] = 'decreasing (complexity down)'
            trends['alert'] = '✅ Target complexity is decreasing'
        else:
            trends['tci_direction'] = 'stable'
            trends['alert'] = 'ℹ️ Target complexity is stable'
    
    # Analyze severity trend
    severities = []
    for record in reversed(history):
        severities.append(record['severity'])
    
    severity_levels = {'minimal': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
    if len(severities) >= 2:
        if severity_levels.get(severities[-1], 0) > severity_levels.get(severities[0], 0):
            trends['severity_direction'] = 'worsening'
        elif severity_levels.get(severities[-1], 0) < severity_levels.get(severities[0], 0):
            trends['severity_direction'] = 'improving'
        else:
            trends['severity_direction'] = 'stable'
    
    # Analyze port count trend
    port_counts = []
    for record in reversed(history):
        ports = json.loads(record['open_ports']) if record['open_ports'] else []
        port_counts.append(len(ports))
        trends['port_trend'].append({
            'date': record['scan_date'],
            'count': len(ports)
        })
    
    if len(port_counts) >= 2:
        if port_counts[-1] > port_counts[0]:
            trends['port_direction'] = 'increasing (attack surface growing)'
        elif port_counts[-1] < port_counts[0]:
            trends['port_direction'] = 'decreasing (attack surface shrinking)'
        else:
            trends['port_direction'] = 'stable'
    
    return trends


def print_trend_report(target: str):
    """Print a formatted trend report for a target"""
    trends = detect_trends(target)
    
    print("\n" + "="*60)
    print(f"📊 Security Trend Analysis for {target}")
    print("="*60)
    
    if trends.get('status') == 'insufficient_data':
        print("⚠️", trends['message'])
        return
    
    print(f"📅 Total Scans: {trends['scan_count']}")
    print(f"🕐 First Scan: {trends['first_scan']}")
    print(f"🕐 Last Scan:  {trends['last_scan']}")
    print("-"*60)
    
    print("\n📈 TCI Score Trend:")
    for entry in trends['tci_trend']:
        print(f"  {entry['date'][:16]} → {entry['score']}/100")
    print(f"  → Direction: {trends.get('tci_direction', 'unknown')}")
    
    print("\n🔌 Open Ports Trend:")
    for entry in trends['port_trend']:
        print(f"  {entry['date'][:16]} → {entry['count']} ports")
    print(f"  → Direction: {trends.get('port_direction', 'unknown')}")
    
    print("\n🎯 Severity Trend:")
    print(f"  → Direction: {trends.get('severity_direction', 'unknown')}")
    
    print("\n" + "-"*60)
    print(f"⚠️ Alert: {trends.get('alert', 'No alerts')}")
    print("="*60)


def test_history_db():
    """Test the history database"""
    init_db()
    
    # Sample data
    sample_scan = {
        'hosts': [
            {
                'address': '192.168.1.100',
                'hostnames': ['test.example.com'],
                'ports': [
                    {'portid': 80, 'state': 'open', 'service': {'name': 'http'}},
                    {'portid': 443, 'state': 'open', 'service': {'name': 'https'}},
                    {'portid': 22, 'state': 'open', 'service': {'name': 'ssh'}},
                ]
            }
        ]
    }
    
    sample_meta = {
        'target': 'test.example.com',
        'provider': 'groq',
        'report_file': 'test-12345.html',
        'tci_score': 45,
        'tci_severity': 'medium',
        'vulnerabilities': ['SQL Injection', 'XSS']
    }
    
    # Store scan
    store_scan_result(sample_scan, sample_meta)
    print("✅ Sample scan stored in database")
    
    # Get history
    history = get_scan_history('test.example.com')
    print(f"📋 Found {len(history)} scans in history")
    
    # Show trend report
    print_trend_report('test.example.com')


if __name__ == "__main__":
    test_history_db()
