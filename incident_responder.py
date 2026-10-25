"""
Module: incident_responder.py
Author: IBM SkillsBuild Cyber Security Team / BharatCares Project
Date: October 2026
Purpose: Automated Incident Response and SOC Playbook generation mapping detections to MITRE ATT&CK.
"""

from typing import Dict, Any, List
import datetime

# MITRE ATT&CK Enterprise Matrix Knowledge Base for detected threat types
MITRE_ATTACK_MAPPING = {
    "DoS_SYN_Flood": {
        "technique_id": "T1498.001",
        "technique_name": "Network Denial of Service: Direct Network Flood",
        "tactic": "Impact",
        "severity": "HIGH",
        "recommended_action": "Apply TCP SYN cookies, rate limit SYN packets at edge gateway, block source IP in iptables.",
        "firewall_rule_template": "iptables -A INPUT -p tcp --syn -s {src_ip} -j DROP"
    },
    "Port_Scan": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
        "severity": "MEDIUM",
        "recommended_action": "Blacklist aggressive scanner IP, disable unused network ports, alert SOC tier 1.",
        "firewall_rule_template": "iptables -I INPUT -s {src_ip} -j REJECT --reject-with icmp-host-prohibited"
    },
    "Brute_Force_SSH": {
        "technique_id": "T1110.001",
        "technique_name": "Brute Force: Password Guessing (SSH Port 22)",
        "tactic": "Credential Access",
        "severity": "HIGH",
        "recommended_action": "Trigger fail2ban jail for source IP, enforce SSH key authentication, disable root login.",
        "firewall_rule_template": "iptables -A INPUT -p tcp --dport 22 -s {src_ip} -j DROP"
    },
    "Web_Attack_SQLi": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application: SQL Injection",
        "tactic": "Initial Access",
        "severity": "CRITICAL",
        "recommended_action": "Engage Web Application Firewall (WAF) rule, inspect HTTP POST payloads, audit SQL queries.",
        "firewall_rule_template": "iptables -A INPUT -p tcp --dport 80,443 -s {src_ip} -j DROP"
    },
    "Botnet_Infiltration": {
        "technique_id": "T1071.001",
        "technique_name": "Application Layer Protocol: Web C2 Beaconing",
        "tactic": "Command and Control",
        "severity": "CRITICAL",
        "recommended_action": "Isolate compromised host endpoint, sever C2 communication channel, capture packet pcap for forensic memory analysis.",
        "firewall_rule_template": "iptables -A FORWARD -s {src_ip} -j DROP"
    },
    "Normal": {
        "technique_id": "None",
        "technique_name": "Legitimate Network Traffic",
        "tactic": "Normal Operations",
        "severity": "LOW",
        "recommended_action": "Permit traffic; continuous baseline logging.",
        "firewall_rule_template": "# No rule needed - Traffic is Benign"
    }
}

class IncidentResponseEngine:
    """
    Automated Incident Responder simulating IBM QRadar SOAR capabilities.
    """

    @staticmethod
    def generate_incident_report(
        attack_type: str, 
        confidence: float, 
        src_ip: str = "192.168.1.105", 
        dst_ip: str = "10.0.0.1"
    ) -> Dict[str, Any]:
        """
        Generates a structured SOC incident response ticket with MITRE ATT&CK telemetry.

        Args:
            attack_type (str): Predicted attack classification.
            confidence (float): Model prediction confidence score (0.0 to 1.0).
            src_ip (str): Simulated source IP address.
            dst_ip (str): Simulated target destination IP.

        Returns:
            Dict[str, Any]: Complete SOC Incident Playbook ticket.
        """
        threat_info = MITRE_ATTACK_MAPPING.get(attack_type, {
            "technique_id": "T1000",
            "technique_name": "Unknown Anomaly / Zero-Day Pattern",
            "tactic": "Defense Evasion",
            "severity": "HIGH",
            "recommended_action": "Quarantine suspicious endpoint and inspect flow pcaps.",
            "firewall_rule_template": "iptables -A INPUT -s {src_ip} -j DROP"
        })

        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        firewall_rule = threat_info["firewall_rule_template"].format(src_ip=src_ip)

        incident = {
            "incident_id": f"SOC-INC-{int(datetime.datetime.now().timestamp() * 1000) % 1000000:06d}",
            "timestamp": timestamp,
            "detected_threat": attack_type,
            "confidence_score": round(confidence * 100, 2),
            "severity": threat_info["severity"],
            "mitre_tactic": threat_info["tactic"],
            "mitre_technique_id": threat_info["technique_id"],
            "mitre_technique_name": threat_info["technique_name"],
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "recommended_containment": threat_info["recommended_action"],
            "automated_firewall_mitigation": firewall_rule
        }
        return incident
