"""
Kestrel LLM Prompts

System prompts and templates for LLM-assisted operations.
"""

from typing import Optional, Any


def build_translation_prompt(
    intent: str,
    tools: list[dict],
    target: Optional[str] = None,
    context: Optional[str] = None,
) -> tuple[str, str]:
    """
    Build prompts for translating natural language intent to tool request.
    
    Args:
        intent: User's natural language intent
        tools: List of available tool schemas
        target: Known target (optional)
        context: Session context (optional)
        
    Returns:
        Tuple of (system_prompt, user_prompt)
    """
    # Build tool descriptions
    tool_desc = "\n".join([
        f"- {t['name']}: {t.get('description', 'No description')}"
        for t in tools
    ])
    
    system_prompt = f"""You are a security tool translator. Your job is to convert natural language security testing requests into structured tool commands.

Available tools:
{tool_desc}

You must respond with a JSON object containing:
- "tool": The tool name to use
- "target": The target to scan
- "options": Tool-specific options as key-value pairs
- "reasoning": Brief explanation of your choice

Rules:
1. Choose the most appropriate tool for the task
2. Use sensible defaults for options not specified
3. Never include dangerous options without explicit request
4. If the intent is unclear, ask for clarification

Return ONLY valid JSON, no markdown or explanation outside the JSON."""

    user_prompt = f"Intent: {intent}"
    
    if target:
        user_prompt += f"\nKnown target: {target}"
    
    if context:
        user_prompt += f"\n\nSession context:\n{context}"
    
    return system_prompt, user_prompt


def build_analysis_prompt(
    findings: list[dict],
    analysis_type: str = "vulnerability",
) -> tuple[str, str]:
    """
    Build prompts for analyzing scan findings.
    
    Args:
        findings: List of findings to analyze
        analysis_type: Type of analysis to perform
        
    Returns:
        Tuple of (system_prompt, user_prompt)
    """
    system_prompt = """You are a security analyst reviewing scan findings.

Your task is to:
1. Identify potential vulnerabilities
2. Assess severity (critical, high, medium, low, info)
3. Correlate with known CVEs where possible
4. Suggest follow-up actions

Respond with a JSON object containing:
- "analysis": Your detailed analysis
- "vulnerabilities": List of identified vulnerabilities with severity
- "cve_matches": Any potential CVE matches
- "next_steps": Suggested follow-up actions

Be specific and actionable. Return ONLY valid JSON."""

    findings_text = "\n".join([
        f"- [{f.get('severity', 'info')}] {f.get('title', 'Unknown')}: {f.get('description', '')}"
        for f in findings
    ])
    
    user_prompt = f"Analyze these security scan findings:\n\n{findings_text}"
    
    return system_prompt, user_prompt


def build_exploit_planning_prompt(
    vulnerability: dict,
    target: str,
    context: Optional[str] = None,
) -> tuple[str, str]:
    """
    Build prompts for exploit planning.
    
    Args:
        vulnerability: Vulnerability details
        target: Target system
        context: Additional context
        
    Returns:
        Tuple of (system_prompt, user_prompt)
    """
    system_prompt = """You are a security researcher planning a controlled exploitation attempt.

IMPORTANT: This is for AUTHORIZED bug bounty testing only. 
All exploit attempts require explicit user authorization.

Your task is to:
1. Analyze the vulnerability
2. Research exploitation techniques
3. Create a step-by-step exploit plan
4. Assess risks and potential impact
5. Provide exact commands to execute

Respond with a JSON object containing:
- "vulnerability_summary": Brief summary of the vulnerability
- "exploit_type": Type of exploitation (e.g., "path_traversal", "sqli", "rce")
- "steps": Array of steps, each with:
  - "description": What this step does
  - "command": Exact command to run
  - "expected_output": What to look for
  - "risk_level": "low", "medium", or "high"
- "success_indicators": How to confirm successful exploitation
- "risk_assessment": Overall risk assessment
- "estimated_impact": Potential impact if successful

Be precise with commands. Return ONLY valid JSON."""

    vuln_text = f"""
Vulnerability: {vulnerability.get('title', 'Unknown')}
CVE: {vulnerability.get('cve_id', 'N/A')}
Severity: {vulnerability.get('severity', 'Unknown')}
Description: {vulnerability.get('description', 'No description')}
Target: {target}
Evidence: {vulnerability.get('evidence', 'None')}
"""
    
    user_prompt = f"Plan an exploitation approach for:\n{vuln_text}"
    
    if context:
        user_prompt += f"\n\nAdditional context:\n{context}"
    
    return system_prompt, user_prompt


def build_report_prompt(
    vulnerability: dict,
    exploit_result: dict,
    platform: str = "hackerone",
) -> tuple[str, str]:
    """
    Build prompts for generating submission reports.
    
    Args:
        vulnerability: Vulnerability details
        exploit_result: Results of exploitation attempt
        platform: Target platform format
        
    Returns:
        Tuple of (system_prompt, user_prompt)
    """
    platform_guidance = {
        "hackerone": """Format for HackerOne:
- Use markdown formatting
- Include: Summary, Severity, Steps to Reproduce, Impact, Remediation
- Be concise but complete
- Include all relevant evidence""",
        
        "bugcrowd": """Format for Bugcrowd:
- Use their standard template structure
- Include: Title, Description, Steps, Impact, Attachments
- Focus on clear reproduction steps""",
    }
    
    system_prompt = f"""You are a professional bug bounty report writer.

{platform_guidance.get(platform, platform_guidance['hackerone'])}

Generate a complete, submission-ready report based on the provided vulnerability and exploitation results.

The report should be professional, clear, and include all necessary details for the security team to understand and reproduce the issue.

Return the report as plain markdown text, ready to copy and submit."""

    user_prompt = f"""Generate a bug bounty report for:

Vulnerability:
- Title: {vulnerability.get('title', 'Unknown')}
- CVE: {vulnerability.get('cve_id', 'N/A')}
- Severity: {vulnerability.get('severity', 'Unknown')}
- Description: {vulnerability.get('description', '')}

Exploitation Result:
- Success: {exploit_result.get('success', False)}
- Evidence: {exploit_result.get('evidence', 'None')}
- Commands Used: {exploit_result.get('commands', [])}
- Output: {exploit_result.get('output', '')[:1000]}
"""
    
    return system_prompt, user_prompt


def build_cve_correlation_prompt(
    fingerprint: dict,
) -> tuple[str, str]:
    """
    Build prompts for CVE correlation.
    
    Args:
        fingerprint: Service fingerprint data
        
    Returns:
        Tuple of (system_prompt, user_prompt)
    """
    system_prompt = """You are a security researcher correlating service fingerprints with known CVEs.

Given a service fingerprint (product name, version), identify:
1. Known CVEs affecting this version
2. Severity of each CVE
3. Whether public exploits exist
4. Upgrade path recommendations

Respond with a JSON object containing:
- "product": Normalized product name
- "version": Version string
- "cves": Array of CVE objects with:
  - "id": CVE ID
  - "severity": "critical", "high", "medium", "low"
  - "description": Brief description
  - "exploitable": boolean indicating if public exploits exist
  - "cvss": CVSS score if known
- "recommendation": Upgrade/mitigation recommendation

Focus on HIGH and CRITICAL severity CVEs. Return ONLY valid JSON."""

    fingerprint_text = f"""
Product: {fingerprint.get('product', 'Unknown')}
Version: {fingerprint.get('version', 'Unknown')}
Service: {fingerprint.get('service', 'Unknown')}
Additional Info: {fingerprint.get('extra_info', 'None')}
"""
    
    user_prompt = f"Find CVEs for this service fingerprint:\n{fingerprint_text}"
    
    return system_prompt, user_prompt
