# Kestrel — LLM-assisted bug bounty hunting platform
# Copyright (C) 2026 David Kuznicki and Kestrel Contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

"""
Kestrel Session Management

Tracks the state of hunting sessions, findings, and execution history.
"""

import uuid
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Any
from enum import Enum
from pathlib import Path


class SessionState(Enum):
    """State of a hunting session."""
    CREATED = "created"
    READY = "ready"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    ERROR = "error"


class FindingSeverity(Enum):
    """Severity levels for findings."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    
    @property
    def numeric(self) -> int:
        """Get numeric value for sorting."""
        return {
            "info": 0,
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
        }[self.value]


@dataclass
class Finding:
    """A security finding discovered during a hunt."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    title: str = ""
    description: str = ""
    severity: FindingSeverity = FindingSeverity.INFO
    tool: str = ""
    target: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    
    # Additional context
    uri: Optional[str] = None
    evidence: Optional[str] = None
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    
    # Exploitation status
    exploitable: bool = False
    exploit_verified: bool = False
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "tool": self.tool,
            "target": self.target,
            "timestamp": self.timestamp.isoformat(),
            "uri": self.uri,
            "evidence": self.evidence,
            "cve_id": self.cve_id,
            "cvss_score": self.cvss_score,
            "exploitable": self.exploitable,
            "exploit_verified": self.exploit_verified,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        """Create from dictionary."""
        return cls(
            id=data.get("id", str(uuid.uuid4())[:8]),
            title=data.get("title", ""),
            description=data.get("description", ""),
            severity=FindingSeverity(data.get("severity", "info")),
            tool=data.get("tool", ""),
            target=data.get("target", ""),
            timestamp=datetime.fromisoformat(data["timestamp"]) if "timestamp" in data else datetime.now(),
            uri=data.get("uri"),
            evidence=data.get("evidence"),
            cve_id=data.get("cve_id"),
            cvss_score=data.get("cvss_score"),
            exploitable=data.get("exploitable", False),
            exploit_verified=data.get("exploit_verified", False),
        )


@dataclass
class ExecutionRecord:
    """Record of a command execution."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    tool: str = ""
    command: str = ""
    target: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    
    # Results
    success: bool = False
    exit_code: Optional[int] = None
    duration_seconds: float = 0.0
    output_summary: str = ""  # Truncated output
    findings_count: int = 0
    
    # Authorization tracking
    authorized: bool = False
    authorized_by: str = "user"
    authorized_at: Optional[datetime] = None
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "tool": self.tool,
            "command": self.command,
            "target": self.target,
            "timestamp": self.timestamp.isoformat(),
            "success": self.success,
            "exit_code": self.exit_code,
            "duration_seconds": self.duration_seconds,
            "output_summary": self.output_summary,
            "findings_count": self.findings_count,
            "authorized": self.authorized,
            "authorized_by": self.authorized_by,
            "authorized_at": self.authorized_at.isoformat() if self.authorized_at else None,
        }


@dataclass
class HuntSession:
    """
    A hunting session tracking state and progress.
    
    Represents a single bounty hunting engagement on a program/target.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    state: SessionState = SessionState.CREATED
    
    # Target info
    program_id: Optional[str] = None
    program_name: Optional[str] = None
    platform: Optional[str] = None
    target: str = ""
    
    # Timestamps
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    
    # Progress tracking
    current_phase: str = "init"
    progress_percent: int = 0
    
    # Collections
    findings: list[Finding] = field(default_factory=list)
    executions: list[ExecutionRecord] = field(default_factory=list)
    
    # Metadata
    notes: str = ""
    tags: list[str] = field(default_factory=list)
    
    def start(self) -> None:
        """Mark session as started."""
        self.state = SessionState.RUNNING
        self.started_at = datetime.now()
        self.current_phase = "recon"
    
    def pause(self) -> None:
        """Pause the session."""
        self.state = SessionState.PAUSED
    
    def resume(self) -> None:
        """Resume the session."""
        self.state = SessionState.RUNNING
    
    def complete(self) -> None:
        """Mark session as completed."""
        self.state = SessionState.COMPLETED
        self.completed_at = datetime.now()
        self.progress_percent = 100
    
    def error(self, message: str) -> None:
        """Mark session as errored."""
        self.state = SessionState.ERROR
        self.notes += f"\n[ERROR] {message}"
    
    def add_finding(self, finding: Finding) -> None:
        """Add a finding to the session."""
        finding.target = finding.target or self.target
        self.findings.append(finding)
    
    def add_execution(self, execution: ExecutionRecord) -> None:
        """Add an execution record."""
        self.executions.append(execution)
    
    def get_findings_by_severity(self, severity: FindingSeverity) -> list[Finding]:
        """Get findings filtered by severity."""
        return [f for f in self.findings if f.severity == severity]
    
    def get_critical_findings(self) -> list[Finding]:
        """Get critical and high severity findings."""
        return [
            f for f in self.findings
            if f.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH)
        ]
    
    def get_exploitable_findings(self) -> list[Finding]:
        """Get findings marked as exploitable."""
        return [f for f in self.findings if f.exploitable]
    
    @property
    def duration_seconds(self) -> float:
        """Get session duration in seconds."""
        if not self.started_at:
            return 0.0
        
        end_time = self.completed_at or datetime.now()
        return (end_time - self.started_at).total_seconds()
    
    @property
    def finding_counts(self) -> dict[str, int]:
        """Get counts of findings by severity."""
        counts = {sev.value: 0 for sev in FindingSeverity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts
    
    def get_context_for_llm(self) -> str:
        """
        Build context string for LLM prompts.
        
        Returns:
            Formatted context about the session state
        """
        lines = [
            f"# Hunt Session Context",
            f"",
            f"## Target",
            f"- Program: {self.program_name or 'Unknown'}",
            f"- Platform: {self.platform or 'Unknown'}",
            f"- Target: {self.target}",
            f"- Phase: {self.current_phase}",
            f"",
        ]
        
        if self.findings:
            lines.append(f"## Findings ({len(self.findings)} total)")
            for finding in sorted(
                self.findings,
                key=lambda f: f.severity.numeric,
                reverse=True
            )[:10]:  # Top 10 by severity
                lines.append(
                    f"- [{finding.severity.value.upper()}] {finding.title}"
                )
                if finding.evidence:
                    lines.append(f"  Evidence: {finding.evidence[:100]}")
            lines.append("")
        
        if self.executions:
            lines.append(f"## Recent Commands ({len(self.executions)} total)")
            for exec_rec in self.executions[-5:]:  # Last 5
                status = "✓" if exec_rec.success else "✗"
                lines.append(
                    f"- {status} {exec_rec.tool}: {exec_rec.command[:60]}..."
                )
            lines.append("")
        
        return "\n".join(lines)
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "name": self.name,
            "state": self.state.value,
            "program_id": self.program_id,
            "program_name": self.program_name,
            "platform": self.platform,
            "target": self.target,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "current_phase": self.current_phase,
            "progress_percent": self.progress_percent,
            "findings": [f.to_dict() for f in self.findings],
            "executions": [e.to_dict() for e in self.executions],
            "notes": self.notes,
            "tags": self.tags,
            "duration_seconds": self.duration_seconds,
            "finding_counts": self.finding_counts,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "HuntSession":
        """Create from dictionary."""
        session = cls(
            id=data.get("id", str(uuid.uuid4())),
            name=data.get("name", ""),
            state=SessionState(data.get("state", "created")),
            program_id=data.get("program_id"),
            program_name=data.get("program_name"),
            platform=data.get("platform"),
            target=data.get("target", ""),
            current_phase=data.get("current_phase", "init"),
            progress_percent=data.get("progress_percent", 0),
            notes=data.get("notes", ""),
            tags=data.get("tags", []),
        )
        
        if data.get("created_at"):
            session.created_at = datetime.fromisoformat(data["created_at"])
        if data.get("started_at"):
            session.started_at = datetime.fromisoformat(data["started_at"])
        if data.get("completed_at"):
            session.completed_at = datetime.fromisoformat(data["completed_at"])
        
        for f_data in data.get("findings", []):
            session.findings.append(Finding.from_dict(f_data))
        
        return session
    
    def save(self, path: Path) -> None:
        """Save session to JSON file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)
    
    @classmethod
    def load(cls, path: Path) -> "HuntSession":
        """Load session from JSON file."""
        with open(path) as f:
            return cls.from_dict(json.load(f))


class SessionManager:
    """
    Manages multiple hunting sessions.
    """
    
    def __init__(self, storage_dir: Optional[Path] = None):
        """
        Initialize the session manager.
        
        Args:
            storage_dir: Directory to store session files
        """
        self.storage_dir = storage_dir or Path.home() / ".local" / "share" / "kestrel" / "sessions"
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        self._active_session: Optional[HuntSession] = None
        self._sessions: dict[str, HuntSession] = {}
    
    @property
    def active_session(self) -> Optional[HuntSession]:
        """Get the currently active session."""
        return self._active_session
    
    def create_session(
        self,
        target: str,
        name: Optional[str] = None,
        program_id: Optional[str] = None,
        program_name: Optional[str] = None,
        platform: Optional[str] = None,
    ) -> HuntSession:
        """
        Create a new hunting session.
        
        Args:
            target: Primary target for the hunt
            name: Session name (auto-generated if not provided)
            program_id: Bug bounty program ID
            program_name: Program display name
            platform: Platform name (hackerone, bugcrowd, etc.)
            
        Returns:
            New HuntSession
        """
        session = HuntSession(
            name=name or f"Hunt on {target}",
            target=target,
            program_id=program_id,
            program_name=program_name,
            platform=platform,
            state=SessionState.READY,
        )
        
        self._sessions[session.id] = session
        self._active_session = session
        
        return session
    
    def get_session(self, session_id: str) -> Optional[HuntSession]:
        """Get a session by ID."""
        # Check in-memory first
        if session_id in self._sessions:
            return self._sessions[session_id]
        
        # Try to load from disk
        session_path = self.storage_dir / f"{session_id}.json"
        if session_path.exists():
            session = HuntSession.load(session_path)
            self._sessions[session_id] = session
            return session
        
        return None
    
    def set_active(self, session_id: str) -> bool:
        """Set the active session."""
        session = self.get_session(session_id)
        if session:
            self._active_session = session
            return True
        return False
    
    def save_session(self, session: HuntSession) -> None:
        """Save a session to disk."""
        session_path = self.storage_dir / f"{session.id}.json"
        session.save(session_path)
    
    def save_active(self) -> None:
        """Save the active session."""
        if self._active_session:
            self.save_session(self._active_session)
    
    def list_sessions(self) -> list[dict]:
        """
        List all available sessions.
        
        Returns:
            List of session summaries
        """
        sessions = []
        
        # In-memory sessions
        for session in self._sessions.values():
            sessions.append({
                "id": session.id,
                "name": session.name,
                "state": session.state.value,
                "target": session.target,
                "program_name": session.program_name,
                "created_at": session.created_at.isoformat(),
                "findings_count": len(session.findings),
            })
        
        # Saved sessions not in memory
        for session_file in self.storage_dir.glob("*.json"):
            session_id = session_file.stem
            if session_id not in self._sessions:
                try:
                    session = HuntSession.load(session_file)
                    sessions.append({
                        "id": session.id,
                        "name": session.name,
                        "state": session.state.value,
                        "target": session.target,
                        "program_name": session.program_name,
                        "created_at": session.created_at.isoformat(),
                        "findings_count": len(session.findings),
                    })
                except Exception:
                    pass
        
        return sorted(sessions, key=lambda s: s["created_at"], reverse=True)
