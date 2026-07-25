"""Unified reporting engine: findings + text/json/html renderers.

Every module produces `Finding` objects and hands them to `Report`, which can
render to the terminal, JSON (for pipelines), or a self-contained HTML file.
"""

from __future__ import annotations

import html
import json
import time
from dataclasses import asdict, dataclass, field
from enum import Enum


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


class Status(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    INFO = "info"


_SEV_COLOR = {
    "info": "\033[36m",
    "low": "\033[32m",
    "medium": "\033[33m",
    "high": "\033[31m",
    "critical": "\033[1;31m",
}
_STATUS_COLOR = {
    "pass": "\033[32m",
    "fail": "\033[31m",
    "warn": "\033[33m",
    "info": "\033[36m",
}
_RESET = "\033[0m"


@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    status: Status
    detail: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["status"] = self.status.value
        return d


@dataclass
class Report:
    module: str
    target: str
    findings: list[Finding] = field(default_factory=list)
    generated_at: float = field(default_factory=time.time)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    # ---- summaries -------------------------------------------------------
    def counts_by_severity(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            if f.status in (Status.FAIL, Status.WARN):
                counts[f.severity.value] += 1
        return counts

    def counts_by_status(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Status}
        for f in self.findings:
            counts[f.status.value] += 1
        return counts

    # ---- renderers -------------------------------------------------------
    def to_json(self) -> str:
        return json.dumps(
            {
                "module": self.module,
                "target": self.target,
                "generated_at": self.generated_at,
                "summary": {
                    "by_status": self.counts_by_status(),
                    "by_severity": self.counts_by_severity(),
                },
                "findings": [f.as_dict() for f in self.findings],
            },
            indent=2,
        )

    def to_text(self, color: bool = True) -> str:
        def c(code: str, text: str) -> str:
            return f"{code}{text}{_RESET}" if color else text

        lines: list[str] = []
        bar = "=" * 72
        lines.append(bar)
        lines.append(f" outcats :: {self.module}  |  target: {self.target}")
        lines.append(bar)

        ordered = sorted(
            self.findings, key=lambda f: (-f.severity.rank, f.status.value)
        )
        for f in ordered:
            sc = _STATUS_COLOR.get(f.status.value, "")
            vc = _SEV_COLOR.get(f.severity.value, "")
            tag = c(sc, f"[{f.status.value.upper():4}]")
            sev = c(vc, f"{f.severity.value.upper():8}")
            lines.append(f"{tag} {sev} {f.id}  {f.title}")
            if f.detail:
                lines.append(f"          {f.detail}")
            if f.status in (Status.FAIL, Status.WARN) and f.remediation:
                lines.append(f"          fix: {f.remediation}")
            if f.references:
                lines.append(f"          refs: {', '.join(f.references)}")
        lines.append("-" * 72)
        st = self.counts_by_status()
        sv = self.counts_by_severity()
        lines.append(
            f" pass={st['pass']} fail={st['fail']} warn={st['warn']} info={st['info']}"
            f"   |   critical={sv['critical']} high={sv['high']} "
            f"medium={sv['medium']} low={sv['low']}"
        )
        lines.append(bar)
        return "\n".join(lines)

    def to_html(self) -> str:
        st = self.counts_by_status()
        sv = self.counts_by_severity()
        rows = []
        ordered = sorted(
            self.findings, key=lambda f: (-f.severity.rank, f.status.value)
        )
        for f in ordered:
            rows.append(
                "<tr class='{sevcls}'>"
                "<td><span class='status {stcls}'>{st}</span></td>"
                "<td><span class='sev {sevcls}'>{sev}</span></td>"
                "<td class='mono'>{fid}</td>"
                "<td>{title}<div class='detail'>{detail}</div>"
                "{fix}{refs}</td>"
                "</tr>".format(
                    sevcls=f.severity.value,
                    stcls=f.status.value,
                    st=f.status.value.upper(),
                    sev=f.severity.value.upper(),
                    fid=html.escape(f.id),
                    title=html.escape(f.title),
                    detail=html.escape(f.detail),
                    fix=(
                        f"<div class='fix'>fix: {html.escape(f.remediation)}</div>"
                        if f.remediation and f.status in (Status.FAIL, Status.WARN)
                        else ""
                    ),
                    refs=(
                        "<div class='refs'>"
                        + ", ".join(html.escape(r) for r in f.references)
                        + "</div>"
                        if f.references
                        else ""
                    ),
                )
            )
        generated = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.generated_at))
        return _HTML_TEMPLATE.format(
            module=html.escape(self.module),
            target=html.escape(self.target),
            generated=generated,
            passc=st["pass"],
            failc=st["fail"],
            warnc=st["warn"],
            crit=sv["critical"],
            high=sv["high"],
            med=sv["medium"],
            low=sv["low"],
            rows="\n".join(rows),
        )


_HTML_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>outcats report - {module}</title>
<style>
 body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#0f1117;color:#e6e6e6}}
 header{{padding:24px 32px;background:#161923;border-bottom:1px solid #262a36}}
 h1{{margin:0;font-size:20px}} .meta{{color:#8b93a7;font-size:13px;margin-top:6px}}
 .cards{{display:flex;gap:12px;padding:20px 32px;flex-wrap:wrap}}
 .card{{background:#161923;border:1px solid #262a36;border-radius:10px;padding:14px 18px;min-width:96px}}
 .card .n{{font-size:26px;font-weight:700}} .card .l{{font-size:12px;color:#8b93a7}}
 table{{width:calc(100% - 64px);margin:12px 32px 40px;border-collapse:collapse;font-size:14px}}
 th,td{{text-align:left;padding:10px 12px;border-bottom:1px solid #222634;vertical-align:top}}
 th{{color:#8b93a7;font-weight:600;font-size:12px;text-transform:uppercase}}
 .mono{{font-family:ui-monospace,Menlo,monospace;color:#9cd}}
 .detail{{color:#9aa3b6;font-size:13px;margin-top:4px}}
 .fix{{color:#7fd18c;font-size:13px;margin-top:4px}}
 .refs{{color:#6f7891;font-size:12px;margin-top:4px}}
 .status,.sev{{padding:2px 8px;border-radius:6px;font-size:11px;font-weight:700}}
 .status.pass{{background:#12351f;color:#7fd18c}} .status.fail{{background:#3a1518;color:#f28b82}}
 .status.warn{{background:#3a3312;color:#f2d16b}} .status.info{{background:#12303a;color:#7cc7e0}}
 .sev.critical{{background:#4a1015;color:#ff8a8a}} .sev.high{{background:#3a1518;color:#f28b82}}
 .sev.medium{{background:#3a3312;color:#f2d16b}} .sev.low{{background:#12351f;color:#7fd18c}}
 .sev.info{{background:#12303a;color:#7cc7e0}}
</style></head><body>
<header><h1>outcats report &middot; {module}</h1>
<div class="meta">target: {target} &nbsp;|&nbsp; generated: {generated}</div></header>
<div class="cards">
 <div class="card"><div class="n" style="color:#7fd18c">{passc}</div><div class="l">PASS</div></div>
 <div class="card"><div class="n" style="color:#f28b82">{failc}</div><div class="l">FAIL</div></div>
 <div class="card"><div class="n" style="color:#f2d16b">{warnc}</div><div class="l">WARN</div></div>
 <div class="card"><div class="n" style="color:#ff8a8a">{crit}</div><div class="l">CRITICAL</div></div>
 <div class="card"><div class="n" style="color:#f28b82">{high}</div><div class="l">HIGH</div></div>
 <div class="card"><div class="n" style="color:#f2d16b">{med}</div><div class="l">MEDIUM</div></div>
 <div class="card"><div class="n" style="color:#7fd18c">{low}</div><div class="l">LOW</div></div>
</div>
<table><thead><tr><th>Status</th><th>Severity</th><th>ID</th><th>Finding</th></tr></thead>
<tbody>
{rows}
</tbody></table>
</body></html>
"""
