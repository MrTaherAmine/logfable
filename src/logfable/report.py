from __future__ import annotations

import html
import json
from collections import Counter
from pathlib import Path
from typing import Any, cast

from .branding import AUTHOR, COPYRIGHT, GITHUB_HANDLE, WEBSITE
from .models import CanonicalEvent, Scenario


def _esc(value: object) -> str:
    return html.escape(str(value))


def _table_rows(items: dict[str, object]) -> str:
    return "".join(f"<tr><td>{_esc(k)}</td><td>{_esc(v)}</td></tr>" for k, v in items.items())


def generate_report(
    path: Path,
    s: Scenario,
    events: list[CanonicalEvent],
    manifest: dict[str, Any],
    quality: dict[str, Any],
    *,
    student_safe: bool,
) -> None:
    counts = Counter(e.source_family for e in events)
    categories = Counter(e.category for e in events)
    top = sorted(events, key=lambda e: (-e.severity, e.event_time, e.event_id))[:14]
    hourly = Counter(e.event_time.strftime("%Y-%m-%d %H:00Z") for e in events)
    max_hour = max(hourly.values(), default=1)

    # fmt: off
    source_rows = "".join(
        f"<tr><td>{_esc(k)}</td><td>{v}</td><td><div class='bar' style='--w:{max(2, round(v/max(counts.values())*100))}%'></div></td></tr>"
        for k, v in counts.most_common()
    )
    volume_rows = "".join(
        f"<tr><td><time>{_esc(k)}</time></td><td>{v}</td><td><div class='bar' style='--w:{max(2, round(v/max_hour*100))}%'></div></td></tr>"
        for k, v in sorted(hourly.items())
    )
    timeline = "".join(
        f"<li><time>{_esc(e.event_time.isoformat())}</time><strong>{_esc(e.source_family)}</strong>"
        f"<span><b>sev {e.severity}</b> · {_esc(e.message)}</span></li>"
        for e in top
    )
    questions = "".join(f"<li>{_esc(q)}</li>" for q in s.questions)
    env_raw = manifest.get("environment", {})
    env = cast(dict[str, Any], env_raw) if isinstance(env_raw, dict) else {}
    entity_kinds_raw = env.get("entity_kinds", {})
    relationship_kinds_raw = env.get("relationship_kinds", {})
    entity_kinds = cast(dict[str, object], entity_kinds_raw) if isinstance(entity_kinds_raw, dict) else {}
    relationship_kinds = (
        cast(dict[str, object], relationship_kinds_raw)
        if isinstance(relationship_kinds_raw, dict)
        else {}
    )
    entity_rows = _table_rows(entity_kinds)
    relationship_rows = _table_rows(relationship_kinds)
    category_rows = _table_rows(dict(categories.most_common()))

    instructor_sections = ""
    if not student_safe:
        step_rows = []
        attack_rows = []
        d3_rows = []
        detection_rows = []
        for index, step in enumerate(s.steps, 1):
            attack_ids = ", ".join(m.technique_id for m in step.attack) or "—"
            evidence = ", ".join(sorted({e.source for e in step.evidence})) or "—"
            step_rows.append(
                f"<tr><td>{index}</td><td>{_esc(step.title)}</td><td><code>{_esc(step.id)}</code></td>"
                f"<td>{_esc(attack_ids)}</td><td>{_esc(evidence)}</td></tr>"
            )
            for attack_mapping in step.attack:
                attack_rows.append(
                    f"<tr><td><code>{_esc(attack_mapping.technique_id)}</code></td><td>{_esc(attack_mapping.tactic)}</td>"
                    f"<td>{_esc(step.id)}</td><td>{_esc(attack_mapping.rationale)}</td><td>{_esc(attack_mapping.confidence)}</td></tr>"
                )
            for d3fend_mapping in step.d3fend:
                d3_rows.append(
                    f"<tr><td><code>{_esc(d3fend_mapping.d3fend_id)}</code></td><td>{_esc(step.id)}</td>"
                    f"<td>{_esc(d3fend_mapping.mapping_type)}</td><td>{_esc(d3fend_mapping.rationale)}</td><td>{_esc(d3fend_mapping.confidence)}</td></tr>"
                )
            if step.expected_detections:
                detection_rows.append(
                    f"<tr><td>{_esc(step.id)}</td><td>{_esc(', '.join(step.expected_detections))}</td>"
                    f"<td>{_esc(evidence)}</td></tr>"
                )
        impairments = json.dumps(s.impairments or {"configured": False}, indent=2, sort_keys=True)
        benchmark_section = ""
        benchmark_path = path.parent / "benchmark.json"
        if benchmark_path.exists():
            try:
                benchmark_raw: object = json.loads(benchmark_path.read_text(encoding="utf-8"))
                if not isinstance(benchmark_raw, dict):
                    raise TypeError("benchmark report must be a JSON object")
                bm = cast(dict[str, Any], benchmark_raw)
                look_raw = bm.get("benign_lookalikes", {})
                ttd_raw = bm.get("time_to_detect_seconds", {})
                look = cast(dict[str, Any], look_raw) if isinstance(look_raw, dict) else {}
                ttd = cast(dict[str, Any], ttd_raw) if isinstance(ttd_raw, dict) else {}
                benchmark_section = f"""
<section aria-labelledby='benchmark'><div class='eyebrow'>Instructor · measured detection results</div><h2 id='benchmark'>Detection benchmark results</h2>
<div class='grid'><div><div class='metric'>{_esc(bm.get('true_positives',0))}</div><div>true positives</div></div><div><div class='metric'>{_esc(bm.get('false_positives',0))}</div><div>false positives</div></div><div><div class='metric'>{_esc(bm.get('false_negatives',0))}</div><div>false negatives</div></div><div><div class='metric'>{_esc(bm.get('f1',0))}</div><div>F1 score</div></div></div>
<p><strong>Precision:</strong> {_esc(bm.get('precision',0))} · <strong>Recall:</strong> {_esc(bm.get('recall',0))} · <strong>Mean TTD:</strong> {_esc(ttd.get('mean'))} s · <strong>Median TTD:</strong> {_esc(ttd.get('median'))} s</p>
<p><strong>Benign-lookalike false positives:</strong> {_esc(look.get('false_positive_alerts',0))} / {_esc(look.get('events',0))} ({_esc(look.get('false_positive_rate',0))})</p>
<p class='muted'>These are measured against the imported alert set for this synthetic run; they are not claims about a product outside this dataset.</p></section>
"""
            except (OSError, json.JSONDecodeError, TypeError):
                benchmark_section = ""
        instructor_sections = f"""
<section aria-labelledby='progression'><div class='eyebrow'>Instructor · incident plan</div><h2 id='progression'>Attack-stage progression</h2>
<table><thead><tr><th>#</th><th>Step</th><th>ID</th><th>ATT&amp;CK</th><th>Evidence sources</th></tr></thead><tbody>{''.join(step_rows)}</tbody></table></section>
<section aria-labelledby='attack'><div class='eyebrow'>Instructor · framework coverage</div><h2 id='attack'>ATT&amp;CK expected-observable coverage</h2>
<p class='muted'>Mappings describe expected observable evidence. They are not proof that a detection fires.</p>
<table><thead><tr><th>Technique</th><th>Tactic</th><th>Step</th><th>Rationale</th><th>Confidence</th></tr></thead><tbody>{''.join(attack_rows)}</tbody></table></section>
<section aria-labelledby='d3'><div class='eyebrow'>Instructor · defensive opportunities</div><h2 id='d3'>MITRE D3FEND opportunities</h2>
<p class='muted'>Inferred or project-curated relationships remain qualified; no mitigation guarantee is implied.</p>
<table><thead><tr><th>D3FEND</th><th>Step</th><th>Mapping type</th><th>Rationale</th><th>Confidence</th></tr></thead><tbody>{''.join(d3_rows)}</tbody></table></section>
<section aria-labelledby='detect'><div class='eyebrow'>Instructor · detection engineering</div><h2 id='detect'>Expected detection opportunities</h2>
<table><thead><tr><th>Step</th><th>Expected detections</th><th>Required sources</th></tr></thead><tbody>{''.join(detection_rows)}</tbody></table>
<p class='muted'>Run <code>logfable benchmark</code> with an alert export to create machine-readable and Markdown benchmark results.</p></section>
<section aria-labelledby='visibility'><div class='eyebrow'>Instructor · visibility</div><h2 id='visibility'>Telemetry impairments</h2><pre>{_esc(impairments)}</pre></section>
<section aria-labelledby='truth'><div class='eyebrow'>Instructor</div><h2 id='truth'>Ground truth summary</h2><pre>{_esc(json.dumps(manifest.get('ground_truth_summary',{}),indent=2,sort_keys=True))}</pre></section>
{benchmark_section}
"""

    css = """
:root{color-scheme:dark light;--bg:#08111f;--card:#101a2d;--card2:#0c1627;--text:#edf4ff;--muted:#9cafc9;--line:#273652;--accent:#67e8f9;--accent2:#818cf8;--good:#6ee7b7}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:radial-gradient(circle at 20% 0,#15254b 0,transparent 32rem),var(--bg);color:var(--text);line-height:1.55}main{max-width:1180px;margin:auto;padding:34px}.skip{position:absolute;left:-9999px}.skip:focus{left:1rem;top:1rem;background:var(--card);padding:.7rem 1rem;z-index:3}header,section{background:linear-gradient(180deg,rgba(255,255,255,.025),transparent),var(--card);border:1px solid var(--line);border-radius:20px;padding:26px;margin:18px 0;box-shadow:0 16px 50px rgba(0,0,0,.12)}header{padding:34px}h1{font-size:clamp(2.2rem,5vw,4.4rem);line-height:1.02;margin:.12em 0 .3em;letter-spacing:-.04em}h2{font-size:1.55rem;margin:.25rem 0 1rem}.eyebrow{color:var(--accent);text-transform:uppercase;letter-spacing:.14em;font-size:.76rem;font-weight:800}.muted{color:var(--muted)}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(175px,1fr));gap:12px;background:none;border:0;padding:0;box-shadow:none}.grid>div{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:20px}.metric{font-size:2.15rem;font-weight:850;letter-spacing:-.04em}.twocol{display:grid;grid-template-columns:1fr 1fr;gap:18px}.twocol>div{min-width:0}table{width:100%;border-collapse:collapse;font-size:.94rem}td,th{padding:10px 8px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}th{color:var(--muted);font-weight:700}.bar{height:.5rem;border-radius:999px;background:linear-gradient(90deg,var(--accent2),var(--accent));width:var(--w);min-width:4px}.timeline{list-style:none;padding:0;margin:0}.timeline li{display:grid;grid-template-columns:minmax(210px,.85fr) 150px 2fr;gap:12px;padding:10px 0;border-bottom:1px solid var(--line)}.timeline b{color:var(--good);font-size:.8rem}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:var(--card2);padding:15px;border-radius:13px;border:1px solid var(--line);font-size:.85rem}code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--accent)}footer{color:var(--muted);padding:24px 4px 40px;text-align:center;font-size:.9rem}
@media(prefers-color-scheme:light){:root{--bg:#f5f7fb;--card:#fff;--card2:#f2f5fa;--text:#0f172a;--muted:#5b6b82;--line:#d8dfeb;--accent:#0e7490;--accent2:#4f46e5;--good:#047857}body{background:radial-gradient(circle at 20% 0,#e5e7ff 0,transparent 32rem),var(--bg)}}
@media(max-width:780px){main{padding:12px}header,section{padding:19px}.twocol{grid-template-columns:1fr}.timeline li{grid-template-columns:1fr;gap:3px}table{display:block;overflow-x:auto}}
@media print{body{background:white;color:black}main{max-width:none;padding:0}header,section,.grid>div{box-shadow:none;background:white;border-color:#bbb;break-inside:avoid}.bar{background:#555}.skip{display:none}}
"""
    visible_manifest = {k: v for k, v in manifest.items() if k not in {"files", "ground_truth_summary"}}
    if student_safe:
        visible_manifest.pop("mapping_summary", None)
        visible_manifest.pop("suspicious_events", None)

    doc = f"""<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><meta name='color-scheme' content='dark light'><title>LogFable report — {_esc(s.title)}</title><style>{css}</style></head><body><a class='skip' href='#content'>Skip to report content</a><main id='content'>
<header><div class='eyebrow'>LogFable · {'Student-safe' if student_safe else 'Instructor'} report</div><h1>{_esc(s.title)}</h1><p>{_esc(s.summary)}</p><p class='muted'>Synthetic, local-first, compatibility-oriented telemetry. No external assets, analytics, tracking, or runtime network dependency.</p></header>
<section class='grid' aria-label='Run overview'><div><div class='metric'>{len(events):,}</div><div>events</div></div><div><div class='metric'>{len(counts)}</div><div>source families</div></div><div><div class='metric'>{env.get('entities',0):,}</div><div>entities</div></div><div><div class='metric'>{'Hidden' if student_safe else manifest.get('suspicious_events',0)}</div><div>{'instructor labels withheld' if student_safe else 'suspicious events'}</div></div></section>
<section aria-labelledby='environment'><div class='eyebrow'>Environment</div><h2 id='environment'>Organization and entity graph</h2><p><strong>{_esc(env.get('organization','Synthetic organization'))}</strong> · preset <code>{_esc(env.get('preset','unknown'))}</code> · {_esc(env.get('users',0))} users · {_esc(env.get('relationships',0))} relationships.</p><div class='twocol'><div><h3>Entity kinds</h3><table><thead><tr><th>Kind</th><th>Count</th></tr></thead><tbody>{entity_rows}</tbody></table></div><div><h3>Relationship kinds</h3><table><thead><tr><th>Relationship</th><th>Count</th></tr></thead><tbody>{relationship_rows}</tbody></table></div></div></section>
<section aria-labelledby='volume'><div class='eyebrow'>Telemetry</div><h2 id='volume'>Event volume over time</h2><table><thead><tr><th>Hour</th><th>Events</th><th>Relative volume</th></tr></thead><tbody>{volume_rows}</tbody></table></section>
<section aria-labelledby='sources'><div class='eyebrow'>Telemetry</div><h2 id='sources'>Event count by source</h2><table><thead><tr><th>Source</th><th>Events</th><th>Relative volume</th></tr></thead><tbody>{source_rows}</tbody></table></section>
<section aria-labelledby='categories'><div class='eyebrow'>Telemetry</div><h2 id='categories'>Event categories</h2><table><thead><tr><th>Category</th><th>Events</th></tr></thead><tbody>{category_rows}</tbody></table></section>
<section aria-labelledby='timeline'><div class='eyebrow'>Analyst-visible timeline</div><h2 id='timeline'>High-signal events</h2><ul class='timeline'>{timeline}</ul></section>
<section aria-labelledby='questions'><div class='eyebrow'>Exercise</div><h2 id='questions'>Investigation questions</h2><ol>{questions}</ol></section>
{instructor_sections}
<section aria-labelledby='quality'><div class='eyebrow'>Quality</div><h2 id='quality'>Generation checks and exporter lossiness</h2><pre>{_esc(json.dumps(quality,indent=2,sort_keys=True))}</pre></section>
<section aria-labelledby='repro'><div class='eyebrow'>Reproducibility</div><h2 id='repro'>Run metadata</h2><pre>{_esc(json.dumps(visible_manifest,indent=2,sort_keys=True))}</pre></section>
<footer>Generated locally by LogFable · {COPYRIGHT} · Maintainer: {AUTHOR} · {WEBSITE} · GitHub @{GITHUB_HANDLE}</footer></main></body></html>"""
    # fmt: on
    path.write_text(doc, encoding="utf-8")
