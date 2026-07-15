from __future__ import annotations

import csv
import io
import json
from collections import Counter

from database import fetch_scan_history
from scanner import ScanResult


LIGHT_THEME = {
    "bg": "#f4f5f8",
    "bg2": "#ffffff",
    "hero": "linear-gradient(135deg, rgba(255,255,255,0.96), rgba(245,247,250,0.98))",
    "panel": "rgba(255,255,255,0.9)",
    "panel_strong": "rgba(255,255,255,0.98)",
    "text": "#152033",
    "muted": "#637188",
    "border": "rgba(13, 33, 73, 0.12)",
    "accent": "#d17f2f",
    "shadow": "0 18px 60px rgba(20, 32, 51, 0.08)",
}

DARK_THEME = {
    "bg": "#08101a",
    "bg2": "#0f1723",
    "hero": "linear-gradient(135deg, rgba(13,24,40,0.94), rgba(15,23,35,0.9))",
    "panel": "rgba(10, 24, 43, 0.7)",
    "panel_strong": "rgba(10, 24, 43, 0.9)",
    "text": "#f4f7fb",
    "muted": "#9fb2cf",
    "border": "rgba(120, 166, 255, 0.18)",
    "accent": "#58a6ff",
    "shadow": "0 20px 80px rgba(0, 0, 0, 0.3)",
}


def summarize_results(results: list[ScanResult]) -> dict[str, int]:
    status_counts = Counter(result.status for result in results)
    open_results = [result for result in results if result.is_open]
    banners_found = sum(1 for result in open_results if result.banner)
    return {
        "total_ports": len(results),
        "open_ports": len(open_results),
        "banners_found": banners_found,
        "errors": status_counts.get("Error", 0) + status_counts.get("Timed Out", 0),
    }


def to_csv_bytes(results: list[ScanResult]) -> bytes:
    output = io.StringIO()
    fieldnames = ["port", "is_open", "status", "service_hint", "banner", "error"]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(result.to_dict() for result in results)
    return output.getvalue().encode("utf-8")


def to_json_bytes(results: list[ScanResult]) -> bytes:
    return json.dumps([result.to_dict() for result in results], indent=2).encode("utf-8")


def format_banner_preview(banner: str, limit: int = 240) -> str:
    cleaned = (banner or "").strip()
    if not cleaned:
        return "No banner captured for this port."
    if len(cleaned) <= limit:
        return cleaned
    return f"{cleaned[:limit].rstrip()}..."


def load_scan_rows(user_id: int | None) -> list[dict[str, str | int | float]]:
    if user_id is None:
        return []
    return fetch_scan_history(user_id)


def theme_css(theme_name: str) -> str:
    theme = DARK_THEME if theme_name == "dark" else LIGHT_THEME
    return f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap');

.stApp {{
    background:
        radial-gradient(circle at top left, rgba(209,127,47,0.08), transparent 24%),
        radial-gradient(circle at top right, rgba(15,157,138,0.08), transparent 20%),
        linear-gradient(180deg, {theme["bg"]} 0%, {theme["bg2"]} 100%);
    color: {theme["text"]};
    font-family: "Space Grotesk", sans-serif;
}}

.block-container {{
    padding-top: 1.2rem;
    padding-bottom: 2.5rem;
    animation: fadeUp 0.35s ease-out;
}}

h1, h2, h3, label, p, div {{
    color: {theme["text"]};
}}

[data-testid="stHeader"] {{
    background: transparent;
}}

.topbar-title-wrap {{
    margin-bottom: 1rem;
}}

.topbar-title {{
    font-size: 1.8rem;
    font-weight: 700;
    line-height: 1.1;
}}

.split-panel {{
    background: rgba(255, 255, 255, 0.46);
    border: 1px solid {theme["border"]};
    border-radius: 28px;
    padding: 1.35rem;
    box-shadow: {theme["shadow"]};
    backdrop-filter: blur(16px);
}}

.split-panel-accent {{
    background:
        radial-gradient(circle at top right, rgba(209,127,47,0.12), transparent 28%),
        linear-gradient(180deg, {theme["panel_strong"]}, {theme["panel"]});
}}

.split-panel h2 {{
    margin: 0.35rem 0 0.55rem;
    font-size: clamp(1.8rem, 2.4vw, 2.6rem);
    letter-spacing: -0.03em;
}}

.split-panel p {{
    color: {theme["muted"]};
    line-height: 1.75;
}}

.feature-stack {{
    display: grid;
    gap: 0.85rem;
    margin-top: 1.2rem;
}}

.feature-row {{
    display: grid;
    grid-template-columns: 58px 1fr;
    gap: 0.9rem;
    align-items: start;
    padding: 0.9rem;
    border-radius: 18px;
    background: rgba(255,255,255,0.38);
    border: 1px solid {theme["border"]};
}}

.feature-icon, .info-icon {{
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 42px;
    height: 42px;
    border-radius: 14px;
    font-size: 0.88rem;
    font-weight: 700;
    color: {theme["accent"]};
    background: rgba(209,127,47,0.12);
    border: 1px solid rgba(209,127,47,0.18);
}}

.feature-title {{
    font-weight: 700;
    margin-bottom: 0.24rem;
}}

.feature-copy {{
    color: {theme["muted"]};
    line-height: 1.65;
}}

.auth-form-title {{
    text-align: center;
    font-size: 2rem;
    font-weight: 700;
    letter-spacing: -0.03em;
    margin: 1.25rem 0 0.9rem;
}}

@keyframes fadeUp {{
    from {{
        opacity: 0;
        transform: translateY(8px);
    }}
    to {{
        opacity: 1;
        transform: translateY(0);
    }}
}}

@keyframes sheen {{
    0%, 100% {{
        transform: translateX(-120%);
    }}
    45%, 60% {{
        transform: translateX(120%);
    }}
}}

.eyebrow {{
    display: inline-block;
    margin-bottom: 0.45rem;
    padding: 0.32rem 0.78rem;
    border-radius: 999px;
    font-size: 0.78rem;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    background: rgba(209,127,47,0.12);
    color: {theme["accent"]};
    font-weight: 700;
}}

.auth-hero, .hero-shell {{
    background: {theme["hero"]};
    border: 1px solid {theme["border"]};
    border-radius: 28px;
    padding: 1.5rem 1.7rem;
    box-shadow: {theme["shadow"]};
    backdrop-filter: blur(18px);
    margin-bottom: 1.2rem;
    position: relative;
    overflow: hidden;
}}

.auth-hero::after, .hero-shell::after {{
    content: "";
    position: absolute;
    inset: 0;
    background: linear-gradient(110deg, transparent 0%, rgba(255,255,255,0.08) 45%, transparent 70%);
    transform: translateX(-120%);
    animation: sheen 6.5s ease-in-out infinite;
    pointer-events: none;
}}

.auth-hero h1, .hero-shell h1 {{
    margin: 0.35rem 0 0.6rem;
    font-size: clamp(2rem, 3vw, 3rem);
    letter-spacing: -0.03em;
}}

.auth-hero p, .hero-shell p {{
    color: {theme["muted"]};
    margin: 0;
    line-height: 1.7;
}}

.center-card, .section-card, .info-card {{
    background: {theme["panel"]};
    border: 1px solid {theme["border"]};
    border-radius: 24px;
    padding: 1.25rem;
    box-shadow: {theme["shadow"]};
    backdrop-filter: blur(14px);
    transition: transform 0.24s ease, box-shadow 0.24s ease, border-color 0.24s ease;
}}

.scan-card {{
    padding: 1.45rem;
}}

.compact-card {{
    padding: 0.95rem 1.1rem;
}}

.info-card {{
    min-height: 140px;
}}

.section-card:hover, .info-card:hover {{
    transform: translateY(-3px);
    box-shadow: 0 22px 70px rgba(0, 0, 0, 0.12);
    border-color: rgba(209,127,47,0.28);
}}

.card-label {{
    color: {theme["muted"]};
    font-size: 0.84rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    font-weight: 600;
}}

.card-value {{
    font-size: 2rem;
    font-weight: 700;
    margin: 0.45rem 0;
}}

.detail-big {{
    font-size: 2.4rem;
    font-weight: 700;
    margin: 0.4rem 0 1rem;
}}

.card-note {{
    color: {theme["muted"]};
    line-height: 1.7;
}}

.progress-meta {{
    display: flex;
    justify-content: space-between;
    gap: 0.8rem;
    margin-top: 0.8rem;
    color: {theme["muted"]};
    font-size: 0.92rem;
}}

.mini-point {{
    display: grid;
    gap: 0.18rem;
    margin-top: 0.8rem;
}}

.mini-point span {{
    color: {theme["muted"]};
    line-height: 1.6;
}}

.empty-state {{
    background:
        radial-gradient(circle at top right, rgba(209,127,47,0.10), transparent 26%),
        linear-gradient(180deg, {theme["panel_strong"]}, {theme["panel"]});
    border: 1px dashed rgba(209,127,47,0.28);
    border-radius: 24px;
    padding: 1.45rem;
    text-align: center;
    box-shadow: {theme["shadow"]};
}}

.empty-title {{
    font-size: 1.35rem;
    font-weight: 700;
    margin-bottom: 0.35rem;
}}

.empty-copy {{
    color: {theme["muted"]};
    line-height: 1.75;
    max-width: 44rem;
    margin: 0 auto;
}}

.scan-note {{
    padding: 0.9rem 1rem;
    border-radius: 16px;
    background: rgba(209,127,47,0.09);
    border-left: 4px solid {theme["accent"]};
    color: {theme["text"]};
    margin-bottom: 1rem;
}}

.mono {{
    font-family: "IBM Plex Mono", monospace;
}}

.stTextInput input, .stNumberInput input, .stTextInput textarea {{
    border-radius: 14px;
    color: {theme["text"]} !important;
    background: {theme["panel_strong"]} !important;
    transition: box-shadow 0.2s ease, border-color 0.2s ease, transform 0.2s ease;
}}

.stButton > button, .stDownloadButton > button, .stFormSubmitButton > button {{
    width: 100%;
    border-radius: 14px;
    border: 1px solid {theme["border"]};
    background: linear-gradient(180deg, {theme["panel_strong"]}, {theme["panel"]});
    color: {theme["text"]};
    min-height: 2.85rem;
    font-weight: 600;
    transition: transform 0.18s ease, box-shadow 0.18s ease, border-color 0.18s ease;
    box-shadow: 0 10px 24px rgba(0, 0, 0, 0.06);
}}

.stButton > button:hover, .stDownloadButton > button:hover, .stFormSubmitButton > button:hover {{
    transform: translateY(-2px);
    box-shadow: 0 16px 32px rgba(0, 0, 0, 0.12);
    border-color: rgba(209,127,47,0.35);
}}

.stButton > button:active, .stDownloadButton > button:active, .stFormSubmitButton > button:active {{
    transform: translateY(0);
}}

.stToggle label, .stCheckbox label, .stSelectbox label, .stNumberInput label, .stTextInput label, .stSlider label {{
    color: {theme["text"]} !important;
}}

div[data-baseweb="select"] > div {{
    background: {theme["panel_strong"]} !important;
    border: 1px solid {theme["border"]} !important;
    border-radius: 14px !important;
}}

div[data-baseweb="select"] span,
div[data-baseweb="select"] input,
div[data-baseweb="select"] svg {{
    color: {theme["text"]} !important;
    fill: {theme["text"]} !important;
}}

ul[role="listbox"] {{
    background: {theme["panel_strong"]} !important;
    color: {theme["text"]} !important;
    border: 1px solid {theme["border"]} !important;
}}

ul[role="listbox"] li {{
    color: {theme["text"]} !important;
}}

div[data-testid="stForm"] {{
    background: {theme["panel"]};
    border: 1px solid {theme["border"]};
    border-radius: 24px;
    padding: 1.25rem 1.25rem 0.9rem 1.25rem;
    box-shadow: {theme["shadow"]};
    backdrop-filter: blur(14px);
}}

div[data-testid="stForm"] > div {{
    gap: 0.85rem;
}}

div[data-testid="stForm"] button {{
    margin-top: 0.35rem;
}}

.stTextInput input:focus, .stNumberInput input:focus {{
    box-shadow: 0 0 0 3px rgba(209,127,47,0.14) !important;
    border-color: rgba(209,127,47,0.4) !important;
    transform: translateY(-1px);
}}

@media (max-width: 900px) {{
    .progress-meta {{
        flex-direction: column;
    }}
}}

div[data-testid="stDataFrame"] {{
    border: 1px solid {theme["border"]};
    border-radius: 18px;
    overflow: hidden;
    background: {theme["panel_strong"]};
}}

div[data-testid="stNotification"] {{
    border-radius: 18px;
}}
</style>
"""
