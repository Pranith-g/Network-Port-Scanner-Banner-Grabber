from __future__ import annotations

from datetime import datetime

import streamlit as st

from database import create_scan_record, create_user, init_db, verify_user_credentials
from scanner import ScanResult, run_scan, validate_scan_inputs
from utils import (
    format_banner_preview,
    load_scan_rows,
    summarize_results,
    theme_css,
    to_csv_bytes,
    to_json_bytes,
)


st.set_page_config(
    page_title="Network Port Scanner",
    layout="wide",
    initial_sidebar_state="collapsed",
)


def init_state() -> None:
    defaults = {
        "theme": "light",
        "current_page": "register",
        "is_authenticated": False,
        "user_id": None,
        "username": "",
        "results": [],
        "resolved_ip": "",
        "scan_message": "Ready for the next scan.",
        "selected_port": None,
        "scan_started_at": None,
        "scan_completed_at": None,
        "last_error": "",
        "last_success": "",
        "scan_history": [],
    }
    for key, value in defaults.items():
        st.session_state.setdefault(key, value)


def reset_scan_state() -> None:
    st.session_state.results = []
    st.session_state.resolved_ip = ""
    st.session_state.scan_message = "Ready for the next scan."
    st.session_state.selected_port = None
    st.session_state.scan_started_at = None
    st.session_state.scan_completed_at = None
    st.session_state.last_error = ""


def go_to(page: str) -> None:
    st.session_state.current_page = page
    st.rerun()


def set_success(message: str) -> None:
    st.session_state.last_success = message
    st.session_state.last_error = ""


def set_error(message: str) -> None:
    st.session_state.last_error = message
    st.session_state.last_success = ""


def render_shell_header() -> None:
    left, right = st.columns([3.4, 1.6])
    with left:
        st.markdown(
            """
            <div class="topbar-title-wrap">
                <div class="eyebrow">Secure Internal Tooling</div>
                <div class="topbar-title">Network Port Scanner Control Center</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with right:
        theme_label = "Switch To Dark Theme" if st.session_state.theme == "light" else "Switch To Light Theme"
        st.caption(f"Current theme: {st.session_state.theme.title()}")
        if st.button(theme_label, use_container_width=True):
            st.session_state.theme = "dark" if st.session_state.theme == "light" else "light"
            st.rerun()
        if st.session_state.is_authenticated:
            action_cols = st.columns(2)
            with action_cols[0]:
                if st.button("Dashboard", use_container_width=True):
                    go_to("dashboard")
            with action_cols[1]:
                if st.button("Logout", use_container_width=True):
                    logout_user()


def render_flash_messages() -> None:
    if st.session_state.last_success:
        st.success(st.session_state.last_success)
    if st.session_state.last_error:
        st.error(st.session_state.last_error)


def render_auth_hero(title: str, subtitle: str) -> None:
    st.markdown(
        f"""
        <div class="auth-hero">
            <div class="eyebrow">Professional Recon Workflow</div>
            <h1>{title}</h1>
            <p>{subtitle}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_auth_side_panel(mode: str) -> None:
    if mode == "login":
        title = "Secure access for approved scanning"
        subtitle = "Sign in to open the dashboard, review saved activity, and launch new scans from one clean workspace."
        highlights = [
            ("Fast threaded scans", "Check many ports at the same time for quicker results."),
            ("Saved history", "Keep earlier runs in the local database for quick review."),
            ("Theme switch", "Move between light and dark presentation styles in one click."),
        ]
    else:
        title = "Create a modern scanning workspace"
        subtitle = "Register once, then use the dashboard to manage scans, review outputs, and export findings cleanly."
        highlights = [
            ("Professional dashboard", "Cards, scan summaries, and simple navigation after login."),
            ("Detection details", "Open ports, banner previews, and connection notes in one place."),
            ("Export ready", "Download results as CSV or JSON whenever a scan finishes."),
        ]

    items = "".join(
        [
            (
                f'<div class="feature-row">'
                f'<div class="feature-icon">{index:02d}</div>'
                f'<div>'
                f'<div class="feature-title">{label}</div>'
                f'<div class="feature-copy">{copy}</div>'
                f"</div>"
                f"</div>"
            )
            for index, (label, copy) in enumerate(highlights, start=1)
        ]
    )
    st.markdown(
        f"""
        <div class="split-panel split-panel-accent">
            <div class="eyebrow">Recon Suite</div>
            <h2>{title}</h2>
            <p>{subtitle}</p>
            <div class="feature-stack">
                {items}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_register_page() -> None:
    left, right = st.columns([1.05, 0.95], gap="large")
    with left:
        render_auth_hero(
            "Create your secure workspace",
            "Register a user account first. After sign-up, the app will take you to the login page where the sign-in button is available.",
        )
        render_auth_side_panel("register")
    with right:
        inner_left, inner_center, inner_right = st.columns([0.14, 0.72, 0.14])
        with inner_center:
            st.markdown('<div class="auth-form-title">Sign Up</div>', unsafe_allow_html=True)
            with st.form("register_form", clear_on_submit=False):
                username = st.text_input("Username")
                password = st.text_input("Password", type="password")
                confirm_password = st.text_input("Confirm password", type="password")
                submitted = st.form_submit_button("Create Account", use_container_width=True)

            if submitted:
                if not username.strip():
                    set_error("Username is required.")
                elif len(password) < 4:
                    set_error("Password must be at least 4 characters long.")
                elif password != confirm_password:
                    set_error("Passwords do not match.")
                else:
                    try:
                        create_user(username.strip(), password)
                    except ValueError as exc:
                        set_error(str(exc))
                    else:
                        set_success("Account created successfully. Please sign in.")
                        st.session_state.current_page = "login"
                        st.rerun()

            if st.button("Already have an account? Go to Login", use_container_width=True):
                go_to("login")


def render_login_page() -> None:
    left, right = st.columns([1.05, 0.95], gap="large")
    with left:
        render_auth_hero(
            "Sign in to enter the dashboard",
            "Login takes you directly to the dashboard first. From there, use the scan button to open the detection page.",
        )
        render_auth_side_panel("login")
    with right:
        inner_left, inner_center, inner_right = st.columns([0.14, 0.72, 0.14])
        with inner_center:
            st.markdown('<div class="auth-form-title">Login</div>', unsafe_allow_html=True)
            with st.form("login_form", clear_on_submit=False):
                username = st.text_input("Username", key="login_username")
                password = st.text_input("Password", type="password", key="login_password")
                submitted = st.form_submit_button("Sign In", use_container_width=True)

            if submitted:
                user = verify_user_credentials(username.strip(), password)
                if user is None:
                    set_error("Invalid username or password.")
                else:
                    st.session_state.is_authenticated = True
                    st.session_state.user_id = user["id"]
                    st.session_state.username = user["username"]
                    st.session_state.scan_history = load_scan_rows(user["id"])
                    set_success(f"Welcome back, {user['username']}.")
                    st.session_state.current_page = "dashboard"
                    st.rerun()

            if st.button("Need an account? Go to Sign Up", use_container_width=True):
                go_to("register")


def logout_user() -> None:
    username = st.session_state.username
    st.session_state.is_authenticated = False
    st.session_state.user_id = None
    st.session_state.username = ""
    st.session_state.scan_history = []
    reset_scan_state()
    set_success(f"{username} has been logged out.")
    st.session_state.current_page = "login"
    st.rerun()


def require_authentication() -> None:
    if not st.session_state.is_authenticated:
        st.session_state.current_page = "login"
        st.rerun()


def render_dashboard_page() -> None:
    require_authentication()
    history = st.session_state.scan_history
    st.markdown(
        f"""
        <div class="hero-shell">
            <div class="eyebrow">Dashboard</div>
            <h1>Welcome, {st.session_state.username}</h1>
            <p>
                This project is a professional TCP port scanner and banner grabber built for
                cybersecurity learning, controlled testing, and demonstration. It checks target ports,
                identifies open services, and shows lightweight banner details that help users understand
                what may be running on a system.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    cards = st.columns(4)
    cards[0].markdown(
        f"""
        <div class="info-card">
            <div class="info-icon">01</div>
            <div class="card-label">Saved Scans</div>
            <div class="card-value">{len(history)}</div>
            <div class="card-note">Stored in the local project database</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    cards[1].markdown(
        """
        <div class="info-card">
            <div class="info-icon">02</div>
            <div class="card-label">Project Goal</div>
            <div class="card-value">TCP Recon</div>
            <div class="card-note">Find open ports and capture service banners</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    cards[2].markdown(
        """
        <div class="info-card">
            <div class="info-icon">03</div>
            <div class="card-label">Speed Mode</div>
            <div class="card-value">Threaded</div>
            <div class="card-note">Multiple ports are scanned at the same time</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    cards[3].markdown(
        """
        <div class="info-card">
            <div class="info-icon">04</div>
            <div class="card-label">Workspace Flow</div>
            <div class="card-value">Dashboard</div>
            <div class="card-note">Review the project summary here, then open the scan center when ready.</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    overview_left, overview_right = st.columns([1.15, 0.85], gap="large")
    with overview_left:
        st.markdown(
            """
            <div class="section-card">
                <h3>About this project</h3>
                <p>
                    The scanner focuses on TCP port detection only. It does not perform exploits, stealth scanning,
                    packet crafting, or deep fingerprinting. The goal is a safe, clean, and presentation-ready control center
                    for port discovery, banner capture, and result review.
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with overview_right:
        st.markdown(
            """
            <div class="section-card">
                <h3>What you can do here</h3>
                <div class="mini-point"><strong>Open Scan Center</strong><span>Launch a new detection run with threaded performance.</span></div>
                <div class="mini-point"><strong>Review History</strong><span>See saved targets, durations, and open-port counts.</span></div>
                <div class="mini-point"><strong>Export Findings</strong><span>Download results after each completed scan.</span></div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    action_col_left, action_col_center, action_col_right = st.columns([1.5, 1.3, 1.5])
    with action_col_center:
        if st.button("Open Scan Center", use_container_width=True, type="primary"):
            go_to("scanner")

    if history:
        st.markdown("### Recent Scan Activity")
        st.dataframe(history[:8], use_container_width=True, hide_index=True)
    else:
        st.markdown(
            """
            <div class="empty-state">
                <div class="empty-title">No scans yet</div>
                <div class="empty-copy">Run your first scan from the dashboard to start building saved history for this account.</div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def run_scan_flow(
    host: str,
    start_port: int,
    end_port: int,
    timeout: float,
    grab_banner: bool,
    workers: int,
) -> None:
    st.session_state.last_error = ""
    st.session_state.last_success = ""
    st.session_state.scan_started_at = datetime.now()
    st.session_state.scan_completed_at = None

    progress_bar = st.progress(0.0, text="Preparing threaded scan...")
    live_status = st.empty()
    live_metrics = st.empty()
    live_results = st.empty()

    captured_results: list[ScanResult] = []

    def progress_callback(current: int, total: int, result: ScanResult) -> None:
        captured_results.append(result)
        open_count = sum(1 for item in captured_results if item.is_open)
        banner_count = sum(1 for item in captured_results if item.banner)
        percent = current / total if total else 0.0
        progress_bar.progress(percent, text=f"Scanning in parallel: {current}/{total} ports processed")
        live_status.markdown(
            f"""
            <div class="section-card compact-card">
                <div class="card-label">Live status</div>
                <div class="card-note">
                    Latest completed port: <span class="mono">{result.port}</span>
                    with status <strong>{result.status}</strong>
                </div>
                <div class="progress-meta">
                    <span>{current} of {total} ports processed</span>
                    <span>{percent:.0%} complete</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        live_metrics.markdown(
            f"""
            <div class="section-card compact-card">
                <div class="card-label">Live metrics</div>
                <div class="card-note">
                    Open ports: <strong>{open_count}</strong> |
                    Banners: <strong>{banner_count}</strong> |
                    Completed: <strong>{percent:.0%}</strong>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        live_results.dataframe(
            [
                {
                    "Port": item.port,
                    "Status": item.status,
                    "Service": item.service_hint or "Unknown",
                    "Banner": format_banner_preview(item.banner, 60),
                }
                for item in sorted(captured_results, key=lambda row: row.port)[-12:]
            ],
            use_container_width=True,
            hide_index=True,
        )

    try:
        validate_scan_inputs(host, start_port, end_port, timeout)
        results, resolved_ip = run_scan(
            host=host,
            start_port=start_port,
            end_port=end_port,
            timeout=timeout,
            grab_banner=grab_banner,
            workers=workers,
            progress_callback=progress_callback,
        )
    except ValueError as exc:
        set_error(str(exc))
        st.session_state.scan_message = "Scan validation failed."
        progress_bar.empty()
        return
    except Exception as exc:
        set_error(f"Unexpected scan failure: {exc}")
        st.session_state.scan_message = "Scan failed unexpectedly."
        progress_bar.empty()
        return

    st.session_state.results = results
    st.session_state.resolved_ip = resolved_ip
    st.session_state.scan_completed_at = datetime.now()
    st.session_state.scan_message = "Scan completed successfully."
    st.session_state.selected_port = next((item.port for item in results if item.is_open), results[0].port if results else None)
    progress_bar.progress(1.0, text="Threaded scan complete.")

    duration_seconds = (
        st.session_state.scan_completed_at - st.session_state.scan_started_at
    ).total_seconds()
    create_scan_record(
        user_id=st.session_state.user_id,
        target_host=host.strip(),
        resolved_ip=resolved_ip,
        start_port=start_port,
        end_port=end_port,
        timeout=timeout,
        grab_banner=grab_banner,
        workers=workers,
        duration_seconds=duration_seconds,
        results=results,
    )
    st.session_state.scan_history = load_scan_rows(st.session_state.user_id)
    set_success(f"Scan completed in {duration_seconds:.2f} seconds and was saved.")


def render_scan_metrics(results: list[ScanResult]) -> None:
    summary = summarize_results(results)
    duration_text = "Waiting for scan"
    if st.session_state.scan_started_at and st.session_state.scan_completed_at:
        elapsed = st.session_state.scan_completed_at - st.session_state.scan_started_at
        duration_text = f"{elapsed.total_seconds():.2f}s"

    st.markdown("### Scan Summary")
    cards = st.columns(4)
    card_data = [
        ("Total Ports Checked", str(summary["total_ports"]), "All ports included in the most recent run"),
        ("Open Ports", str(summary["open_ports"]), "Detected listening services"),
        ("Banners Found", str(summary["banners_found"]), "Readable service responses captured"),
        ("Scan Time", duration_text, st.session_state.scan_message),
    ]
    for index, (column, (label, value, note)) in enumerate(zip(cards, card_data), start=1):
        column.markdown(
            f"""
            <div class="info-card">
                <div class="info-icon">{index:02d}</div>
                <div class="card-label">{label}</div>
                <div class="card-value">{value}</div>
                <div class="card-note">{note}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_scan_results(results: list[ScanResult]) -> None:
    if not results:
        st.markdown(
            """
            <div class="empty-state">
                <div class="empty-title">No scans yet</div>
                <div class="empty-copy">Use the Scan Now button in the control center to check a target host and populate the detection table.</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        return

    left, right = st.columns([1.55, 1], gap="large")
    with left:
        st.markdown("### Detection Table")
        st.dataframe(
            [
                {
                    "Port": result.port,
                    "Status": result.status,
                    "Open": "Yes" if result.is_open else "No",
                    "Service": result.service_hint or "Unknown",
                    "Banner": format_banner_preview(result.banner, 75),
                    "Notes": result.error or "None",
                }
                for result in results
            ],
            use_container_width=True,
            hide_index=True,
        )
        port_options = [result.port for result in results]
        default_port = st.session_state.selected_port if st.session_state.selected_port in port_options else port_options[0]
        st.session_state.selected_port = st.selectbox(
            "Inspect selected port",
            port_options,
            index=port_options.index(default_port),
        )

    with right:
        selected_port = st.session_state.selected_port
        selected = next(result for result in results if result.port == selected_port)
        st.markdown(
            f"""
            <div class="section-card detail-card">
                <div class="card-label">Port</div>
                <div class="detail-big mono">{selected.port}</div>
                <div class="card-label">Status</div>
                <div class="card-note">{selected.status}</div>
                <div class="card-label">Service Hint</div>
                <div class="card-note">{selected.service_hint or "Unknown service"}</div>
                <div class="card-label">Banner Preview</div>
                <div class="card-note mono">{format_banner_preview(selected.banner, 350)}</div>
                <div class="card-label">What the user can see</div>
                <div class="card-note">
                    This section shows whether the port is open, what common service is usually associated
                    with it, and any banner text returned by the target application.
                </div>
                <div class="card-label">Connection Notes</div>
                <div class="card-note">{selected.error or "No extra errors reported."}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        export_cols = st.columns(2)
        export_cols[0].download_button(
            "Download CSV",
            data=to_csv_bytes(results),
            file_name="scan_results.csv",
            mime="text/csv",
            use_container_width=True,
        )
        export_cols[1].download_button(
            "Download JSON",
            data=to_json_bytes(results),
            file_name="scan_results.json",
            mime="application/json",
            use_container_width=True,
        )


def render_scanner_page() -> None:
    require_authentication()
    st.markdown(
        """
        <div class="hero-shell">
            <div class="eyebrow">Detection Center</div>
            <h1>Threaded Scan Workspace</h1>
            <p>
                Enter the target IP address, define the port range, and run a faster multi-threaded scan.
                The control center stays centered for a cleaner presentation and easier use.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    outer_left, outer_center, outer_right = st.columns([0.75, 2.2, 0.75])
    with outer_center:
        st.markdown("### Scan Control Center")
        st.markdown(
            """
            <div class="scan-note">
                Scan only systems you own or are clearly authorized to assess.
                This tool is intended for local labs, classroom demos, and approved environments.
            </div>
            """,
            unsafe_allow_html=True,
        )
        with st.form("scan_form", clear_on_submit=False):
            col1, col2 = st.columns(2)
            with col1:
                host = st.text_input("IP address or host name", value="127.0.0.1")
                start_port = st.number_input("Start port", min_value=1, max_value=65535, value=1, step=1)
                timeout = st.number_input("Timeout in seconds", min_value=0.05, max_value=10.0, value=0.20, step=0.05)
            with col2:
                end_port = st.number_input("End port", min_value=1, max_value=65535, value=1000, step=1)
                workers = st.number_input("Parallel threads", min_value=10, max_value=300, value=120, step=10)
                grab_banner = st.checkbox("Grab service banners", value=True)

            action_cols = st.columns(3)
            run_clicked = action_cols[0].form_submit_button("Scan Now", use_container_width=True, type="primary")
            dashboard_clicked = action_cols[1].form_submit_button("Back to Dashboard", use_container_width=True)
            reset_clicked = action_cols[2].form_submit_button("Reset Results", use_container_width=True)

    if dashboard_clicked:
        go_to("dashboard")
    if reset_clicked:
        reset_scan_state()
        set_success("Scan results cleared.")
    if run_clicked:
        run_scan_flow(
            host=host,
            start_port=int(start_port),
            end_port=int(end_port),
            timeout=float(timeout),
            grab_banner=grab_banner,
            workers=int(workers),
        )

    results: list[ScanResult] = st.session_state.results
    render_scan_metrics(results)
    render_scan_results(results)

    if st.session_state.scan_history:
        st.markdown("### Stored History")
        st.dataframe(st.session_state.scan_history, use_container_width=True, hide_index=True)


def main() -> None:
    init_db()
    init_state()
    st.markdown(theme_css(st.session_state.theme), unsafe_allow_html=True)
    render_shell_header()
    render_flash_messages()

    current_page = st.session_state.current_page
    if current_page == "register":
        render_register_page()
    elif current_page == "login":
        render_login_page()
    elif current_page == "dashboard":
        render_dashboard_page()
    else:
        render_scanner_page()


if __name__ == "__main__":
    main()
