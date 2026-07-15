# Network Port Scanner & Banner Grabber

A multi-page Streamlit application with user sign-up, login, dashboard navigation, theme switching, persistent scan history, and a faster multi-threaded TCP scanner.

## Features

- Sign-up page followed by a login page with sign-in button
- Dashboard page shown immediately after login
- Logout button and stored user session state
- Scan a target host across a TCP port range
- Optional banner grabbing for open ports
- Multi-threaded backend scanning for much faster execution
- Live progress updates during a scan
- Summary cards, detailed port inspection, and stored scan history
- Export results as CSV or JSON
- Theme switch between a white executive look and a dark cyber look
- Local SQLite database for users and saved scan results

## Requirements

- Python 3.10+
- Streamlit

## Install

```powershell
pip install -r requirements.txt
```

## Run

```powershell
streamlit run app.py
```

## Default Flow

1. Open the app and create a user account on the sign-up page.
2. Go to the login page and sign in.
3. After login, the app opens the dashboard.
4. Click `Open Scan Center` to go to the scanning page.
5. Enter host/IP, start port, end port, timeout, and thread count.
6. Run the scan and review the detection table, port details, exports, and stored history.

## Suggested Local Demo

1. Start a local HTTP service in another terminal:

```powershell
python -m http.server 8080
```

2. Launch the app:

```powershell
streamlit run app.py
```

3. Use these scan settings:

- Host: `127.0.0.1`
- Start port: `8000`
- End port: `8085`
- Parallel threads: `80` or higher
- Banner grabbing: enabled

## Safety Note

Use this tool only on systems you own or are explicitly authorized to test.
