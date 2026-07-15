from __future__ import annotations

import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from typing import Callable


COMMON_SERVICES = {
    20: "FTP Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCbind",
    135: "MS RPC",
    139: "NetBIOS",
    143: "IMAP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    587: "SMTP Submission",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    1723: "PPTP",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP Alternate",
    8443: "HTTPS Alternate",
}


@dataclass(slots=True)
class ScanResult:
    port: int
    is_open: bool
    status: str
    banner: str
    service_hint: str = ""
    error: str = ""

    def to_dict(self) -> dict[str, str | int | bool]:
        return asdict(self)


def validate_scan_inputs(host: str, start_port: int, end_port: int, timeout: float) -> None:
    if not host or not host.strip():
        raise ValueError("Target host is required.")
    if start_port < 1 or end_port > 65535:
        raise ValueError("Ports must stay between 1 and 65535.")
    if start_port > end_port:
        raise ValueError("Start port must be less than or equal to end port.")
    if timeout <= 0:
        raise ValueError("Timeout must be greater than 0 seconds.")


def resolve_target(host: str) -> tuple[str, str]:
    normalized = host.strip()
    try:
        resolved_ip = socket.gethostbyname(normalized)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve host '{normalized}'.") from exc
    return normalized, resolved_ip


def scan_port(host: str, port: int, timeout: float, grab_banner: bool) -> ScanResult:
    service_hint = COMMON_SERVICES.get(port, "")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        connection_code = sock.connect_ex((host, port))
        if connection_code != 0:
            return classify_closed_port(port, service_hint, connection_code)

        banner = ""
        banner_error = ""
        if grab_banner:
            banner, banner_error = grab_service_banner(sock, host, port, timeout)

        return ScanResult(
            port=port,
            is_open=True,
            status="Open",
            banner=banner,
            service_hint=service_hint,
            error=banner_error,
        )
    except socket.timeout:
        return ScanResult(
            port=port,
            is_open=False,
            status="Timed Out",
            banner="",
            service_hint=service_hint,
            error="Connection attempt timed out.",
        )
    except OSError as exc:
        return ScanResult(
            port=port,
            is_open=False,
            status="Error",
            banner="",
            service_hint=service_hint,
            error=str(exc),
        )
    finally:
        sock.close()


def classify_closed_port(port: int, service_hint: str, connection_code: int) -> ScanResult:
    if connection_code == 10061:
        status = "Closed"
        error = "Connection refused."
    elif connection_code == 10060:
        status = "Timed Out"
        error = "Connection timed out."
    else:
        status = "Closed"
        error = f"Port did not accept the connection (code {connection_code})."

    return ScanResult(
        port=port,
        is_open=False,
        status=status,
        banner="",
        service_hint=service_hint,
        error=error,
    )


def grab_service_banner(sock: socket.socket, host: str, port: int, timeout: float) -> tuple[str, str]:
    try:
        response = request_banner_bytes(sock, host, port, timeout)
        if not response:
            return "", "Port is open but no banner was returned."
        return response.decode("utf-8", errors="ignore").strip(), ""
    except socket.timeout:
        return "", "Banner request timed out."
    except OSError as exc:
        return "", f"Banner grab failed: {exc}"


def request_banner_bytes(sock: socket.socket, host: str, port: int, timeout: float) -> bytes:
    if port in {80, 81, 88, 3000, 5000, 7001, 8000, 8008, 8080, 8081, 8888}:
        sock.sendall(build_http_probe(host))
        return sock.recv(1024)

    if port in {443, 4443, 8443}:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with context.wrap_socket(sock, server_hostname=host) as tls_sock:
            tls_sock.settimeout(timeout)
            tls_sock.sendall(build_http_probe(host))
            return tls_sock.recv(1024)

    sock.sendall(b"\r\n")
    return sock.recv(1024)


def build_http_probe(host: str) -> bytes:
    return (
        f"HEAD / HTTP/1.0\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: PortScanner/1.0\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("utf-8")


def run_scan(
    host: str,
    start_port: int,
    end_port: int,
    timeout: float,
    grab_banner: bool,
    workers: int = 100,
    progress_callback: Callable[[int, int, ScanResult], None] | None = None,
) -> tuple[list[ScanResult], str]:
    validate_scan_inputs(host, start_port, end_port, timeout)
    normalized_host, resolved_ip = resolve_target(host)

    ports = list(range(start_port, end_port + 1))
    total = len(ports)
    max_workers = max(1, min(workers, total, 300))

    results: list[ScanResult] = []
    completed = 0

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(scan_port, normalized_host, port, timeout, grab_banner): port
            for port in ports
        }

        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            completed += 1
            if progress_callback is not None:
                progress_callback(completed, total, result)

    results.sort(key=lambda item: item.port)
    return results, resolved_ip
