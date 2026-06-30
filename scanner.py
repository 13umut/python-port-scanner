import argparse
import json
import socket
import threading
from queue import Queue

# max thread numbers
MAX_THREADS = 100

# def timeout for socket connection
DEFAULT_TIMEOUT = 0.5

# port-to-service names
COMMON_SERVICES = {
    20: "FTP",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MSRPC",
    143: "IMAP",
    161: "SNMP",
    445: "Microsoft-DS",
    443: "HTTPS",
    465: "SMTPS",
    587: "SMTP",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-ALT",
}


def parse_arguments():
    """Read command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Simple threaded TCP port scanner."
    )
    parser.add_argument(
        "host",
        help="Target host or IP address to scan.",
    )
    parser.add_argument(
        "start_port",
        type=int,
        help="First port in the scan range.",
    )
    parser.add_argument(
        "end_port",
        type=int,
        help="Last port in the scan range.",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"Timeout in seconds for each port scan (default: {DEFAULT_TIMEOUT}).",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="scan_results.json",
        help="JSON file where scan results are saved.",
    )
    return parser.parse_args()


def get_service_name(port):
    """Return a friendly service name for a port if known."""
    return COMMON_SERVICES.get(port, "Unknown")


def scan_port(host, port, timeout, results, lock):
    """Try to connect to a single port and record if it is open."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            connection_result = sock.connect_ex((host, port))
            if connection_result == 0:
                service = get_service_name(port)
                data = {"port": port, "service": service}
                with lock:
                    results.append(data)
                    print(f"Open port: {port} ({service})")
        except socket.error:
            # ignore port if there is a socket error
            pass


def worker(host, timeout, queue, results, lock):
    """Worker function used by each thread to consume port numbers."""
    while True:
        port = queue.get()
        if port is None:
            queue.task_done()
            break
        scan_port(host, port, timeout, results, lock)
        queue.task_done()


def run_scan(host, start_port, end_port, timeout):
    """Coordinate the threaded port scan and return open ports."""
    port_queue = Queue()
    results = []
    lock = threading.Lock()

    # start worker threads
    threads = []
    for _ in range(MAX_THREADS):
        thread = threading.Thread(
            target=worker,
            args=(host, timeout, port_queue, results, lock),
            daemon=True,
        )
        thread.start()
        threads.append(thread)

    # enqueue all port numbers
    for port in range(start_port, end_port + 1):
        port_queue.put(port)

    # Signal the worker threads to stop when queue is finished.
    for _ in range(MAX_THREADS):
        port_queue.put(None)

    port_queue.join()

    return sorted(results, key=lambda item: item["port"])


def save_results(output_file, host, start_port, end_port, timeout, results):
    """Write the scan results to a JSON file."""
    payload = {
        "target": host,
        "start_port": start_port,
        "end_port": end_port,
        "timeout": timeout,
        "open_ports": results,
    }
    with open(output_file, "w", encoding="utf-8") as file:
        json.dump(payload, file, indent=4)


def main():
    args = parse_arguments()

    # Validate port range before scanning.
    if args.start_port < 1 or args.end_port > 65535:
        print("Port numbers must be between 1 and 65535.")
        return
    if args.start_port > args.end_port:
        print("Start port must be less than or equal to end port.")
        return

    print(
        f"Scanning {args.host} from port {args.start_port} "
        f"to {args.end_port} with timeout {args.timeout}s..."
    )

    open_ports = run_scan(
        args.host,
        args.start_port,
        args.end_port,
        args.timeout,
    )

    save_results(
        args.output,
        args.host,
        args.start_port,
        args.end_port,
        args.timeout,
        open_ports,
    )

    print(f"Scan complete. Results saved to {args.output}")


if __name__ == "__main__":
    main()
