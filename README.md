# Python Port Scanner

A simple command-line port scanner written in Python. It scans a target host and a range of TCP ports using threads, prints open ports with common service names, and saves the results to a JSON file.

## Requirements

- Python 3.6. (or newer)

## Usage

```bash
python scanner.py <host> <start_port> <end_port>
```

Example:

```bash
python scanner.py 127.0.0.1 1 1024
```

## Options

- `-t`, `--timeout`: Set the socket timeout in seconds. Default is `0.5`.
- `-o`, `--output`: Set the JSON output file. Default is `scan_results.json`.

Example with options:

```bash
python scanner.py 127.0.0.1 1 1024 -t 1.0 -o results.json
```

## Output

- The script prints open ports as it finds them.
- The script saves results to the JSON file with the host, range, timeout, and open ports.

## Notes

- The scanner uses up to 100 concurrent threads.
- Port numbers must be between `1` and `65535`.
