# Hardshard

## Overview
Hardshard is an offensive security tool designed for penetration testers and red team operators to enumerate, analyze, and exploit Elasticsearch clusters. It is a work in progress.

## Usage
Run the main application:
```sh
python hardshard.py [options]
```

### Example Options
- `--host <elasticsearch_host>`: Specify the Elasticsearch host (default: localhost).
- `--port <port>`: Specify the port (default: 9200).
- `--output <format>`: Output format (`table`, `json`, `csv`).
- `--filter <query>`: Filter shards or indices by name or pattern.

### Example Command
```sh
python hardshard.py --host 127.0.0.1 --output json --filter my_index*
```

<img width="612" alt="image" src="https://github.com/user-attachments/assets/a9c3166b-3529-4150-9408-b03a380343f0" />
