# Hardshard

## Overview
Hardshard is an offensive security tool designed for penetration testers and red team operators to easily navigate Elasticsearch clusters. It is a work in progress.

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
<img width="615" alt="image" src="https://github.com/user-attachments/assets/3be599a9-4d19-4cfd-88b1-b74fb0174ba7" />

<img width="612" alt="image" src="https://github.com/user-attachments/assets/a9c3166b-3529-4150-9408-b03a380343f0" />
