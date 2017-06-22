# pyScan

pyScan is a light scanner which can be run independently or import as a python module.

# Requirement

`Python > 3.0`

# Usage

### 1. run independently

```
git clone https://github.com/gsfish/pyScan.git
python scan.py -t 10 -o result.txt
```

### 2. import as module

```
import scan

task = scan.Scan()
task.set_targets(hosts, ports, thread, method...)
task.start()

# return True / False
port_status = task.check_port(host, port, method, timeout...)

# return a dict
# {host: [port_1, port_2, port_3...]}
host_result = task.host_scan(host, ports, method, timeout=None...)
```
