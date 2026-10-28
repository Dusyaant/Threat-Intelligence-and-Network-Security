"""Q2 - Simple vulnerability assessment: TCP connect port scanner."""
import socket, threading
from concurrent.futures import ThreadPoolExecutor

COMMON = {21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",110:"POP3",443:"HTTPS",3306:"MySQL",8080:"HTTP-Alt"}

def scan_port(host, port, timeout=0.3):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return port if s.connect_ex((host, port)) == 0 else None

# Start two demo listeners so the scan has something to find (local lab only)
servers = []
for p in (8080, 3306):
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("127.0.0.1", p)); srv.listen(5); servers.append(srv)
    except OSError:
        pass

target, ports = "127.0.0.1", range(1, 1025)
print(f"Scanning {target} ports 1-1024 and 3306, 8080 ...")
with ThreadPoolExecutor(100) as ex:
    results = list(ex.map(lambda p: scan_port(target, p), list(ports) + [3306, 8080]))
open_ports = sorted(p for p in results if p)
print(f"\n{'PORT':<8}{'STATE':<8}SERVICE")
for p in open_ports:
    print(f"{p:<8}{'open':<8}{COMMON.get(p, 'unknown')}")
print(f"\nTotal open ports found: {len(open_ports)}")
for s in servers: s.close()
