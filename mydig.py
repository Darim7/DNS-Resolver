import dns.exception
import dns.message
import dns.query
import sys

# Root servers from iana.org
root_servers = [
    "198.41.0.4", "170.247.170.2", "192.33.4.12",
    "199.7.91.13", "192.203.230.10", "192.5.5.241",
    "192.112.36.4", "198.97.190.53", "192.36.148.17",
    "192.58.128.30", "193.0.14.129", "199.7.83.42", "202.12.27.33"
]

def query(name: str, type: str, servers: list[str]):
    q = dns.message.make_query(name, type)

    response = None
    for server in servers:
        try:
            response = dns.query.udp(q, server, timeout=5)
            break
        except dns.exception.Timeout:
            continue

    return response

if __name__ == "__main__":
    name, record_type = sys.argv[1], sys.argv[2]
    print(f"You just asked: {name} IN {record_type}")
    res = query(name, record_type, root_servers)
    print(f"You got an answer: {res.to_text()}")
