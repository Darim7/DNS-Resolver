import dns.exception
import dns.message
import dns.query
import dns.rrset
import dns.rdatatype

import time
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
            # print(f"Querying {name} {type} @{server}")
            response = dns.query.udp(q, server, timeout=5)
            break
        except dns.exception.Timeout:
            continue

    return response

def extract_record(response_set: dns.rrset.RRset, record_type: str):
    ips = []
    rtype = None
    record_type = record_type.upper()

    if record_type == "NS":
        rtype = dns.rdatatype.NS
    elif record_type == "A":
        rtype = dns.rdatatype.A
    elif record_type == "MX":
        rtype = dns.rdatatype.MX
    else:
        print(f"Invalid record type.")
        return ips

    for rrset in response_set:
        for rdata in rrset:
            if rdata.rdtype == rtype:  # Look for A records
                    ips.append(rdata.to_text())  # Get ip
    return ips

def recurse(name: str, record_type: str, query_server_ips: list[str]):
    response = query(name, record_type, query_server_ips)
    if response and response.answer:
        return response

    # print(f"Didn't find answer section, querying for additional section...")
    # print(response)
    if response and response.additional:
        additional_ips = extract_record(response.additional, "A")
        # print(additional_ips)
        return recurse(name, record_type, additional_ips)  # Return the IP address
    
    # print(f"Didn't find a additional section, looking for authorities...")
    if response and response.authority:
        authority_ns = extract_record(response.authority, "NS")
        res = None
        for ns in authority_ns:
            if res:
                break
            res = recurse(ns, "A", root_servers)
        if not res:
            return None
        ns_ips = extract_record(res.answer, "A")
        return recurse(name, record_type, ns_ips)

if __name__ == "__main__":
    name, record_type = sys.argv[1], sys.argv[2]

    start = time.perf_counter()
    res = recurse(name, record_type, root_servers)
    end = time.perf_counter()
    query_time = (end - start) * 1000

    print("QUESTION SECTION:")
    for rrset in res.question:
        print(rrset.to_text())

    print("\nANSWER SECTION:")
    for rrset in res.answer:
        print(rrset.to_text())

    print(f"\nQuery time: {int(query_time)} msec")
    print(f"WHEN: {time.strftime('%a %b %d %H:%M:%S %Y')}")
    print(f"MSG SIZE rcvd: {len(res.to_wire())}")