import dns.dnssec
import dns.exception
import dns.message
import dns.query
import dns.rdataclass
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

def query(name: str, type: str, servers: list[str], sec=False):
    q = dns.message.make_query(name, type, want_dnssec=sec)

    response = None
    for server in servers:
        try:
            # print(f"Querying {name} {type} @{server}")
            response = dns.query.udp(q, server, timeout=5)
            break
        except dns.exception.Timeout:
            continue

    return response

def select_rdatatype(record_type: str):
    rtype = None
    record_type = record_type.upper()

    if record_type == "NS":
        rtype = dns.rdatatype.NS
    elif record_type == "A":
        rtype = dns.rdatatype.A
    elif record_type == "MX":
        rtype = dns.rdatatype.MX
    elif record_type == "DNSKEY":
        rtype = dns.rdatatype.DNSKEY
    elif record_type == "RRSIG":
        rtype = dns.rdatatype.RRSIG
    
    return rtype

def extract_record(response_set: dns.rrset.RRset, record_type: str):
    recs = []
    rtype = select_rdatatype(record_type)
    if not rtype:
        print(f"Not supported record type: {record_type}")
        return recs

    for rrset in response_set:
        for rdata in rrset:
            if rdata.rdtype == rtype:  # Look for records.
                recs.append(rdata.to_text())  # Get records.
    return recs

def extract_rdata(response_set: dns.rrset.RRset, record_type: str):
    data = []
    rtype = select_rdatatype(record_type)
    for rrset in response_set:
        for rdata in rrset:
            if rdata.rdtype == rtype:  # Look for records.
                data.append(rdata)  # Get records.
    return data

def check_sec(response: dns.message.Message, name):
    # Get all the signatures.
    rrsig_rrset = response.find_rrset(dns.message.ANSWER, name, dns.rdataclass.IN, dns.rdatatype.RRSIG)
    record_rrset = response.find_rrset(dns.message.ANSWER, name, dns.rdataclass.IN, dns.rdatatype.A)
    # print(f"Got rrsig: {rrsig_rrset}")

    # Request for dnskey.
    key_res = recurse(name, "DNSKEY")
    dnskey_rrset = key_res.find_rrset(dns.message.ANSWER, name, dns.rdataclass.IN, dns.rdatatype.DNSKEY)
    # print(f"Got dnskey: {dnskey_rrset} for {name}")

    print([key for key in dnskey_rrset])
    dns.dnssec.validate_rrsig(record_rrset, rrsig_rrset, {dnskey_rrset.name: dnskey_rrset})
    pass

def recurse(name: str, record_type: str, query_server_ips: list[str] = root_servers, sec=False):
    response = query(name, record_type, query_server_ips, sec)
    if response and response.answer:
        return response

    # print(f"Didn't find answer section, querying for additional section...")
    if response and response.additional:
        additional_ips = extract_record(response.additional, "A")
        return recurse(name, record_type, additional_ips, sec)  # Return the IP address
    
    # print(f"Didn't find a additional section, looking for authorities...")
    if response and response.authority:
        authority_ns = extract_record(response.authority, "NS")
        res = None
        for ns in authority_ns:
            if res:
                break
            res = recurse(ns, "A", root_servers, sec)
        ns_ips = extract_record(res.answer, "A")
        return recurse(name, record_type, ns_ips, sec)

if __name__ == "__main__":
    name, record_type = sys.argv[1], sys.argv[2]
    want_sec = record_type.upper() == "A"

    start = time.perf_counter()
    res = recurse(name, record_type, root_servers, want_sec)
    if want_sec:
        check_sec(res, name)
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
