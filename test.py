import dns.exception
import dns.message
import dns.query
import dns.rdatatype
import dns.rdtypes
import dns.rrset

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

def extractNS(response: dns.message.Message):
    name_servers = []

    if response.authority:
        for rrset in response.authority:
            if rrset.rdtype == dns.rdatatype.NS:  # Look for NS records
                for rdata in rrset:
                    name_servers.append(rdata.to_text())  # Get nameserver names

    return name_servers

def extractIP(response_set: dns.rrset.RRset):
    ips = []
    for rrset in response_set:
        for rdata in rrset:
            if rdata.rdtype == dns.rdatatype.A:  # Look for A records
                    ips.append(rdata.to_text())  # Get ip
    return ips

def recurse(name: str, record_type: str, query_server_ips: list[str]):
    response = query(name, record_type, query_server_ips)
    if response and response.answer:
        return response.answer

    print(f"Didn't find answer section, querying for additional section...")
    # print(response)
    if response and response.additional:
        additional_ips = extractIP(response.additional)
        print(additional_ips)
        return recurse(name, record_type, additional_ips)  # Return the IP address
    
    print(f"Didn't find a additional section, looking for authorities...")
    # if response and response.answer:
    #     for rrset in response.answer:
    #         for rdata in rrset:
    #             return rdata.to_text()  # Return the IP address

# print(resolve_a_gtld_server())
print(recurse("reddit.com", "A", root_servers))
