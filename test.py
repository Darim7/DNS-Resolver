import dns.exception
import dns.message
import dns.query
import dns.rdatatype
import dns.rdtypes

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

def resolve_nameserver_ip(ns_name):
    """
    Resolve the IP address of a nameserver iteratively.
    """
    response = query(ns_name, "A", root_servers)  # Query root servers for the NS name
    if response and response.additional:
        for rrset in response.additional:
            for rdata in rrset:
                return rdata.to_text()  # Return the IP address
    
    if response and response.answer:
        for rrset in response.answer:
            for rdata in rrset:
                return rdata.to_text()  # Return the IP address
            

    return None

def resolve_a_gtld_server():
    # Step 1: Query the root servers for a.gtld-servers.net
    root_response = query("a.gtld-servers.net.", "A", root_servers)

    # Step 2: Extract NS records for .net
    ns_records = extractNS(root_response)
    if not ns_records:
        raise Exception("No NS records found for .net in root response.")

    # Step 3: Resolve the IP of one .net nameserver
    ns_ip = None
    for ns_name in ns_records:
        ns_ip = resolve_nameserver_ip(ns_name)
        if ns_ip:
            break
    if not ns_ip:
        raise Exception("Failed to resolve the IP of any .net nameserver.")

    # Step 4: Query the .net nameserver for a.gtld-servers.net
    a_gtld_ip = query("a.gtld-servers.net.", "A", [ns_ip])
    if not a_gtld_ip:
        raise Exception("Failed to resolve the IP of a.gtld-servers.net.")

    return a_gtld_ip

msg = query("m.gtld-servers.net.", dns.rdatatype.A, ["198.41.0.4"])
print(msg)
ns = extractNS(msg)
print(ns)

print(resolve_a_gtld_server())
