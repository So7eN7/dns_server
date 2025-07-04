import socket # Socket programming
import struct # Byte representation
import threading # Multi-threading
import sqlite3 # Database

HOST = "localhost"
PORT = 2053

# Parses the 12-byte DNS header to extract ID, QR flag, and QDCOUNT
def parse_dns_header(data):
    try:
        # Unpack header fields: ID, flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
        id, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", data[:12])
        # Extract QR (query/response) bit from flags
        qr = (flags >> 15) & 1
        return {
            "id": id,
            "qr": qr,
            "qdcount": qdcount
        }
    except:
        # Return None for malformed headers
        return None

# Builds the DNS response header with specified ID and RCODE
def build_dns_header(query_id, rcode=0):
    id = query_id
    # Set QR=1 (response) and RCODE
    flags = (1 << 15) | rcode  
    # Set counts: QDCOUNT=1, ANCOUNT=1 for valid responses; 0 for errors
    qdcount = 1 if rcode == 0 else 0
    ancount = 1 if rcode == 0 else 0
    nscount = 0
    arcount = 0
    # Pack header fields into 12 bytes
    return struct.pack(">HHHHHH", id, flags, qdcount, ancount, nscount, arcount)

# Parses the DNS question section to extract QNAME, QTYPE and QCLASS
def parse_dns_question(data, offset):
    try:
        # Parse QNAME: sequence of length-prefixed labels ending with 0
        labels = []
        while True:
            length = data[offset]
            if length == 0:
                offset += 1
                break
            offset += 1
            label = data[offset:offset+length].decode("ascii")
            labels.append(label)
            offset += length
        qname = ".".join(labels)
        # Parse QTYPE and QCLASS (2 bytes each)
        qtype, qclass = struct.unpack(">HH", data[offset:offset+4])
        offset += 4
        return {
            "qname": qname,
            "qtype": qtype,
            "qclass": qclass
        }, offset
    except:
        # Return None for malformed questions
        return None, offset

# Builds the DNS answer section for A, MX or CNAME records
def build_dns_answer(qname, qtype):
    record = query_dns_record(qname, qtype)
    if record is None:
        raise ValueError("No record found.")
    rdata_str, ttl = record

    # Use pointer to QNAME
    name = struct.pack(">H", 0xc00c)  
    qclass = 1 # IN (Internet)
    ttl = 3600 # Time to live (1 hour)
    if qtype == 1: # A record
        octets = [int(x) for x in rdata_str.split(".")]
        rdata = struct.pack(">BBBB", *octets)
        rdlength = 4
    elif qtype == 5: # CNAME record 
        # Encode target domain
        rdata = encode_domain_name(rdata_str)
        rdlength = len(rdata)
    elif qtype == 15: # MX record
        # Encode preference (10) and mail serve
        preference, mail_server = rdata_str.split(" ", 1)
        rdata = struct.pack(">H", int(preference)) + encode_domain_name(mail_server)
        rdlength = len(rdata)    
    else:
        raise ValueError("Unsupported QTYPE")  
    # Pack answer fields: NAME, TYPE, CLASS, TTL, RDLENGTH, RDATA
    return struct.pack(">HHHIH", 0xc00c, qtype, qclass, ttl, rdlength) + rdata

'''
Encodes a domain name into DNS format
e.g, "example.com" -> [7]example[3]com[0]    
'''
def encode_domain_name(domain):
    parts = domain.split(".")
    result = b""
    for part in parts:
        # Add length prefix and ASCII-encoded label
        result += bytes([len(part)]) + part.encode("ascii")
    # Terminate with zero byte
    result += b"\x00"
    return result

# Fetch records from the database
def query_dns_record(qname, qtype):
    conn = sqlite3.connect("dns.db", check_same_thread=False)
    cursor = conn.cursor()
    # Query for matching qname and qtype
    cursor.execute("SELECT rdata, ttl FROM dns_records WHERE qname = ? AND qtype = ?",
        (qname, qtype)
        )   
    result = cursor.fetchone()
    conn.close()
    return result # Returns (rdata, ttl) or None

# Processes a DNS packer (query) and builds a response
def process_dns_packet(data):
    # Parse header
    header = parse_dns_header(data)
    if header is None or header["qdcount"] == 0:
        print("Invalid packet")
        return None
    print(f"Parsed header: ID:{header['id']}, QR:{header['qr']}, QDCOUNT:{header['qdcount']}")

    # Parse question
    question, q_end = parse_dns_question(data, 12)
    if question is None:
        print("Invalid question")
        return None
    print(f"Parsed question: QNAME={question['qname']}, QTYPE={question['qtype']}, QCLASS={question['qclass']}")

    # Default response: RCODE=4 (NOTIMP) for unsupported queries
    response = build_dns_header(header['id'], rcode=4)
    # Handle supported queries: QCLASS=1, QTYPE=1 (A), 5 (CNAME) or 15 (MX)
    if question["qclass"] == 1 and question["qtype"] in [1, 5, 15]:
        try:
            response = build_dns_header(header["id"])
            # Echo questoin section
            response += data[12:q_end]
            # Add answer section
            response += build_dns_answer(question["qname"], question["qtype"])
        except ValueError: # No record found or unsupported qtype
            response = build_dns_header(header["id"], rcode=4)

    return response
    
# Runs the UDP server to handle DNS queries
def udp_server():
    # Create UDP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    print("UDP Server listening on: localhost:2053...")

    while True:
        try:
            # Receive query (max 512 bytes for UDP)
            data, client_addr = server_socket.recvfrom(1024)
            print(f"UDP: received {len(data)} bytes from {client_addr}: {data.hex()}")
            # Process query and send response
            response = process_dns_packet(data)
            if response:
                print(f"UDP: Sending response: {response.hex()}")
                server_socket.sendto(response, client_addr)
        except Exception as e:
            print(f"UDP Error: {e}")

# Runs the TCP server to handle DNS queries
def tcp_server():
    #Create TCP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    print("TCP Server listening on: localhost:2053")

    while True:
        try:
            # Accept client connection
            client_socket, client_addr = server_socket.accept()
            print(f"TCP: New connection from {client_addr}")
            # Read 2-byte length prefix
            length_data = client_socket.recv(2)
            if len(length_data) != 2:
                print("TCP: Invalid length prefix")
                client_socket.close()
                continue
            # Read packet based on length
            length = struct.unpack(">H", length_data)[0]
            data = client_socket.recv(length)
            if len(data) != length:
                print("TCP: Incomplete packet")
                client_socket.close()
                continue

            print(f"TCP: Received {len(data)} bytes from {client_socket}: {data.hex()}")
            # Process query
            response = process_dns_packet(data)
            if response:
                # Add 2-byte length prefix to response
                response =  struct.pack(">H", len(response)) + response
                print(f"TCP: Sending response: {response.hex()}")
                client_socket.send(response)
            client_socket.close()

        except Exception as e:
            print(f"TCP Error: {e}")

# Main function to start UDP and TCP servers in separate threads
def main():
    # Create threads for UDP and TCP servers
    udp_thread = threading.Thread(target=udp_server)
    tcp_thread = threading.Thread(target=tcp_server)

    # Start threads
    udp_thread.start()
    tcp_thread.start()
    # Wait for threads to complete
    udp_thread.join()
    tcp_thread.join()

if __name__ == "__main__":
    main()
