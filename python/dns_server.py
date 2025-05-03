import socket
import struct

HOST = "localhost"
PORT = 2053

def parse_dns_header(data):
    id, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", data[:12])
    qr = (flags >> 15) & 1 
    return {
        "id": id,
        "qr": qr,
        "qdcount": qdcount
    }

def build_dns_header(query_id):
    id = query_id
    flags = (1 << 15)
    qdcount = 1 
    ancount = 1 
    nscount = 0
    arcount = 0
    return struct.pack(">HHHHHH", id, flags, qdcount, ancount, nscount, arcount)

def parse_dns_question(data, offset):
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
    
    qtype, qclass = struct.unpack(">HH", data[offset:offset+4])
    offset += 4

    return {
        "qname": qname,
        "qtype": qtype,
        "qclass": qclass
    }, offset

def build_dns_answer():
    name = struct.pack(">H", 0xc00c)  # Pointer to QNAME
    qtype = 1
    qclass = 1
    ttl = 3600
    rdlength = 4
    rdata = struct.pack(">BBBB", 93, 184, 216, 34)  # 93.184.216.34
    return struct.pack(">HHHIH", 0xc00c, qtype, qclass, ttl, rdlength) + rdata

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server_socket.bind((HOST, PORT))
    print("Listening on: localhost:2053...")

    while True:
        try:
            data, client_socket = server_socket.recvfrom(1024)
            print(f"Received {len(data)} bytes from {client_socket}: {data.hex()}")

            if len(data) >= 12:
                header = parse_dns_header(data)
                print(f"Parsed header: ID={header['id']}, QR={header['qr']}, QDCOUNT={header['qdcount']}")
                
                if header["qdcount"] > 0:
                    question, q_end = parse_dns_question(data, 12)
                    print(f"Parsed question: QNAME={question['qname']}, QTYPE={question['qtype']}, QCLASS={question['qclass']}")

                    response = build_dns_header(header["id"])
                    response += data[12:q_end]  
                    response += build_dns_answer()
                    print(f"Sending response: {response.hex()}")                  
                    server_socket.sendto(response, client_socket)
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    main()
