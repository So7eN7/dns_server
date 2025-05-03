import socket
import struct
import threading

HOST = "localhost"
PORT = 2053

def parse_dns_header(data):
    try:
        id, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", data[:12])
        qr = (flags >> 15) & 1
        return {
            "id": id,
            "qr": qr,
            "qdcount": qdcount
        }
    except:
        return None

def build_dns_header(query_id, rcode=0):
    id = query_id
    flags = (1 << 15) | rcode  
    qdcount = 1 if rcode == 0 else 0
    ancount = 1 if rcode == 0 else 0
    nscount = 0
    arcount = 0
    return struct.pack(">HHHHHH", id, flags, qdcount, ancount, nscount, arcount)

def parse_dns_question(data, offset):
    try:
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
    except:
        return None, offset

def build_dns_answer(qtype):
    name = struct.pack(">H", 0xc00c)  
    qclass = 1
    ttl = 3600
    if qtype == 1:
        rdlength = 4
        rdata = struct.pack(">BBBB", 94, 184, 216, 34)
    elif qtype == 5:
        rdata = encode_domain_name("example.com")
        rdlength = len(rdata)
    elif qtype == 15:
        rdata = struct.pack(">H", 10) + encode_domain_name("mail.exmaple.com")
        rdlength = len(rdata)
    else:
        raise ValueError("Unsupported QTYPE")  
    return struct.pack(">HHHIH", 0xc00c, qtype, qclass, ttl, rdlength) + rdata

def encode_domain_name(domain):
    parts = domain.split(".")
    result = b""
    for part in parts:
        result += bytes([len(part)]) + part.encode("ascii")
    result += b"\x00"
    return result

def process_dns_packet(data):
    header = parse_dns_header(data)
    if header is None or header["qdcount"] == 0:
        print("Invalid packet")
        return None
    print(f"Parsed header: ID:{header['id']}, QR:{header['qr']}, QDCOUNT:{header['qdcount']}")

    question, q_end = parse_dns_question(data, 12)
    if question is None:
        print("Invalid question")
        return None
    print(f"Parsed question: QNAME={question['qname']}, QTYPE={question['qtype']}, QCLASS={question['qclass']}")

    response = build_dns_header(header['id'], rcode=4)
    if question["qclass"] == 1 and question["qtype"] in [1, 5, 15]:
        response = build_dns_header(header["id"])
        response += data[12:q_end]
        response += build_dns_answer(question["qtype"])

    return response
    
def udp_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    print("UDP Server listening on: localhost:2053...")

    while True:
        try:
            data, client_addr = server_socket.recvfrom(1024)
            print(f"UDP: received {len(data)} bytes from {client_addr}: {data.hex()}")

            response = process_dns_packet(data)
            if response:
                print(f"UDP: Sending response: {response.hex()}")
                server_socket.sendto(response, client_addr)
        except Exception as e:
            print(f"UDP Error: {e}")

def tcp_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    print("TCP Server listening on: localhost:2053")

    while True:
        try:
            client_socket, client_addr = server_socket.accept()
            print(f"TCP: New connection from {client_addr}")

            length_data = client_socket.recv(2)
            if len(length_data) != 2:
                print("TCP: Invalid length prefix")
                client_socket.close()
                continue

            length = struct.unpack(">H", length_data)[0]
            data = client_socket.recv(length)
            if len(data) != length:
                print("TCP: Incomplete packet")
                client_socket.close()
                continue

            print(f"TCP: Received {len(data)} bytes from {client_socket}: {data.hex()}")

            response = process_dns_packet(data)
            if response:
                response =  struct.pack(">H", len(response)) + response
                print(f"TCP: Sending response: {response.hex()}")
                client_socket.send(response)
            client_socket.close()

        except Exception as e:
            print(f"TCP Error: {e}")

def main():
    udp_thread = threading.Thread(target=udp_server)
    tcp_thread = threading.Thread(target=tcp_server)

    udp_thread.start()
    tcp_thread.start()

    udp_thread.join()
    tcp_thread.join()

if __name__ == "__main__":
    main()
