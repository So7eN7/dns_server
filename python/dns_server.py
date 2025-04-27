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

            server_socket.sendto(data, client_socket)
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    main()
