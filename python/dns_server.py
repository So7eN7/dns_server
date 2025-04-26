import socket

def main():
    HOST = "localhost"
    PORT = 2053
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server_socket.bind((HOST, PORT))
    print("Listening on: localhost:2053...")

    while True:
        try:
            data, client_socket = server_socket.recvfrom(1024)
            print(f"Received {len(data)} bytes from {client_socket}: {data.hex()}")

            server_socket.sendto(data, client_socket)
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    main()
