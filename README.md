# DNS Server Project

This project implements a **DNS server** in **Python** and **Rust** that handles **A**, **MX**, and **CNAME** record queries over **UDP** and **TCP** on `localhost:2053`.
There is also a database branch that uses a SQlite database for records.

## Running the server
### Python3
```bash
python3 dns_server.py
```
### Rust
```
cd rust/dns_server
cargo run
```
## Testing
Use dig to test the server
### UDP
```bash
dig @localhost -p 2053 example.com
dig @localhost -p 2053 -t MX example.com
dig @localhost -p 2053 -t CNAME www.example.com
dig @localhost -p 2053 -t TXT example.com
```

### TCP
```bash
dig @localhost -p 2053 example.com +tcp
dig @localhost -p 2053 -t MX example.com +tcp
dig @localhost -p 2053 -t CNAME www.example.com +tcp
dig @localhost -p 2053 -t TXT example.com +tcp
```

### Malformed packets
Use netcat for this one.
```bash
echo -n "123" | nc -u 127.0.0.1 2053
echo -n "12" | nc 127.0.0.1 2053
```
