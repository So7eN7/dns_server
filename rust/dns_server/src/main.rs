use std::{net::UdpSocket, u16};

const ADDR: &str = "localhost:2053";

struct DnsHeader {
    id: u16,
    qr: u8,
    qdcount: u16,
}

fn parse_dns_header(data: &[u8]) -> Option<DnsHeader> {
   if data.len() < 12 {
       return None;
   } 
   let id = u16::from_be_bytes([data[0], data[1]]);
   let flags = u16::from_be_bytes([data[2], data[3]]);
   let qr = ((flags >> 15) & 1) as u8;
   let qdcount = u16::from_be_bytes([data[4], data[5]]);
   Some(DnsHeader { id, qr, qdcount })
}

fn main() -> std::io::Result<()> {
    let socket = UdpSocket::bind(ADDR)?;
    println!("Listening on {}", ADDR);

    let mut buf = [0; 1024];

    loop {
        let (amt, src) = socket.recv_from(&mut buf)?;
        println!("Received {} bytes from {}: {:x?}", amt, src, &buf[..amt]);

        if let Some(header) = parse_dns_header(&buf[..amt]) {
            println!("Parsed header: ID={}, QR={}, QDCOUNT={}", 
                      header.id, header.qr, header.qdcount);
        }
        socket.send_to(&buf[..amt], src)?;
    }
}
