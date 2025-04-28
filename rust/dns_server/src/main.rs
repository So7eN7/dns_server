use std::net::UdpSocket;

const ADDR: &str = "localhost:2053";

struct DnsHeader {
    id: u16,
    qr: u8,
    qdcount: u16,
}

struct DnsQuestion {
    qname: String,
    qtype: u16,
    qclass: u16,
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

fn parse_dns_question(data: &[u8], mut offset: usize) -> Option<(DnsQuestion, usize)> {
    let mut labels = Vec::new();
    while offset < data.len() {
        let length = data[offset] as usize;
        if length == 0 {
            offset += 1;
            break;
        }
        offset += 1;
        if offset + length > data.len() {
            return None;
        }
        let label = String::from_utf8(data[offset..offset + length].to_vec()).ok()?;
        labels.push(label);
        offset += length;
    }
    let qname = labels.join(".");

    if offset + 4 > data.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
    let qclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
    offset += 4;

    Some((DnsQuestion { qname, qtype, qclass }, offset))
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

            if header.qdcount > 0 {
                if let Some((question, _)) = parse_dns_question(&buf[..amt], 12) {
                    println!("Parsed question: QNAME={}, QTYPE={}, QCLASS={}",
                              question.qname, question.qtype, question.qclass);
                }
            }
        }
    
        socket.send_to(&buf[..amt], src)?;
    }
}
