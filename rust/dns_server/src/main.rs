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

fn build_dns_header(query_id: u16, rcode: u16) -> [u8; 12] {
    let id = query_id.to_be_bytes();
    let flags = ((1u16 << 15) | rcode).to_be_bytes();
    let qdcount = if rcode == 0 { 1u16.to_be_bytes() } else { 0u16.to_be_bytes() };
    let ancount = if rcode == 0 { 1u16.to_be_bytes() } else { 0u16.to_be_bytes() };
    let nscount = 0u16.to_be_bytes();
    let arcount = 0u16.to_be_bytes();
    [
        id[0], id[1],
        flags[0], flags[1],
        qdcount[0], qdcount[1],
        ancount[0], ancount[1],
        nscount[0], nscount[1],
        arcount[0], arcount[1],
    ]
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

fn build_dns_answer() -> Vec<u8> {
    let mut answer = Vec::new();
    answer.extend_from_slice(&0xc00c_u16.to_be_bytes());
    answer.extend_from_slice(&1u16.to_be_bytes()); 
    answer.extend_from_slice(&1u16.to_be_bytes()); 
    answer.extend_from_slice(&3600u32.to_be_bytes()); 
    answer.extend_from_slice(&4u16.to_be_bytes()); 
    answer.extend_from_slice(&[93, 184, 216, 34]);
    answer
}

fn main() -> std::io::Result<()> {
    let socket = UdpSocket::bind(ADDR)?;
    println!("Listening on {}", ADDR);

    let mut buf = [0; 1024];

    loop {
        let (amt, src) = socket.recv_from(&mut buf)?;
        println!("Received {} bytes from {}: {:x?}", amt, src, &buf[..amt]);

        let mut response = Vec::new();
        if let Some(header) = parse_dns_header(&buf[..amt]) {
            println!("Parsed header: ID={}, QR={}, QDCOUNT={}", 
                      header.id, header.qr, header.qdcount);

            if header.qdcount > 0 {
                if let Some((question, q_end)) = parse_dns_question(&buf[..amt], 12) {
                    println!("Parsed question: QNAME={}, QTYPE={}, QCLASS={}",
                              question.qname, question.qtype, question.qclass);

                    if question.qtype == 1 && question.qclass == 1 {
                        response.extend_from_slice(&build_dns_header(header.id, 0));
                        response.extend_from_slice(&buf[12..q_end]);
                        response.extend_from_slice(&build_dns_answer());
                    } else {
                        response.extend_from_slice(&build_dns_header(header.id, 4));
                    }
                } else {
                    println!("Invalid question");
                    continue;
                }
            } else {
                println!("No questions");
                continue;
            }
        } else {
            println!("Invalid packet");
            continue;
        }
        println!("Sending response: {:x?}", response);
        socket.send_to(&response, src)?;
    }
}
