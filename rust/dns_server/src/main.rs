use tokio::net::{TcpListener, UdpSocket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

fn build_dns_answer(qtype: u16) -> Vec<u8> {
    let mut answer = Vec::new();
    answer.extend_from_slice(&0xc00c_u16.to_be_bytes());
    answer.extend_from_slice(&qtype.to_be_bytes()); 
    answer.extend_from_slice(&1u16.to_be_bytes()); 
    answer.extend_from_slice(&3600u32.to_be_bytes()); 
    let rdata = match qtype {
        1 => vec![93, 184, 216, 34],
        5 => encode_domain_name("example.com"),
        15 => {
            let mut rdata = vec![0, 10];
            rdata.extend_from_slice(&encode_domain_name("mail.example.com"));
            rdata
        }
        _ => panic!("Unsupported QTYPE"),
    };
    answer.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    answer.extend_from_slice(&rdata);
    answer
}

fn encode_domain_name(domain: &str) -> Vec<u8> {
    let mut result = Vec::new();
    
    for part in domain.split('.') {
        result.push(part.len() as u8);
        result.extend_from_slice(part.as_bytes());
    }
    result.push(0);
    result
}

fn process_dns_packet(data: &[u8]) -> Option<Vec<u8>> {
    let mut response = Vec::new();
    if let Some(header) = parse_dns_header(&data) {
        println!(
            "Parsed header: ID={}, QR={}, QDCOUNT={}",
            header.id, header.qr, header.qdcount
        );
    if header.qdcount > 0 {
            if let Some((question, q_end)) = parse_dns_question(&data, 12) {
                println!(
                    "Parsed question: QNAME={}, QTYPE={}, QCLASS={}",
                    question.qname, question.qtype, question.qclass
                );

                if question.qclass == 1 && (question.qtype == 1 || question.qtype == 5 || question.qtype == 15) {
                    response.extend_from_slice(&build_dns_header(header.id, 0));
                    response.extend_from_slice(&data[12..q_end]);
                    response.extend_from_slice(&build_dns_answer(question.qtype));
                } else {
                    response.extend_from_slice(&build_dns_header(header.id, 4));
                }
                return Some(response);
            }
        }
    }
    None
}


#[tokio::main]

async fn main() -> std::io::Result<()> {
    let udp_task = tokio::spawn(async {
        let socket = UdpSocket::bind(ADDR).await.unwrap();
        println!("UDP server listening on localhost:2053");
        let mut buf = [0; 1024];
        loop {
            let (amt, src) = socket.recv_from(&mut buf).await.unwrap();
            println!("UDP: Received {} bytes from {}: {:x?}", amt, src, &buf[..amt]);
            if let Some(response) = process_dns_packet(&buf[..amt]) {
                println!("UDP: Sending response: {:x?}", response);
                socket.send_to(&response, src).await.unwrap();
            }
        }
    });

    let tcp_task = tokio::spawn(async {
        let listener = TcpListener::bind(ADDR).await.unwrap();
        println!("TCP server listening on localhost:2053");
        loop {
            let (mut socket, addr) = listener.accept().await.unwrap();
            println!("TCP: New connection from {}", addr);
            tokio::spawn(async move {
                let mut length_buf = [0; 2];
                if socket.read_exact(&mut length_buf).await.is_err() {
                    println!("TCP: Invalid length prefix");
                    return;
                }
                let length = u16::from_be_bytes(length_buf) as usize;
                let mut buf = vec![0; length];
                if socket.read_exact(&mut buf).await.is_err() {
                    println!("TCP: Incomplete packet");
                    return;
                }
                println!("TCP: Received {} bytes from {}: {:x?}", length, addr, &buf);
                if let Some(mut response) = process_dns_packet(&buf) {
                    let mut response_with_length = (response.len() as u16).to_be_bytes().to_vec();
                    response_with_length.append(&mut response);
                    println!("TCP: Sending response: {:x?}", response_with_length);
                    socket.write_all(&response_with_length).await.unwrap();
                }
            });
        }
    });

    tokio::try_join!(udp_task, tcp_task)?;
    Ok(())
}
