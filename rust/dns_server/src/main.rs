use tokio::net::{TcpListener, UdpSocket}; // Async TCP and UDP sockets
use tokio::io::{AsyncReadExt, AsyncWriteExt}; // Async I/O traits

const ADDR: &str = "localhost:2053";

// Structure to hold DNS header fields
struct DnsHeader {
    id: u16,        // Transaction ID
    qr: u8,         // Query/Response flag (0=query, 1=response)
    qdcount: u16,   // Number of questions
}

// Structure to hold DNS question fields
struct DnsQuestion {
    qname: String, // Domain name
    qtype: u16,    // Query type (eg., 1=A, 5=CNAME and 15=MX)
    qclass: u16,   // Query class (1=IN)
}

// Parses the 12-byte DNS header
fn parse_dns_header(data: &[u8]) -> Option<DnsHeader> {
   if data.len() < 12 {
       return None; // Packet too short
   } 
   // Extract fields using big-endian
   let id = u16::from_be_bytes([data[0], data[1]]);
   let flags = u16::from_be_bytes([data[2], data[3]]);
   let qr = ((flags >> 15) & 1) as u8; // QR bit
   let qdcount = u16::from_be_bytes([data[4], data[5]]);
   Some(DnsHeader { id, qr, qdcount })
}

// Builds the DNS response header
fn build_dns_header(query_id: u16, rcode: u16) -> [u8; 12] {
    let id = query_id.to_be_bytes();
    // Set QR=1 and RCODE
    let flags = ((1u16 << 15) | rcode).to_be_bytes();
    // Set counts: QDCOUNT=1, ANCOUNT=1 for valid responses; 0 for errors
    let qdcount = if rcode == 0 { 1u16.to_be_bytes() } else { 0u16.to_be_bytes() };
    let ancount = if rcode == 0 { 1u16.to_be_bytes() } else { 0u16.to_be_bytes() };
    let nscount = 0u16.to_be_bytes();
    let arcount = 0u16.to_be_bytes();
    // Construct 12-byte header
    [
        id[0], id[1],
        flags[0], flags[1],
        qdcount[0], qdcount[1],
        ancount[0], ancount[1],
        nscount[0], nscount[1],
        arcount[0], arcount[1],
    ]
}

// Parses the DNS question section
fn parse_dns_question(data: &[u8], mut offset: usize) -> Option<(DnsQuestion, usize)> {
    // Parse QNAME: length-prefixed labels ending with 0
    let mut labels = Vec::new();
    while offset < data.len() {
        let length = data[offset] as usize;
        if length == 0 {
            offset += 1;
            break;
        }
        offset += 1;
        if offset + length > data.len() {
            return None; // Invalid label length
        }
        let label = String::from_utf8(data[offset..offset + length].to_vec()).ok()?;
        labels.push(label);
        offset += length;
    }
    let qname = labels.join(".");

    if offset + 4 > data.len() {
        return None; // Not enough bytes for QTYPE/QCLASS
    }
    // Parse QTYPE and QCLASS
    let qtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
    let qclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
    offset += 4;

    Some((DnsQuestion { qname, qtype, qclass }, offset))
}

// Builds the DNS answer section for A, MX or CNAME records
fn build_dns_answer(qtype: u16) -> Vec<u8> {
    let mut answer = Vec::new();
    // Use pointer to QNAME
    answer.extend_from_slice(&0xc00c_u16.to_be_bytes());
    answer.extend_from_slice(&qtype.to_be_bytes()); // TYPE
    answer.extend_from_slice(&1u16.to_be_bytes()); // CLASS (Internet)
    answer.extend_from_slice(&3600u32.to_be_bytes()); // Time to live (1 hour)
    // Build RDATA based on QTYPE
    let rdata = match qtype {
        1 => vec![93, 184, 216, 34], // A: Hardcoded IP
        5 => encode_domain_name("example.com"), // CNAME: Target domain
        15 => {
            let mut rdata = vec![0, 10]; // MX: Preference (10)
            rdata.extend_from_slice(&encode_domain_name("mail.example.com")); // Mail server
            rdata
        }
        _ => panic!("Unsupported QTYPE"),
    };
    answer.extend_from_slice(&(rdata.len() as u16).to_be_bytes()); // RDLENGTH
    answer.extend_from_slice(&rdata); // RDATA
    answer
}

/* 
 * Encodes a domain name into DNS format 
 * e.g, "example.com -> [7]example[3]com[0]"
 */
fn encode_domain_name(domain: &str) -> Vec<u8> {
    let mut result = Vec::new();
    
    for part in domain.split('.') {
        result.push(part.len() as u8); // Length prefix
        result.extend_from_slice(part.as_bytes()); // ASCII label
    }
    result.push(0); // Terminate with zero
    result
}

// Processes a DNS query and builds a response
fn process_dns_packet(data: &[u8]) -> Option<Vec<u8>> {
    let mut response = Vec::new();
    // Parse header
    if let Some(header) = parse_dns_header(&data) {
        println!(
            "Parsed header: ID={}, QR={}, QDCOUNT={}",
            header.id, header.qr, header.qdcount
        );
    if header.qdcount > 0 {
            // Parse question
            if let Some((question, q_end)) = parse_dns_question(&data, 12) {
                println!(
                    "Parsed question: QNAME={}, QTYPE={}, QCLASS={}",
                    question.qname, question.qtype, question.qclass
                );
                // Handle supported queries: QCLASS=1, QTYPE=1 (A), 5 (CNAME) or 15(MX)
                if question.qclass == 1 && (question.qtype == 1 || question.qtype == 5 || question.qtype == 15) {
                    response.extend_from_slice(&build_dns_header(header.id, 0));
                    response.extend_from_slice(&data[12..q_end]); // Echo question
                    response.extend_from_slice(&build_dns_answer(question.qtype)); // Add answer
                } else {
                    // Return RCODE=4 for unsupported queries
                    response.extend_from_slice(&build_dns_header(header.id, 4));
                }
                return Some(response);
            }
        }
    }
    println!("Invalid packet");
    None // Return None for invalid packets
}

// Main async function to run UDP and TCP servers
#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Spawn UDP server task
    let udp_task = tokio::spawn(async {
        // Bind UDP socket
        let socket = UdpSocket::bind(ADDR).await.unwrap();
        println!("UDP server listening on localhost:2053");
        let mut buf = [0; 1024];
        loop {
            // Receive query
            let (amt, src) = socket.recv_from(&mut buf).await.unwrap();
            println!("UDP: Received {} bytes from {}: {:x?}", amt, src, &buf[..amt]);
            // Process and send response
            if let Some(response) = process_dns_packet(&buf[..amt]) {
                println!("UDP: Sending response: {:x?}", response);
                socket.send_to(&response, src).await.unwrap();
            }
        }
    });
    
    // Spawn TCP server task
    let tcp_task = tokio::spawn(async {
        // Bind TCP listener
        let listener = TcpListener::bind(ADDR).await.unwrap();
        println!("TCP server listening on localhost:2053");
        loop {
            // Accept client connection
            let (mut socket, addr) = listener.accept().await.unwrap();
            println!("TCP: New connection from {}", addr);
            // Spawn task to handle client
            tokio::spawn(async move {
                // Read 2-byte length prefix
                let mut length_buf = [0; 2];
                if socket.read_exact(&mut length_buf).await.is_err() {
                    println!("TCP: Invalid length prefix");
                    return;
                }
                let length = u16::from_be_bytes(length_buf) as usize;
                // Read packet
                let mut buf = vec![0; length];
                if socket.read_exact(&mut buf).await.is_err() {
                    println!("TCP: Incomplete packet");
                    return;
                }
                println!("TCP: Received {} bytes from {}: {:x?}", length, addr, &buf);
                // Process query
                if let Some(mut response) = process_dns_packet(&buf) {
                    // Add 2-byte length prefix to response
                    let mut response_with_length = (response.len() as u16).to_be_bytes().to_vec();
                    response_with_length.append(&mut response);
                    println!("TCP: Sending response: {:x?}", response_with_length);
                    socket.write_all(&response_with_length).await.unwrap();
                }
            });
        }
    });
    
    // Run both tasks concurrently
    tokio::try_join!(udp_task, tcp_task)?;
    Ok(())
}
