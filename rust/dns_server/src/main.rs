use std::net::UdpSocket;

const ADDR: &str = "localhost:2053";

fn main() -> std::io::Result<()> {
    let socket = UdpSocket::bind(ADDR)?;
    println!("Listening on {}", ADDR);

    let mut buf = [0; 1024];

    loop {
        let (amt, src) = socket.recv_from(&mut buf)?;
        println!("Received {} bytes from {}: {:x?}", amt, src, &buf[..amt]);

        socket.send_to(&buf[..amt], src)?;
    }
}
