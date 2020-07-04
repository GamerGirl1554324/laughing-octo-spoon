use std::net::SocketAddr;
use std::time::Duration;
use std::convert::From;
use std::fs::File;
use rand::seq::SliceRandom;
use rand::thread_rng;

use clap::{Arg, App};
use linereader::LineReader;

use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio::prelude::*;

use colored::Colorize;

const RECVBUFSIZE: usize = 2;
const SENDBUFSIZE: usize = 8;

fn get_ip(istr: &str) -> std::net::Ipv4Addr {
    istr.parse()
        .expect("Failed to create address from hostname")
}

fn get_addr(iistr: &str) -> SocketAddr {
    std::net::SocketAddr::V4(std::net::SocketAddrV4::new(get_ip(iistr), 0))
}

fn form_socks5_request(buf: &mut [u8; SENDBUFSIZE]) {
    buf[0] = 0x05;
    buf[1] = 6;

    buf[2] = 0x00;
    buf[3] = 0x01;
    buf[4] = 0x02;
    buf[5] = 0x03;
    buf[6] = 0x80;
    buf[7] = 0xff;
}

async fn write_probe(stream: &mut TcpStream) {
    let mut buf = [0u8; SENDBUFSIZE];

    form_socks5_request(&mut buf);

    stream.write_all(&buf).await
        .expect("Failed to send the probe!");
}

async fn read_probe(stream: &mut TcpStream) -> [u8; RECVBUFSIZE] {
    let mut buf = [0u8; RECVBUFSIZE];
    
    stream.read(&mut buf).await
        .expect("Failed to read");

    buf
}

enum SocksVer {
    Socks5,
    Socks4,
    Invalid,
}

impl From<u8> for SocksVer {
    fn from(ver: u8) -> Self {
        match ver {
            0x05 => SocksVer::Socks5,
            0x04 => SocksVer::Socks4,
            _    => SocksVer::Invalid,
        }
    }
}

enum SocksAuthType {
    Nopasswd,
    Gssapi,
    UserPasswd,
    Iana,
    Reserverd,
    Rejected,
    Invalid
}

impl From<u8> for SocksAuthType {
    fn from(ver: u8) -> Self {
        match ver {
            0x00 => SocksAuthType::Nopasswd,
            0x01 => SocksAuthType::Gssapi,
            0x02 => SocksAuthType::UserPasswd,
            0x03 => SocksAuthType::Iana,
            0x80 => SocksAuthType::Reserverd,
            0xff => SocksAuthType::Rejected,
            _    => SocksAuthType::Invalid,
        }
    }
}

fn print_ver(ver: &SocksVer) {
    print!("Version: ");

    match ver {
        SocksVer::Socks4  => print!("SOCKS4 "),
        SocksVer::Socks5  => print!("SOCKS5 "),
        SocksVer::Invalid => print!("INVALID "),
    }
}

fn print_auth(auth: &SocksAuthType) {
    print!("Authentication: ");

    match auth {
        SocksAuthType::Nopasswd   => print!("No password "),
        SocksAuthType::Gssapi     => print!("GSSAPI "),
        SocksAuthType::UserPasswd => print!("User Password auth "),
        SocksAuthType::Iana       => print!("Iana "),
        SocksAuthType::Reserverd  => print!("Reserved, unknown "),
        SocksAuthType::Rejected   => print!("Rejected "),
        SocksAuthType::Invalid    => print!("INVALID "),
    }
}

fn print_vre_authype(creds: &(SocksVer, SocksAuthType)) {
    print_ver(&creds.0);
    print_auth(&creds.1);
    print!("\n");
}

fn socks_parse_resp(buf: &[u8; RECVBUFSIZE]) -> (SocksVer, SocksAuthType) {
    let ver = buf[0];
    let method = buf[1];

    (SocksVer::from(ver), SocksAuthType::from(method))
}

async fn send_probe(adr: SocketAddr) -> Option<(SocksVer, SocksAuthType)> {

    match TcpStream::connect(&adr).await {
        Ok(mut stream) => {
            println!("connected to {}", adr);

            write_probe(&mut stream).await;

            println!("listening...");

            let resp = read_probe(&mut stream).await;

            println!("{:02X} {:02X}", resp[0], resp[1]);
            
            let (ver, auth) = socks_parse_resp(&resp);

            stream.shutdown(std::net::Shutdown::Both)
                .expect("Failed to shutdown stream");
            
            return Some((ver, auth));
        },
        Err(err) => {
            println!("Failed to connect {:?}", err);
            return None;
        }
    }
}

async fn probe_port(adr: SocketAddr)
                    -> Option<u16> {
    
    match TcpStream::connect(adr).await {
        Ok(stream) => {
            println!("ACK ----------------> {}", adr);

            stream.shutdown(std::net::Shutdown::Both)
                .expect("Failed to kill the socket");

            return Some(adr.port());
        },
        Err(_) => {
            println!("REJ");
            return None;
        },
    }
}

fn shuffle(array: &mut Vec<u16>) {
    let mut rng = thread_rng();
    array.shuffle(&mut rng);
}

async fn portscan(addr: std::net::SocketAddr,
                  start: u16, end: u16) -> Vec<u16> {
    let mut ports: Vec<u16> = (start..end).collect();

    shuffle(&mut ports);

    let mut target_addr = SocketAddr::new(addr.ip(), 0);

    let mut handles = Vec::new();
    for port in ports {
        target_addr.set_port(port);

        handles.push(timeout(Duration::from_secs(180), probe_port(target_addr)));
    }

    let mut open_ports: Vec<u16> = Vec::new();
    for handle in handles {
        match handle.await {
            Ok(something) => {
                match something {
                    Some(port) => {
                        open_ports.push(port);
                    },
                    None => {}
                }
            },
            Err(_) => {},       // !! TIMEOUT
        }
    }

    println!("Found open ports: {:?}", open_ports);
    open_ports
}

// Final result
struct SurveyResult {
    addr: SocketAddr, 
    open_ports: Vec<u16>,
    found_socks: Vec<((SocksVer, SocksAuthType), bool)>,
}
//                     ^               ^         ^
//                     version       auth type   valid prox flag

fn pprint_result(res: &Vec<SurveyResult>) {
    for result in res.iter() {
        println!("Address: {}", format!("{}", result.addr).magenta());
        print!("Open ports: ");

        for port in result.open_ports.iter() {
            print!("{}, ", port);
        }

        print!("\n");

        for socks in result.found_socks.iter() {
            match socks.1 {
                true => {
                    println!("{}", " Valid: ".green());
                    print!("    ");
                    print_vre_authype(&socks.0);
                }
                false => {
                    println!("{}", " Invalid: ".yellow());
                    print!("    ");
                    print_vre_authype(&socks.0);
                }
            }
        }
    }
}


// find all open ports then probe each one for socks
// @addr - tgt
// @pend >= @pstart - port range
async fn survey_target(addr: SocketAddr, pstart: u16, pend: u16) -> SurveyResult {
    println!("SURVERYING {:?}", addr);
    
    let open_ports = portscan(addr, pstart, pend).await;
    let mut proxies = Vec::new();

    let mut addr_cpy = addr.clone();
    for port in open_ports.iter() {
        addr_cpy.set_port(*port);

        println!("probing port number: {}", port);
        
        let probe_res = send_probe(addr_cpy).await;

        match probe_res {
            Some(valid_data) => {
                match valid_data.0 {
                    SocksVer::Socks5 => {
                        proxies.push((valid_data, true));
                    },
                    _ => {
                        proxies.push((valid_data, false));
                    },
                }
            },
            None => {},
        }
    }

    SurveyResult {
        addr: addr,
        open_ports: open_ports,
        found_socks: proxies,
    }
}

#[tokio::main]
async fn main() {
    let matches = App::new("Ringger")
        .version("2.2.8")
        .author("Kevin Spacey")
        .about("A scanner?")
        .arg(Arg::with_name("list")
             .short("l")
             .long("list")
             .help("Target Port")
             .takes_value(true))
        .get_matches();

    let list_filename = matches.value_of("list")
        .ok_or("No file specified")
        .expect("Bad file value");

    let file = File::open(list_filename)
        .expect("Failed to open the file!");

    // should start an output task here

    // join handles
    let mut handles = Vec::new(); 

    let mut reader = LineReader::new(file);
    while let Some(line) = reader.next_line() {
        let line = line.expect("Failed to read next line");

        let str_address = std::str::from_utf8(line)
            .expect("faile")
            .trim()
            .to_string();

        handles.push(tokio::task::spawn(async move {
            survey_target(get_addr(&str_address), 38785, 38805).await
        }));
    }

    println!("Merging all tasks...");

    let mut results = Vec::new(); 

    for handle in handles {
        let result = handle.await
            .expect("Fuckd up shit!");

        results.push(result);
    }

    println!("Results: {} units", results.len());

    pprint_result(&results);
}
