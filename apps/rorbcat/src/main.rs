use cobs::Cobs;
use itm::*;
use oflow::OFlow;
use std::io::{self, Write};
use std::io::{ErrorKind, Read};
use std::net::TcpStream;
use std::thread;
use std::time::Duration;

/* This is yucky code - just a POC for now, but it does interwork correctly with orbuculum 2.2.0 :-) */
fn main() {
    let mut stream: TcpStream;
    let mut cobs_decoder = Cobs::new();
    let mut oflow_decoder = OFlow::new();
    let mut itm_decoder = ITMDecoder::new(true);
    let mut ppacket: Box<Vec<u8>>;

    ppacket = Box::new(Vec::with_capacity(cobs::MAX_PACKET_LEN));

    loop {
        let mut first_iteration = true;
        loop {
            match TcpStream::connect("localhost:3402") {
                Ok(s) => {
                    stream = s;
                    break;
                }
                Err(x) => {
                    if first_iteration {
                        println!("Could not connect to server [{}]", x.to_string());
                        first_iteration = false;
                    }
                    thread::sleep(Duration::from_millis(100));
                    continue;
                }
            }
        }

        stream
            .set_read_timeout(Some(Duration::from_millis(100)))
            .expect("Couldn't set read timeout");
        let mut iplen;
        let mut tokens = [0u8; cobs::MAX_ENC_PACKET_LEN];
        loop {
            match stream.read(&mut tokens) {
                Ok(n) => {
                    iplen = n;
                }
                Err(x) => {
                    if ErrorKind::Interrupted == x.kind() || ErrorKind::WouldBlock == x.kind() {
                        continue;
                    } else {
                        eprintln!("{:?}", x);
                        break;
                    }
                }
            }

            if 0 == iplen {
                break;
            }
            let mut s = tokens[..iplen.min(tokens.len())].iter();

            /* Have some data to feed into the currently being assembled packet */
            loop {
                if cobs_decoder.get_frame(&mut s, &mut ppacket).is_ok() {
                    /* Constructed packet ownership goes to the decoder */
                    let ret = oflow_decoder.decode(*ppacket);

                    /* ...so we will need a new one for next time around */
                    ppacket = Box::new(Vec::with_capacity(cobs::MAX_PACKET_LEN));

                    let oflow_frame = match ret {
                        Ok(f) => f,
                        Err(x) => {
                            println!("OFlow decode error {}", x);
                            break;
                        }
                    };

                    let mut i = oflow_frame.iter();
                    loop {
                        let itm_frame = match itm_decoder.get_frame(&mut i) {
                            Ok(f) => f,
                            Err(_x) => {
                                break;
                            }
                        };

                        match itm_frame {
                            ITMFrame::Instrumentation {
                                addr,
                                mut data,
                                mut len,
                            } => {
                                if addr == 1 {
                                    while len != 0 {
                                        len -= 1;
                                        print!("{}", char::from_u32(data & 0xff).unwrap_or('?'));
                                        data >>= 8;
                                    }
                                }
                            }
                            _ => (),
                        }
                    }
                } else {
                    io::stdout().flush().expect("Cannot flush stdout");
                    break;
                }
            }
        }
    }
}
