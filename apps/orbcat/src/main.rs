use std::io::Read;
use std::net::TcpStream;

use cobs::Cobs;

fn main() {
    let mut stream = TcpStream::connect("localhost:3402").unwrap();
    let mut p = vec![0u8; 4096];
    let mut cobs_decoder = Cobs::new();
    let _ = stream.read(&mut p).unwrap();
    loop {
        let mut s = p.iter();

        loop {
            let mut v = Vec::<u8>::with_capacity(10000);
            loop {
                if cobs_decoder.get_frame(&mut s, &mut v).is_ok() {
                    println!("{} ", v.len());
                }
            }
        }
    }
}
