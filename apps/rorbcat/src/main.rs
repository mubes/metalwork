use collector::Collect;
use std::error::Error;
use std::io::{self, Write};

fn main() {
    loop {
        println!("{:?}", collect_data("localhost:3402"))
    }
}

///////////////////////////////////////////////////////////////////////////
// Process individual packets
///////////////////////////////////////////////////////////////////////////
struct Process {}

impl Process {
    fn new() -> Self {
        Process {}
    }

    fn process(&mut self, i: ITMFrame) {
        match i {
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

    fn packet_end() {
        io::stdout().flush().expect("Cannot flush stdout");
    }
}
