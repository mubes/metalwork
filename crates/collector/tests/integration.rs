use collector::*;
use itm::*;
use std::io::{self, Write};

#[test]
fn main() {
    println!("Orbuculum server must be running in default config before this test");
    println!("otherwise you will see no output.");
    let mut collect_data = Collect::new("localhost:3402");
    let mut p = Process::new();
    loop {
        println!("ERROR::{:?}", collect_data.collect_data(&mut p));
    }
}

///////////////////////////////////////////////////////////////////////////
// Process individual packets
///////////////////////////////////////////////////////////////////////////
struct Process {
    am_connected: bool,
}

impl Process {
    fn new() -> Self {
        Process {
            am_connected: false,
        }
    }
}

impl FrameHandler for Process {
    fn state_ind(&mut self, connected: bool) {
        io::stdout().flush().expect("Cannot flush stdout");
        if connected && !self.am_connected {
            println!("Connected");
            self.am_connected = true;
        }

        if !connected && self.am_connected {
            println!("Disconnected");
            self.am_connected = false;
        }
    }

    fn process(&mut self, i: ITMFrame) -> bool {
        println!("{:?}", i);
        true
    }
}
