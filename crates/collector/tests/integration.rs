use collector::*;
use itm::*;
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn, LevelFilter};
use simple_logger::SimpleLogger;
use std::thread;
use std::time::Duration;

#[test]
fn main() {
    SimpleLogger::new()
        .with_level(LevelFilter::Debug)
        .init()
        .expect("Could not start logger");
    warn!("Orbuculum server must be running in default config before this test");
    warn!("otherwise you will see no output.");

    let mut p = Process::new();
    loop {
        let mut collect_data = match Collect::new_collector("localhost:3402", true, 1) {
            Ok(x) => x,
            Err(y) => {
                error!("{:?}", y);
                panic!("Failed to open source");
            }
        };
        error!("At main loop:{:?}", collect_data.collect_data(&mut p));
        thread::sleep(Duration::from_secs(1));
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
}

impl FrameHandler for Process {
    fn state_ind(&self, e: &CollectError) {
        match e {
            CollectError::NoError => (),
            _ => error!("At callback:{:?}", e),
        };
    }

    fn process(&mut self, i: ITMFrame) -> bool {
        info!("{:?}", i);
        true
    }
}
