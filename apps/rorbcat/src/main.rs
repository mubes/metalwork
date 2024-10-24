use clap::{ArgAction, Parser};
use collector::*;
use constcat::concat;
use itm::*;
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn, LevelFilter};
use simple_logger::SimpleLogger;
use std::io::{self, Write};

const DEFAULT_CONNECT_ADDR: &str = "localhost";
const PORT_SEP: &str = ":";
const DEFAULT_PORT: &str = "3402";

const LOG_LEVEL: [LevelFilter; 6] = [
    LevelFilter::Off,
    LevelFilter::Error,
    LevelFilter::Warn,
    LevelFilter::Info,
    LevelFilter::Debug,
    LevelFilter::Trace,
];

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    /// Channel(s) and formats in form <channel>,"<format>" (e.g. -c1,"%c" -c2,"%d" ...)
    channel: Vec<String>,
    #[arg(short = 'C', long, default_value_t = 0, num_args(1..), value_names=["Channel","Format"], action = clap::ArgAction::Append)]
    /// (Scaled) speed of the CPU in KHz, generally /1, /4, /16 or /64 of the real CPU speed
    cpufreq: usize,
    #[arg(short = 'E', long)]
    /// Terminate when the feeding socket ends
    eof: bool,
    #[arg(short = 'f', long)]
    /// Take input from specified file
    input_file: Option<String>,
    #[arg(short = 'g', long, default_value_t = '\n')]
    ///Character to use to trigger timestamp
    trigger: char,
    #[arg(short = 'n', long, default_value_t = true, action = ArgAction::SetFalse)]
    /// Enforce sync requirement for ITM
    itm_sync: bool,
    #[arg(short, long, value_parser = [collector::OFLOW_PREFIX,collector::ITM_PREFIX])]
    /// Protocol to communicate. Defaults to itm if -s is set, otherwise oflow
    protocol: Option<String>,
    #[arg(short, long)]
    /// Server and port to use
    server: Option<String>,
    #[arg(short, long, default_value_t = 1, value_parser = clap::value_parser!(u8).range(1..=255))]
    /// Which orbflow tag to use
    tag: u8,
    #[arg(short, long,value_parser = ["a", "r", "d", "s", "t"],
        help = "Add absolute, relative\
        (to session start), delta, system timestamp or system timestamp delta\n\
        to output. Note the accuracy of a, r & d are host dependent.")]
    /// Add timestamp
    #[arg(short = 'T', long)]
    timestamp: Option<String>,
    #[arg(short, long, default_value_t = 1, value_parser = clap::value_parser!(u8).range(0..=5))]
    /// Verbose mode 0(errors)..4(debug)..5(trace)
    verbose: u8,
    #[arg(short = 'x', long)]
    /// Include exception information in output, in time order
    exceptions: bool,
}

fn main() {
    let args = Args::parse();
    println!("{:?}", args.channel);
    SimpleLogger::new()
        .with_level(LOG_LEVEL[args.verbose as usize])
        .init()
        .expect("Could not start logger");
    info!("Command line args: {:?}", args);

    /* Calculate the connecting address ...this is slightly involved */
    let collect_url = match args.input_file {
        Some(x) => {
            /* File source, just calculate and return it */
            concat!(collector::FILE_PREFIX, collector::URL_SEPARATOR).to_string() + &x
        }
        None => {
            /* Network source: Determine what the protocol frontmatter looks like. This        */
            /* will be ITM if explicitly set, or if there is an address and not explicitly set */
            let prot = args.protocol.unwrap_or(if args.server.is_some() {
                collector::ITM_PREFIX.to_string()
            } else {
                collector::OFLOW_PREFIX.to_string()
            });

            /* Get the server address, or default address if there isn't one already */
            let mut addr = args.server.unwrap_or(DEFAULT_CONNECT_ADDR.to_string());

            /* Add a port number if we need one */
            if !addr.contains(PORT_SEP) {
                addr = addr.to_string() + &PORT_SEP.to_string() + &DEFAULT_PORT.to_string();
            };

            /* Now add in the address */
            prot + &collector::URL_SEPARATOR.to_string() + &addr
        }
    };

    info!("Connect URL is {}", collect_url);
    let mut process = Process::new();
    debug!("Processor created");
    loop {
        debug!("Opening collector");
        let mut collector = match Collect::new_collector(&collect_url, args.itm_sync, args.tag) {
            Ok(x) => x,
            Err(y) => {
                warn!("{:?}", y);
                println!("Failed to open source {}", collect_url);
                std::process::exit(1);
            }
        };

        debug!("Grabbing data");
        let _z = collector.collect_data(&mut process);
        info!("Exited collect with error {:?}", _z);

        if args.eof {
            info!("Terminating due to args.eof set");
            break;
        }
    }
}

///////////////////////////////////////////////////////////////////////////
// Processor for individual packets
///////////////////////////////////////////////////////////////////////////
struct Process {}

impl Process {
    fn new() -> Self {
        Process {}
    }
}

impl collector::FrameHandler for Process {
    fn process(&mut self, i: ITMFrame) -> bool {
        match i {
            ITMFrame::Instrumentation {
                addr,
                mut data,
                mut len,
            } => {
                debug!("Instrumentation packet {:02x}:{}:{:08x}", addr, len, data);
                if addr == 1 {
                    while len != 0 {
                        len -= 1;
                        print!("{}", char::from_u32(data & 0xff).unwrap_or('?'));
                        data >>= 8;
                    }
                }
            }
            _ => {
                debug! {"Dropped ITMFrame {:?}",i};
            }
        }
        true
    }

    fn state_ind(&self, e: &CollectError) {
        match e {
            CollectError::NoError => (),
            _ => {
                info!("Decode error reported {:?}", e);
                println!("{:?}", e)
            }
        };
        io::stdout().flush().expect("Cannot flush stdout");
    }
}
