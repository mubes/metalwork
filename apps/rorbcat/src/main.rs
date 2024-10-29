use chrono::Local;
use clap::{ArgAction, Parser};
use collector::*;
use constcat::concat;
use std::collections::HashSet;
use inline_colorization::*;
use itm::*;
//use chrono::prelude::*;
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn, LevelFilter};

use aho_corasick::AhoCorasick;
use simplelog::*;
use std::io::{self, Write};

const CHANNEL_DELIMETER: char = ',';

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short = 'c', long, num_args(1..), value_names=["Channel","Format"], action = clap::ArgAction::Append)]
    /// Channel(s) and formats in form [channel,"format"]
    channel: Vec<String>,
    #[arg(long)]
    /// Get additional information on '-c' formats
    chelp: bool,
    #[arg(
        short = 'C',
        long,
        default_value_t = 1,
        hide_default_value(true),
        help = "(Scaled) speed of the CPU in KHz,\n\
        generally /1, /4, /16 or /64 of the real CPU speed"
    )]
    cpufreq: usize,
    #[arg(short = 'E', long)]
    /// Terminate when the feeding socket ends
    eof: bool,
    #[arg(short = 'f', long)]
    /// Take input from specified file
    input_file: Option<String>,
    #[arg(short = 'g', long, default_value_t = DEFAULT_TRIGGER_CHAR)]
    ///Character to use to trigger timestamp
    trigger: char,
    #[arg(value_parser = clap::value_parser!(i32).range(0..=511))]
    #[arg(short = 'i', long,num_args = 0.., value_delimiter = CHANNEL_DELIMETER)]
    /// Include specified interrupt information in output (range 0..511)
    interrupts: Vec<i32>,
    #[arg(short = 'n', long, default_value_t = true, action = ArgAction::SetFalse)]
    /// Enforce sync requirement for ITM
    itm_sync: bool,
    #[arg(
        short, long, value_parser = [collector::OFLOW_PREFIX,collector::ITM_PREFIX],
        help="Protocol to communicate. Defaults to itm if -s\nis set, otherwise oflow")]
    /// Protocol to communicate.
    protocol: Option<String>,
    #[arg(short, long)]
    /// Server and port to use
    server: Option<String>,
    #[arg(short, long, default_value_t = 1,
        value_parser = clap::value_parser!(u8).range(1..=255))]
    /// Which orbflow tag to use
    tag: u8,
    #[arg(
        value_enum,
        help = "Append absolute,relative (to session start), delta, target\n\
        Relative or target Delta to output. Note the accuracy of a, r & d\n\
        are host dependent."
    )]
    /// Add timestamp
    #[arg(short = 'T', long)]
    timestamp: Option<IntervalType>,
    #[arg(short, long, default_value_t = 1, value_parser = clap::value_parser!(u8).range(0..=5))]
    /// Verbose mode 0(errors)..4(debug)..5(trace)
    verbose: u8,
    #[arg(value_parser = clap::value_parser!(i32).range(0..=15))]
    #[arg(short = 'x', long,num_args = 0.., value_delimiter = CHANNEL_DELIMETER)]
    /// Include exception information in output (range 0..15)
    exceptions: Vec<i32>,
}

// Option values for timestamp type
#[derive(clap::ValueEnum, Debug, Clone, PartialEq, Eq)]
pub enum IntervalType {
    #[value(name = "a")]
    Absolute,
    #[value(name = "r")]
    Relative,
    #[value(name = "d")]
    Delta,
    #[value(name = "R")]
    TargetRelative,
    #[value(name = "D")]
    TargetDelta,
    None,
}

fn main() {
    /* === Get command line arguments */
    let args = Args::parse();
    if args.chelp {
        print_chelp();
        return;
    }

    /* === Setup logging */
    const LOG_LEVEL: [LevelFilter; 6] = [
        LevelFilter::Off,
        LevelFilter::Error,
        LevelFilter::Warn,
        LevelFilter::Info,
        LevelFilter::Debug,
        LevelFilter::Trace,
    ];
    TermLogger::init(
        LOG_LEVEL[args.verbose as usize],
        Config::default(),
        TerminalMode::Stderr,
        ColorChoice::Auto,
    )
    .expect("Couldn't start logging");
    info!("{:?}", args);

    let combined: HashSet<i32> = args
        .exceptions
        .iter()
        .cloned()
        .chain(args.interrupts.iter().map(|x| x + 16))
        .collect();

    /* === Create the main processor */
    let mut process = Process::new(
        args.trigger,
        args.timestamp.unwrap_or(IntervalType::None),
        args.cpufreq,
        combined,
    );
    debug!("Processor created");

    /* === Map the channels given on the command line into the output formats */
    if let Err(x) = process.map_channels(&args.channel) {
        error!("{}", x);
        std::process::exit(1);
    };

    /* === Connect to the remote service */
    let collect_url = Collect::calculate_url(&args.input_file, &args.server, &args.protocol);
    info!("Connect URL is {}", collect_url);

    /* === ...and do the magic */
    loop {
        debug!("Opening collector");
        let mut collector = match Collect::new_collector(&collect_url, args.itm_sync, args.tag) {
            Ok(x) => x,
            Err(y) => {
                warn!("{:?}", y);
                error!("Failed to open source {}", collect_url);
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
const MAX_CHANNELS: u8 = 32; // Number of active channels on ITM
const DEFAULT_TRIGGER_CHAR: char = '\n'; // Trigger character for resetting time print

#[derive(Debug, Clone)]
struct Chan {
    fmt: Option<String>,  // Format for the channel
    handle_as_char: bool, // Fast-flag if this should be handled as chars
}

// Timing related data for running process
#[derive(Debug, Clone)]
struct TimeTrack {
    it: IntervalType,                // Typie of intervals to be reported
    donefirst: bool,                 // Is this the first iteration?
    cpu_freq_div: usize,             // CPU frequency divider
    time: u64,                       // Latest calculated time from target
    old_time: u64,                   // Last time delta start
    old_dt: chrono::DateTime<Local>, // Host-side timing
}
#[derive(Debug, Clone)]
struct Process {
    ac: AhoCorasick, // Substitution engine

    exlist: HashSet<i32>, // List of exceptions and ints to be considered

    trigger: char, // Character to be used for time output trigger
    storing: bool, // am I currently storing a time?
    armed: bool,   // Waiting for a time

    channel: Vec<Chan>, // The individual channels
    t: TimeTrack,       // Timestamp records for deltas
}

// Substitutions that can be made into the pattern string & descriptions of them
// because of the for loop below, ensure this remains an even number.
const PATTERNS: [&str; 10] = [
    "\\n", "\\t", "\\a", "{x08}", "{x04}", "{x02}", "{i32}", "{u32}", "{unic}", "{char}",
];
const DESCRIPTION: [&str; 10] = [
    "New Line",
    "Tab",
    "Bell",
    "32-bit hex value",
    "16-bit hex value",
    "8-bit hex value",
    "32-bit signed integer",
    "32-bit unsigned integer",
    "Unicode character",
    "Legacy 8-bit character",
];

const EXNAMES: [&str; 16] = [
    "Thread",
    "Reset",
    "NMI",
    "HardFault",
    "MemManage",
    "BusFault",
    "UsageFault",
    "UNKNOWN_7",
    "UNKNOWN_8",
    "UNKNOWN_9",
    "UNKNOWN_10",
    "SVCall",
    "Debug Monitor",
    "UNKNOWN_13",
    "PendSV",
    "SysTick",
];
const EXEVENT: [&str; 4] = ["Unknown", "Enter", "Exit", "Resume"];

// Output additional help for print substitutions
fn print_chelp() {
    println!("Substitions allowed in '-c' format string;\n");
    for i in (0..PATTERNS.len()).step_by(2) {
        println!(
            "\t{:6}\t{:20}\t\t{:6}\t{}",
            PATTERNS[i],
            DESCRIPTION[i],
            PATTERNS[i + 1],
            DESCRIPTION[i + 1]
        );
    }
    println!("\nFor example; -c1,\"{{char}}\"            : Print all characters on channel 1");
    println!("             -c2,\"Reading=0x{{x04}}\\n\" : Print \"Reading=0x1234abcd\"");
    println!("             -c3,\"{{unic}}\"            : Output unicode");
}

// Main processor
impl Process {
    // Create a new process with default values
    fn new(trigger: char, interval: IntervalType, cpu_freq_div: usize, exlist: HashSet<i32>) -> Self {
        Process {
            ac: AhoCorasick::new(PATTERNS).unwrap(),
            trigger,

            storing: false,
            armed: false,
            exlist,

            channel: vec![
                Chan {
                    fmt: None,
                    handle_as_char: false,
                };
                MAX_CHANNELS as usize
            ],
            t: TimeTrack {
                it: interval,
                cpu_freq_div,
                old_dt: Local::now(),
                donefirst: false,
                time: 0,
                old_time: 0,
            },
        }
    }

    // Perform channel mapping by extracting formats from arg string input
    pub fn map_channels(&mut self, cli_channels: &Vec<String>) -> Result<(), String> {
        for ip in cli_channels {
            let parts: Vec<&str> = ip.split(CHANNEL_DELIMETER).collect();
            /* Always expect a channel and format */
            if 2 != parts.len() {
                return Err(format!("Badly formed channel expression [{ip:}]"));
            }
            /* Grab the channel number */
            let ch: u8 = match parts[0].parse() {
                Ok(x) => x,
                Err(_) => return Err(format!("Cannot identify channel in [{}]", parts[0])),
            };
            if ch >= MAX_CHANNELS {
                return Err(format!(
                    "Channel {} out of range 0..{}",
                    ch,
                    MAX_CHANNELS as u32 - 1
                ));
            }
            /* Now load the format, and check if it should be handled as chars */
            self.channel[ch as usize] = Chan {
                fmt: Some(parts[1].to_string()),
                handle_as_char: parts[1].contains("{char}"),
            };
        }
        Ok(())
    }

    fn check_exception(t: &mut TimeTrack, no: u16, event: ExceptionEvent) -> String {
        if no < 16 {
            format!(
                "{}{color_bright_blue}HWEVENT_SYSTEM_EXCEPTION event {} type {}{color_reset}",
                Process::check_time_trigger(t),
                EXEVENT[event as usize],
                EXNAMES[no as usize]
            )
        } else {
            format!(
                "{}{color_bright_blue}HWEVENT_INTERRUPT_EXCEPTION event {} external interrupt {}{color_reset}",Process::check_time_trigger(t),
                EXEVENT[event as usize], no as usize - 16
            )
        }
    }

    // Check if time trigger occured, and output formatted time if appropriate
    fn check_time_trigger(t: &mut TimeTrack) -> String {
        let mut r = String::from("");

        match t.it {
            IntervalType::Absolute => {
                let dt = Local::now();
                r = format!(
                    "{color_bright_yellow}{}|{color_reset}",
                    dt.format("%Y-%m-%d %H:%M:%S%.3f")
                );
            }
            IntervalType::Relative => {
                if !t.donefirst {
                    r = format!("{color_bright_yellow}       Relative|{color_reset}");
                } else {
                    let dt = Local::now();
                    let delta = dt.timestamp_millis() - t.old_dt.timestamp_millis();
                    r = format!(
                        "{color_bright_yellow}{:11}.{:03}|{color_reset}",
                        (delta / 1000) % 1000,
                        delta % 1000
                    );
                }
            }
            IntervalType::Delta => {
                if !t.donefirst {
                    r = format!("{color_bright_yellow}          Delta|{color_reset}");
                } else {
                    let dt = Local::now();
                    let delta = dt.timestamp_millis() - t.old_dt.timestamp_millis();
                    t.old_dt = dt;
                    r = format!(
                        "{color_bright_yellow}{:11}.{:03}|{color_reset}",
                        (delta / 1000) % 1000,
                        delta % 1000
                    );
                }
            }
            IntervalType::TargetDelta => {
                if !t.donefirst {
                    r = format!("{color_bright_yellow}   Target Delta|{color_reset}");
                } else if t.cpu_freq_div != 1 {
                    let d = (t.time - t.old_time) * 1000 / t.cpu_freq_div as u64;
                    r = format!(
                        "{color_bright_yellow}{:7}.{:03}_{:03}|{color_reset}",
                        d / 1000000,
                        (d / 1000) % 1000,
                        d % 1000
                    );
                } else {
                    r = format!(
                        "{color_bright_yellow}{:15}|{color_reset}",
                        t.time - t.old_time
                    );
                }

                t.old_time = t.time;
            }
            IntervalType::TargetRelative => {
                if !t.donefirst {
                    r = format!("{color_bright_yellow}Target Relative|{color_reset}");
                } else if t.cpu_freq_div != 1 {
                    let d = t.time * 1000 / t.cpu_freq_div as u64;
                    r = format!(
                        "{color_bright_yellow}{:7}.{:03}_{:03}|{color_reset}",
                        d / 1000000,
                        (d / 1000) % 1000,
                        d % 1000
                    );
                } else {
                    r = format!("{color_bright_yellow}{:15}|{color_reset}", t.time);
                }
            }
            _ => (),
        }
        t.donefirst = true;
        r
    }
    fn process_internal(&mut self, i: ITMFrame) -> bool {
        match i {
            // === Timestamp, update our records
            ITMFrame::Timestamp { ttype, ts } => {
                debug!("Timestamp packet type {:?} +{}", ttype, ts);
                self.t.time += ts;
                self.armed = false;
            }
            ITMFrame::Exception { no, event } => {
                if self.exlist.contains(&(no as i32)) {
                    println!("{}", Process::check_exception(&mut self.t, no, event));
                }
            }
            // === Instrumentation, extract data and format
            ITMFrame::Instrumentation {
                addr,
                mut data,
                mut len,
            } => {
                debug!("Instrumentation packet {:02x}:{}:{:08x}", addr, len, data);
                if addr < MAX_CHANNELS {
                    if let Some(fmt) = &self.channel[addr as usize].fmt {
                        loop {
                            let cv = if self.channel[addr as usize].handle_as_char {
                                data & 0xff
                            } else {
                                data
                            };
                            /* This replace structure needs to match PATTERNS above. Yes, it's yuk, but it's Rust-y.     */
                            /* Perhaps one day there will be some print formatting that doesn't require string literals? */
                            let replace = &[
                                "\x0a".to_string(),
                                "\x09".to_string(),
                                "\x07".to_string(),
                                format!("{:08x}", cv),
                                format!("{:04x}", cv & 0xffff),
                                format!("{:02x}", cv & 0xff),
                                format!("{}", cv as i32),
                                format!("{}", cv),
                                format!("{}", char::from_u32(cv).unwrap_or('?')),
                                format!("{}", char::from_u32(cv).unwrap_or('?')),
                            ];

                            // === Check to see if a trigger occured, and adjust timing appropriately
                            if cv as u8 as char == self.trigger {
                                self.storing = false;
                            } else if !self.storing {
                                self.armed = true;
                                self.storing = true;
                                print!("{}", Process::check_time_trigger(&mut self.t));
                            }

                            print!("{}", self.ac.replace_all(fmt, replace));

                            // === If we are in char mode treat each 8 element as a character
                            if (!self.channel[addr as usize].handle_as_char) || len == 1 {
                                break;
                            }
                            len -= 1;
                            data >>= 8;
                        }
                    }
                } else {
                    warn!("Illegal channel {}", addr);
                }
            }
            _ => {
                debug! {"Dropped ITMFrame {:?}",i};
            }
        }
        true
    }
}

// Collect the itm frames from the decoder, and process them
impl collector::FrameHandler for Process {
    fn process(&mut self, i: ITMFrame) -> bool {
        self.process_internal(i)
    }

    // State callback indication from decoder
    fn state_ind(&self, e: &CollectError) {
        match e {
            CollectError::NoError => (),
            _ => {
                info!("Decode error reported {:?}", e);
            }
        };
        io::stdout().flush().expect("Cannot flush stdout");
    }
}
