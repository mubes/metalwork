use chrono::Local;
use clap::{ArgAction, Parser};
use collector::*;
use constcat::concat;
use inline_colorization::*;
use itm::*;
//use chrono::prelude::*;
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn, LevelFilter};

use aho_corasick::AhoCorasick;
use simplelog::*;
use std::io::{self, Write};

const DEFAULT_TRIGGER_CHAR: char = '\n';

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short = 'c', long, num_args(1..), value_names=["Channel","Format"], action = clap::ArgAction::Append)]
    /// Channel(s) and formats in form [channel,"format"]
    channel: Vec<String>,

    #[arg(short = 'C', long, default_value_t = 1)]
    /// (Scaled) speed of the CPU in KHz, generally /1, /4, /16 or /64 of the real CPU speed
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
    #[arg(
        value_enum,
        help = "Append absolute,relative (to session start), delta,
        target Relative or target Delta\n\
        to output. Note the accuracy of a, r & d are host dependent."
    )]
    /// Add timestamp
    #[arg(short = 'T', long)]
    timestamp: Option<IntervalType>,
    #[arg(short, long, default_value_t = 1, value_parser = clap::value_parser!(u8).range(0..=5))]
    /// Verbose mode 0(errors)..4(debug)..5(trace)
    verbose: u8,
    #[arg(short = 'x', long)]
    /// Include exception information in output, in time order
    exceptions: bool,
}

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
    const LOG_LEVEL: [LevelFilter; 6] = [
        LevelFilter::Off,
        LevelFilter::Error,
        LevelFilter::Warn,
        LevelFilter::Info,
        LevelFilter::Debug,
        LevelFilter::Trace,
    ];
    let args = Args::parse();

    TermLogger::init(
        LOG_LEVEL[args.verbose as usize],
        Config::default(),
        TerminalMode::Stderr,
        ColorChoice::Auto,
    )
    .expect("Couldn't start logging");
    info!("{:?}", args);

    let mut process = Process::new(
        args.trigger,
        args.timestamp.unwrap_or(IntervalType::None),
        args.cpufreq,
    );
    debug!("Processor created");

    if let Err(x) = process.map_channels(&args.channel) {
        error!("{}", x);
        std::process::exit(1);
    };

    let collect_url = Collect::calculate_url(&args.input_file, &args.server, &args.protocol);
    info!("Connect URL is {}", collect_url);

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
const MAX_CHANNELS: u8 = 32;
const CHANNEL_DELIMETER: &str = ",";

#[derive(Debug, Clone)]
struct Chan {
    fmt: Option<String>,
    handle_as_char: bool,
}

struct TimeTrack {
    it: IntervalType,    // Typie of intervals to be reported
    cpu_freq_div: usize, // CPU frequency divider

    time: u64,     // Latest calculated time from target
    old_time: u64, // Last time delta start
    old_dt: chrono::DateTime<Local>,
}

struct Process {
    ac: AhoCorasick,    // Substitution engine
    trigger: char,      // Character to be used for time output trigger
    storing: bool,      // am I currently storing a time?
    armed: bool,        // Waiting for a time
    channel: Vec<Chan>, // The individual channels
    t: TimeTrack,       // Timestamp records for deltas
}

// Substitutions that can be made into the pattern string
const PATTERNS: [&str; 10] = [
    "\\n", "\\t", "\\a", "{x08}", "{x04}", "{x02}", "{i32}", "{u32}", "{unic}", "{char}",
];
const DESCRIPTIONS: [&str; 10] = [
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

impl Process {
    fn new(trigger: char, interval: IntervalType, cpu_freq_div: usize) -> Self {
        Process {
            ac: AhoCorasick::new(PATTERNS).unwrap(),
            trigger: trigger,

            storing: false,
            armed: false,
            channel: vec![
                Chan {
                    fmt: None,
                    handle_as_char: false,
                };
                MAX_CHANNELS as usize
            ],
            t: TimeTrack {
                it: interval,
                cpu_freq_div: cpu_freq_div,
                old_dt: Local::now(),
                time: 0,
                old_time: 0,
            },
        }
    }

    pub fn map_channels(&mut self, cli_channels: &Vec<String>) -> Result<(), String> {
        for ip in cli_channels {
            let parts: Vec<&str> = ip.split(CHANNEL_DELIMETER).collect();
            if 2 != parts.len() {
                return Err(format!("Badly formed channel expression [{ip:}]"));
            }
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
            self.channel[ch as usize] = Chan {
                fmt: Some(parts[1].to_string()),
                handle_as_char: parts[1].contains("{char}"),
            };
        }
        Ok(())
    }

    fn check_time_trigger(t: &mut TimeTrack) {
        match t.it {
            IntervalType::Absolute => {
                let dt = Local::now();
                print!(
                    "{color_bright_yellow}{}|{color_reset}",
                    dt.format("%Y-%m-%d %H:%M:%S%.3f")
                );
            }
            IntervalType::Relative => {
                let dt = Local::now();
                let delta = dt.timestamp_millis() - t.old_dt.timestamp_millis();
                print!(
                    "{color_bright_yellow}{:4}.{:03}|{color_reset}",
                    (delta / 1000) % 1000,
                    delta % 1000
                );
            }
            IntervalType::Delta => {
                let dt = Local::now();
                let delta = dt.timestamp_millis() - t.old_dt.timestamp_millis();
                t.old_dt = dt;
                print!(
                    "{color_bright_yellow}{:4}.{:03}|{color_reset}",
                    (delta / 1000) % 1000,
                    delta % 1000
                );
            }
            IntervalType::TargetDelta => {
                let d = (t.time - t.old_time) / t.cpu_freq_div as u64;
                t.old_time = t.time;
                print!(
                    "{color_bright_yellow}{:3}.{:03}_{:03}|{color_reset}",
                    d / 1000000,
                    (d / 1000) % 1000,
                    d % 1000
                );
            }
            IntervalType::TargetRelative => {
                let d = t.time / t.cpu_freq_div as u64;
                print!(
                    "{color_bright_yellow}{:3}.{:03}_{:03}|{color_reset}",
                    d / 1000000,
                    (d / 1000) % 1000,
                    d % 1000
                );
            }
            _ => (),
        }
    }
}

impl collector::FrameHandler for Process {
    fn process(&mut self, i: ITMFrame) -> bool {
        match i {
            ITMFrame::Timestamp { ttype, ts } => {
                debug!("Timestamp packet type {:?} +{}", ttype, ts);
                self.t.time += ts;
                self.armed = false;
            }
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
                                format!("\x0a"),
                                format!("\x09"),
                                format!("\x07"),
                                format!("{:08x}", cv),
                                format!("{:04x}", cv & 0xffff),
                                format!("{:02x}", cv & 0xff),
                                format!("{}", cv as i32),
                                format!("{}", cv),
                                format!("{}", char::from_u32(cv).unwrap_or('?')),
                                format!("{}", char::from_u32(cv).unwrap_or('?')),
                            ];

                            if cv as u8 as char == self.trigger {
                                self.storing = false;
                            } else {
                                if !self.storing {
                                    self.armed = true;
                                    self.storing = true;
                                    Process::check_time_trigger(&mut self.t);
                                }
                            }
                            print!("{}", self.ac.replace_all(fmt, replace));

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
