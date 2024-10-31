/// ITM Processor
///
/// Implements the
use aho_corasick::AhoCorasick;
use chrono::Local;
use collector::*;
use inline_colorization::*;
use itm::*;
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn, LevelFilter};
use std::collections::HashSet;
use std::io::{self, Write};

#[path = "test_lib.rs"]
mod test_lib;

/// Number of ITM channels that will be considered
pub const MAX_CHANNELS: usize = 32;

/// Trigger character for resetting time print
pub const DEFAULT_TRIGGER_CHAR: char = '\n';

/// Main object for the ITM processor
//#[derive(Debug, Clone)]
pub struct ITMProcessor {
    ac: AhoCorasick, // Substitution engine

    exlist: HashSet<i32>, // List of exceptions and ints to be considered

    trigger: char, // Character to be used for time output trigger
    storing: bool, // am I currently storing a time?
    armed: bool,   // Waiting for a time

    channel: ChanSpec, // The individual channels
    t: TimeTrack,      // Timestamp records for deltas
    output: Box<dyn std::io::Write>,
}

/// Substitutions that can be made into the pattern string & descriptions of them
// because of the for loop below, ensure this remains an even number.
pub const PATTERNS: [&str; 10] = [
    "{char}", "\\n", "\\t", "\\a", "{x08}", "{x04}", "{x02}", "{i32}", "{u32}", "{unic}",
];

/// Convinience indicator that special case of CHAR is held in 0'th index
const IS_8BIT_CHAR: u64 = 1 << 0;

/// Textual descriptions of what each string substitution represents (align with PATTERNS)
pub const DESCRIPTION: [&str; 10] = [
    "Legacy 8-bit character",
    "New Line",
    "Tab",
    "Bell",
    "32-bit hex value",
    "16-bit hex value",
    "8-bit hex value",
    "32-bit signed integer",
    "32-bit unsigned integer",
    "Unicode character",
];

/// Types of timestamp that can be applied to ITM data
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

#[derive(Debug, Default, Clone, PartialEq)]
pub enum HandleAs {
    #[default]
    None,
    Normal,
}

/// Definition for channel behaviours
pub type ChanSpec = [Chan; MAX_CHANNELS];

/// Structure for a single ITM channel
#[derive(Debug, Default, Clone)]
pub struct Chan {
    pub fmt: Option<String>, // Format for the channel
    pub active: u64,         // Translations that are active
    pub handling: HandleAs,  // Fast-flag if this should be handled as chars
}

// Timing related data for running process
#[derive(Debug, Clone)]
struct TimeTrack {
    interval: IntervalType,          // Type of intervals to be reported
    donefirst: bool,                 // Is this the first iteration?
    cpu_freq_div: usize,             // CPU frequency divider
    time: u64,                       // Latest calculated time from target
    old_time: u64,                   // Last time delta start
    old_dt: chrono::DateTime<Local>, // Host-side timing
}

// Names for system exceptions
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

// Actions for system exceptions
const EXEVENT: [&str; 4] = ["Unknown", "Entry", "Exit", "Resume"];

// Main processor loop
impl ITMProcessor {
    /// Create a new process with set values passed in [ChanSpec]
    pub fn new<W: std::io::Write + 'static>(
        trigger: char,
        interval: IntervalType,
        cpu_freq_div: usize,
        exlist: HashSet<i32>,
        channel: ChanSpec,
        output: W,
    ) -> ITMProcessor {
        ITMProcessor {
            ac: AhoCorasick::new(PATTERNS).unwrap(),
            trigger,
            exlist,
            storing: false,
            armed: false,
            channel,
            output: Box::new(output),
            t: TimeTrack {
                interval,
                cpu_freq_div,
                old_dt: Local::now(),
                donefirst: false,
                time: 0,
                old_time: 0,
            },
        }
    }

    // Evaluate exception/interrupt and produce record
    fn check_exception(t: &mut TimeTrack, no: u16, event: ExceptionEvent) -> String {
        if no < 16 {
            format!(
                "{}{color_bright_blue}EXCEPTION {} {}{color_reset}",
                ITMProcessor::check_time_trigger(t),
                EXNAMES[no as usize],
                EXEVENT[event as usize],
            )
        } else {
            format!(
                "{}{color_bright_blue}INTERRUPT {} {}{color_reset}",
                ITMProcessor::check_time_trigger(t),
                no as usize - 16,
                EXEVENT[event as usize],
            )
        }
    }

    // Check if time trigger occured, and output formatted time record if appropriate
    fn check_time_trigger(t: &mut TimeTrack) -> String {
        let mut r = String::new();

        match t.interval {
            // -------------------------------------------------------------------------
            // === Absolute System local time and date
            IntervalType::Absolute => {
                let dt = Local::now();
                r = format!(
                    "{color_bright_yellow}{}|{color_reset}",
                    dt.format("%Y-%m-%d %H:%M:%S%.3f")
                );
            }
            // -------------------------------------------------------------------------
            // === Relative time in seconds and milliseconds since start
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
            // -------------------------------------------------------------------------
            // === Relative time in seconds and milliseconds since last event
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
            // -------------------------------------------------------------------------
            // === Target side time in seconds and milliseconds or ticks, since last event
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
            // -------------------------------------------------------------------------
            // === Target side time in seconds and milliseconds or ticks, since start
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

    const NOTRANSLATE: String = String::new();

    // Object internal processor for itm events
    fn process_internal(&mut self, i: ITMFrame) -> bool {
        match i {
            // -------------------------------------------------------------------------
            // === Timestamp, update our records
            ITMFrame::Timestamp { ttype, ts } => {
                debug!("Timestamp packet type {:?} +{}", ttype, ts);
                self.t.time += ts;
                self.armed = false;
            }
            // -------------------------------------------------------------------------
            // Exception, if active then check report
            ITMFrame::Exception { no, event } => {
                if self.exlist.contains(&(no as i32)) {
                    let _ = self
                        .output
                        .write(ITMProcessor::check_exception(&mut self.t, no, event).as_bytes());
                }
            }
            // -------------------------------------------------------------------------
            // === Instrumentation, extract data and format
            ITMFrame::Instrumentation {
                addr,
                mut data,
                mut len,
            } => {
                debug!("Instrumentation packet {:02x}:{}:{:08x}", addr, len, data);
                if (addr as usize) < MAX_CHANNELS {
                    if let Some(fmt) = &self.channel[addr as usize].fmt {
                        let act = self.channel[addr as usize].active;
                        loop {
                            let cv = if (act & IS_8BIT_CHAR) != 0 {
                                data & 0xff
                            } else {
                                data
                            };
                            // This replace structure needs to match PATTERNS above. Yes, it's yuk, but it's Rust-y.
                            // Perhaps one day there will be some print formatting that doesn't require string literals?
                            // This code allows each format to only be run if the format string contains any matches.
                            // With 10 potential matches this is a ~3 times decrease in CPU utilisation.
                            let replace = &[
                                if act & (1 << 0) != 0 {
                                    format!("{}", char::from_u32(cv).unwrap_or('?'))
                                } else {
                                    ITMProcessor::NOTRANSLATE
                                },
                                if act & (1 << 1) != 0 {
                                    "\x0a".to_string()
                                } else {
                                    ITMProcessor::NOTRANSLATE
                                },
                                if act & (1 << 2) != 0 {
                                    "\x09".to_string()
                                } else {
                                    ITMProcessor::NOTRANSLATE
                                },
                                if act & (1 << 3) != 0 {
                                    "\x07".to_string()
                                } else {
                                    ITMProcessor::NOTRANSLATE
                                },
                                if act & (1 << 4) != 0 {
                                    format!("{:08x}", cv)
                                } else {
                                    ITMProcessor::NOTRANSLATE
                                },
                                if act & (1 << 5) != 0 {
                                    format!("{:04x}", cv & 0xffff)
                                } else {
                                    ITMProcessor::NOTRANSLATE
                                },
                                if act & (1 << 6) != 0 {
                                    format!("{:02x}", cv & 0xff)
                                } else {
                                    ITMProcessor::NOTRANSLATE
                                },
                                if act & (1 << 7) != 0 {
                                    format!("{}", cv as i32)
                                } else {
                                    ITMProcessor::NOTRANSLATE
                                },
                                if act & (1 << 8) != 0 {
                                    format!("{}", cv)
                                } else {
                                    ITMProcessor::NOTRANSLATE
                                },
                                if act & (1 << 9) != 0 {
                                    format!("{}", char::from_u32(cv).unwrap_or('?'))
                                } else {
                                    ITMProcessor::NOTRANSLATE
                                },
                            ];

                            // === Check to see if a trigger occured, and adjust timing appropriately
                            if cv as u8 as char == self.trigger {
                                self.storing = false;
                            } else if !self.storing {
                                self.armed = true;
                                self.storing = true;
                                let _ = self.output.write(
                                    ITMProcessor::check_time_trigger(&mut self.t).as_bytes(),
                                );
                            }

                            let _ = self
                                .output
                                .write(self.ac.replace_all(fmt, replace).as_bytes());

                            // === If we are in char mode treat each 8 element as a character
                            if (act & IS_8BIT_CHAR) == 0 || len == 1 {
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
impl collector::FrameHandler for ITMProcessor {
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
