use clap::{ArgAction, Parser};
use collector::*;
use constcat::concat;
use itm_processor::{ChanSpec, HandleAs, ITMProcessor};
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn, LevelFilter};
use simplelog::*;
use std::collections::HashSet;
//use std::io::{self, Write};

const CHANNEL_DELIMETER: char = ',';

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
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
    #[arg(short = 'g', long, default_value_t = itm_processor::DEFAULT_TRIGGER_CHAR)]
    ///Character to use to trigger timestamp
    trigger: char,
    #[arg(value_parser = clap::value_parser!(i32).range(0..=511))]
    #[arg(short = 'i', long,num_args = 0.., value_delimiter = CHANNEL_DELIMETER,
        help="Include interrupt information in output. Followed by values\n\
        constrains only those interrupts to be reported (range 0..511)")]
    interrupts: Option<Vec<i32>>,
    #[arg(short = 'n', long, default_value_t = true, action = ArgAction::SetFalse)]
    /// Enforce sync requirement for ITM
    itm_sync: bool,
    #[arg(
        short, long, value_parser = [collector::OFLOW_PREFIX,collector::ITM_PREFIX],
        help="Protocol to communicate. Defaults to itm if is-s\n set, otherwise oflow")]
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
        help = "Append absolute, relative, delta, target relative or target\n\
        delta to output. Relative is with reference to session start.\n\
        The accuracy of a, r & d are host dependent, R and D are target\n\
        dependent."
    )]
    /// Add timestamp
    #[arg(short = 'T', long)]
    timestamp: Option<itm_processor::IntervalType>,
    #[arg(short, long, default_value_t = 1, value_parser = clap::value_parser!(u8).range(0..=5))]
    /// Verbose mode 0(errors)..4(debug)..5(trace)
    verbose: u8,
    #[arg(value_parser = clap::value_parser!(i32).range(0..=15))]
    #[arg(short = 'x', long,num_args = 0.., value_delimiter = CHANNEL_DELIMETER,
        help="Include exception information in output. Followed by values\n\
        constrains only those exceptions to be reported (range 0..15)")]
    exceptions: Option<Vec<i32>>,
    #[arg(num_args(1..), required=true, action = clap::ArgAction::Append)]
    /// Channel(s) and formats in form [channel,"format"]
    channel: Vec<String>,
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

    // === Setup interrupts and exception handling
    //
    // Get empty vector if exceptions weren't set on command line, full set if -x was set but not
    // constrained to any values, or the values that were set if explicit. Note that we start at
    // 1 and not 0 for the 'full set'. This avoids getting hit with Thread Resume messages, but
    // these can be added explicitly if needed.
    let ex: Vec<i32> = match &args.exceptions {
        None => Vec::new(),
        Some(v) if v.is_empty() => Vec::from_iter(1..=15),
        Some(v) => v.clone(),
    };

    // Now add in the interrupts based on the same rules.
    let combined: HashSet<i32> = ex
        .iter()
        .chain(
            match &args.interrupts {
                None => Vec::new(),
                Some(v) if v.is_empty() => Vec::from_iter(0..511),
                Some(v) => v.iter().map(|x| x + 16).collect(),
            }
            .iter(),
        )
        .copied()
        .collect();

    /* === Map the channels given on the command line into the output formats */
    let channels = match map_channels(&args.channel) {
        Ok(x) => x,
        Err(y) => {
            error!("{}", y);
            std::process::exit(1);
        }
    };

    /* === Create the main process */
    let mut process = ITMProcessor::new(
        args.trigger,
        args.timestamp.unwrap_or(itm_processor::IntervalType::None),
        args.cpufreq,
        combined,
        channels,
        std::io::stdout(),
    );
    debug!("Processor created");

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

// Perform channel mapping by extracting formats from arg string input
pub fn map_channels(cli_channels: &Vec<String>) -> Result<ChanSpec, String> {
    let mut channel: ChanSpec = Default::default();

    for ip in cli_channels {
        let parts: Vec<&str> = ip.split(CHANNEL_DELIMETER).collect();
        /* Always expect a channel and format */
        if 2 != parts.len() {
            return Err(format!(
                "Badly formed channel expression [{ip:}], should be [channel,\"format\"]"
            ));
        }
        /* Grab the channel number */
        let ch: u8 = match parts[0].parse() {
            Ok(x) => x,
            Err(_) => return Err(format!("Cannot identify channel in [{}]", parts[0])),
        };
        if (ch as usize) >= itm_processor::MAX_CHANNELS {
            return Err(format!(
                "Channel {} out of range 0..{}",
                ch,
                itm_processor::MAX_CHANNELS as u32 - 1
            ));
        }
        /* Identify the active translations that are needed */
        let mut active: u64 = 0;
        for x in 0..itm_processor::PATTERNS.len() {
            active |= if parts[1].contains(itm_processor::PATTERNS[x]) {
                1 << x
            } else {
                0
            };
        }
        /* Now load the format into the channel */
        channel[ch as usize] = itm_processor::Chan {
            fmt: Some(parts[1].to_string()),
            active,
            handling: HandleAs::Normal,
        };
    }
    Ok(channel)
}

// Output additional help for print substitutions
fn print_chelp() {
    eprintln!("Substitions allowed in '-c' format string;\n");
    for i in (0..itm_processor::PATTERNS.len()).step_by(2) {
        eprintln!(
            "\t{:6}\t{:20}\t\t{:6}\t{}",
            itm_processor::PATTERNS[i],
            itm_processor::DESCRIPTION[i],
            itm_processor::PATTERNS[i + 1],
            itm_processor::DESCRIPTION[i + 1]
        );
    }
    eprintln!("\nFor example; -c1,\"{{char}}\"            : Print all characters on channel 1");
    eprintln!("             -c2,\"Reading=0x{{x04}}\\n\" : Print \"Reading=0x1234abcd\"");
    eprintln!("             -c3,\"{{unic}}\"            : Output unicode");
}
