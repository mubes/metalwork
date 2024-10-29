//! Data collector
//!
//! Connects to a remote location over TCP/IP and pushes decoded data back to the handler.
//!
//! Deals with all the errors and disconnects that can occur, so the application just
//! gets a steady stream of data when they are available.
//!

use cobs::{Cobs, CobsError};
use itm::*;
use std::fs::File;
use std::path::Path;
use constcat::concat;
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn, LevelFilter};
use oflow::{OFlow, OFlowError};
use std::fmt::Debug;
use std::io::{ErrorKind, Read};
use std::mem;
use std::net::TcpStream;

#[path = "test_lib.rs"]
mod test_lib;

/// Prefix for an address offering oflow
pub const OFLOW_PREFIX: &str = "oflow";
/// Prefix for an address offering itm
pub const ITM_PREFIX: &str = "itm";
/// Prefix for the address of a file
pub const FILE_PREFIX: &str = "file";
/// Separator for parts of a url
pub const URL_SEPARATOR: &str = "://";
/// Default connection address for when one isn't specified
pub const DEFAULT_CONNECT_ADDR: &str = "localhost";
/// Default port for when one isn't specified
pub const DEFAULT_PORT: &str = "3402";
const PORT_SEP: &str = ":";

/// Trait any frame handler is required to implement
pub trait FrameHandler {
    /// A frame to be processed. Return true if everything is OK, false to reset the link
    fn process(&mut self, i: ITMFrame) -> bool;

    /// Indication of current state. Return true if everything is OK, false to reset the link
    fn state_ind(&self, e: &CollectError);
}

/// Errors from use of this crate
#[derive(Debug, thiserror::Error)]
pub enum CollectError {
    /// No error
    #[error("No error")]
    NoError,
    /// Connection was lost
    #[error("Connection was reset")]
    Reset,
    /// Something went amiss in processing (the callback returned false)
    #[error("Processing Failed")]
    ProcessingFailed,
    /// Source of data not found
    #[error("Source not found")]
    NoSource,
    /// Error from IO Layer
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    /// Error from OFlow layer
    #[error("OFlow error: {0}")]
    OFlowError(#[from] OFlowError),
    /// Error from Cobs layer
    #[error("COBS error: {0}")]
    CobsError(#[from] CobsError),
    /// Error from ITM decoder
    #[error("ITM error: {0}")]
    ITMError(#[from] ITMError),
}

trait ReadWrite: std::io::Read + std::io::Write {}
impl ReadWrite for TcpStream {}
impl ReadWrite for File {}

/// The collection object
pub struct Collect {
    stream_number: u8,
    cobs_decoder: Cobs,
    oflow_decoder: OFlow,
    itm_decoder: ITMDecoder,
    is_itm: bool,
    stream: Box<dyn ReadWrite>,
}

impl Collect {
    // -------------------------------------------------------------------------------------
    /// Calculate the connecting address url
    ///
    /// This can get slightly complicated with all of the options. The rules are;
    ///   Return a file url if a file is specified.
    ///   Else;
    ///      Use the address if specified, otherwise default address
    ///      If no port was specified in the address then add the default port
    ///      If the protocol was specified explicitly then add that
    ///      Else;
    ///         If an address was provided then add ITM protocol, otherwise add OFLOW.
    ///   Return constructed addresss
    ///
    /// # Example
    /// ```
    /// use collector::*;
    /// println!("default URL is {}",Collect::calculate_url(&None,&None,&None));
    /// println!("File URL is {}",Collect::calculate_url(&Some("fileexample"),&None,&None));
    /// println!("COBS URL is {}",Collect::calculate_url(&None,&Some("example"),&Some(String::new("cobs"))));
    /// ```
    ///
    pub fn calculate_url(
        input_file: &Option<String>,
        server: &Option<String>,
        protocol: &Option<String>,
    ) -> String {
        match input_file {
            Some(x) => {
                /* File source, just calculate and return it */
                concat!(FILE_PREFIX, URL_SEPARATOR).to_string() + x
            }

            None => {
                /* Network source: Determine what the protocol frontmatter looks like. */
                let prot = match protocol {
                    Some(p) => p.clone(),
                    None => {
                        if server.is_some() {
                            ITM_PREFIX.to_string()
                        } else {
                            OFLOW_PREFIX.to_string()
                        }
                    }
                };

                /* Get the server address, or default address if there isn't one already */
                let mut addr = server
                    .as_ref()
                    .map(String::as_str)
                    .unwrap_or(DEFAULT_CONNECT_ADDR)
                    .to_string();

                /* Add a port number if we need one */
                if !addr.contains(PORT_SEP) {
                    addr = addr + PORT_SEP + DEFAULT_PORT;
                };

                /* Now add in the address */
                prot + URL_SEPARATOR + &addr
            }
        }
    }

    // -------------------------------------------------------------------------------------
    /// Create new instance which will (attempt to) connect to specified address
    ///
    /// # Example
    ///
    /// ```
    /// use collector::*;
    /// let mut collect_data = Collect::new_collector("oflow://localhost:3402",true,1);
    /// ```
    ///
    pub fn new_collector(addr: &str, itm_sync: bool, tag: u8) -> Result<Self, CollectError> {
        info!(
            "Collector created for address:{}, sync state:{} and tag:{}",
            addr, itm_sync, tag
        );
        let c = Collect::do_open(addr)?;
        Ok(Collect {
            cobs_decoder: Cobs::new(),
            oflow_decoder: OFlow::new(),
            itm_decoder: ITMDecoder::new(itm_sync),
            stream_number: tag,
            is_itm: c.0,
            stream: c.1,
        })
    }

    // -------------------------------------------------------------------------------------
    /// Collect data, calling callback with FrameHandler trait to process the returned data
    ///
    /// This routine is called with a pre-created instance.
    /// 
    /// # Example
    ///
    /// ```
    /// use collector::*;
    /// let mut collect_data = Collect::new("oflow://localhost:3402");
    /// let mut p = Process::new();
    /// loop {
    ///     println!("ERROR::{:?}", collect_data.collect_data(&mut p));
    /// }
    ///
    pub fn collect_data(&mut self, cb: &mut impl FrameHandler) -> CollectError {
        let mut tokens = [0u8; cobs::MAX_ENC_PACKET_LEN];
        let mut ppacket = Vec::with_capacity(cobs::MAX_PACKET_LEN);
        info!("Starting collector");
        cb.state_ind(&self::CollectError::NoError);
        loop {
            let iplen = match self.stream.read(&mut tokens) {
                Ok(n) => n,
                Err(x) => {
                    if ErrorKind::Interrupted == x.kind() || ErrorKind::WouldBlock == x.kind() {
                        continue;
                    } else {
                        debug!("Error from rx:{:?}", x);
                        let err = self::CollectError::from(x);
                        cb.state_ind(&err);
                        /* Errors from the stream collection layer are terminal */
                        return err;
                    }
                }
            };

            if 0 == iplen {
                debug!("Zero length data rx, Resetting connection");
                cb.state_ind(&self::CollectError::Reset);
                /* This is EOF, so return...up to the layer above what happens next */
                return self::CollectError::Reset;
            }

            /* At this point we have _some_ data, but we don't know that it forms into packets */
            let mut s = tokens[..iplen.min(tokens.len())].iter().peekable();

            if !self.is_itm {
                /* These are Oflow packets, so they need to go through COBS and OFLOW decoders */
                debug!("COBS input packet len {}", iplen);
                while s.peek().is_some() {
                    match self.cobs_decoder.get_frame(&mut s, &mut ppacket) {
                        Ok(()) => (),
                        Err(x) => {
                            if x == cobs::CobsError::ShortData {
                                debug!("Short COBS packet");
                                // It's quite normal to not have a complete end of packet here, so spin and wait for more
                                break;
                            } else {
                                debug!("Error in cobs decode {:?}", x);
                                ppacket.clear();
                                cb.state_ind(&self::CollectError::from(x));
                            }
                        }
                    }

                    debug!("Complete COBS packet, len {}", ppacket.len());
                    /* Constructed packet ownership goes to the decoder */
                    let packet = mem::take(&mut ppacket);
                    /* ...so we will need a new one for next time around */
                    ppacket = Vec::with_capacity(cobs::MAX_PACKET_LEN);

                    /* A COBS packet contains a maximum of one OFlow packet */
                    let oflow_frame = match self.oflow_decoder.decode(packet) {
                        Ok(r) => r,
                        Err(x) => {
                            debug!("Error returned by OFLOW decode: {:?}", x);
                            cb.state_ind(&self::CollectError::from(x));
                            continue;
                        }
                    };

                    /* Only continue if the stream was for us */
                    if oflow_frame.get_stream_no() != self.stream_number {
                        debug!("Stream not for us, dropped");
                        continue;
                    }

                    debug!("OFlow frame length {}", oflow_frame.len());
                    let mut i = oflow_frame.iter().peekable();

                    match self.itm_process(&mut i, cb) {
                        Ok(_) => (),
                        Err(_y) => {
                            debug!("{:?}", _y);
                            continue;
                        }
                    };
                }
            } else {
                /* If we're in ITM mode just chew on what we've got */
                debug!("ITM packet len {}", iplen);
                match self.itm_process(&mut s, cb) {
                    Ok(_) => (),
                    Err(_y) => {
                        debug!("{:?}", _y);
                        continue;
                    }
                };
            }
            debug!("NoError callback");
            cb.state_ind(&CollectError::NoError);
        }
    }

    // -------------------------------------------------------------------------------------
    // Process a specific set of itm frames until the data run out...
    pub fn itm_process<'a, I>(
        &mut self,
        i: &mut I,
        cb: &mut impl FrameHandler,
    ) -> Result<(), ITMError>
    where
        I: Iterator<Item = &'a u8>,
    {
        loop {
            let itm_frame = self.itm_decoder.get_frame(i)?;
            debug!("Sent frame for processing");
            if !cb.process(itm_frame) {
                debug!("Frame processor returned false");
                cb.state_ind(&CollectError::ProcessingFailed);
                return Err(ITMError::ProcessingError);
            }
        }
    }

    // -------------------------------------------------------------------------------------
    // Open a new connection and configure it for use
    // Returns a ReadWrite handle to the connection and an indication if it's ITM or OFLOW
    //
    fn do_open(addr: &str) -> Result<(bool, Box<dyn ReadWrite>), CollectError> {
        if let Some(oflow_addr) = addr.strip_prefix(concat!(OFLOW_PREFIX, URL_SEPARATOR)) {
            let r = TcpStream::connect(oflow_addr)?;
            Ok((false, Box::new(r)))
        } else if let Some(itm_addr) = addr.strip_prefix(concat!(ITM_PREFIX, URL_SEPARATOR)) {
            let r = TcpStream::connect(itm_addr)?;
            Ok((true, Box::new(r)))
        } else if let Some(file_path) = addr.strip_prefix(concat!(FILE_PREFIX, URL_SEPARATOR)) {
            let r = File::open(Path::new(file_path))?;
            Ok((false, Box::new(r)))
        } else {
            Err(CollectError::NoSource)
        }
    }
}
