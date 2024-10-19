//! Data collector
//!
//! Connects to a remote location over TCP/IP and pushes decoded data back to the handler.
//!
//! Deals with all the errors and disconnects that can occur, so the application just
//! gets a steady stream of data when they are available.
//!

use cobs::Cobs;
use itm::*;
use std::fmt::Debug;
use std::mem;
use std::net::TcpStream;
use std::thread;
use std::time::Duration;

use oflow::{OFlow, OFlowError};
use std::io::{ErrorKind, Read};

/// Trait any frame handler is required to implement
pub trait FrameHandler {
    /// A frame to be processed. Return true if everything is OK, false to reset the link
    fn process(&mut self, i: ITMFrame) -> bool;

    /// Indication of current state. Return true if everything is OK, false to reset the link
    fn state_ind(&mut self, connected: bool);
}

/// Errors from use of this crate
#[derive(Debug, thiserror::Error)]
pub enum CollectError {
    /// Connection was lost
    #[error("Connection was reset")]
    Reset,
    /// Something went amiss in processing (the callback returned false)
    #[error("Processing Failed")]
    ProcessingFailed,
    /// Error from IO Layer
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    /// Error from OFlow (or, by extension, COBS) layer
    #[error("OFlow error: {0}")]
    OFlowError(#[from] OFlowError),
    /// Error from ITM decoder
    #[error("ITM error: {0}")]
    ITMError(#[from] ITMError),
}

#[derive(Debug)]
/// The collection object
pub struct Collect {
    address: String,
    cobs_decoder: Cobs,
    oflow_decoder: OFlow,
    itm_decoder: ITMDecoder,
}

impl Collect {
    /// Create new instance which will (attempt to) connect to specified address
    ///
    /// # Example
    ///
    /// ```
    /// use collector::*;
    /// let mut collect_data = Collect::new("localhost:3402");
    /// ```
    ///
    pub fn new(addr: &str) -> Self {
        Collect {
            address: addr.to_string(),
            cobs_decoder: Cobs::new(),
            oflow_decoder: OFlow::new(),
            itm_decoder: ITMDecoder::new(true),
        }
    }

    /// Collect data, calling callback with FrameHandler trait to process the returned data
    ///
    /// # Example
    ///
    /// ```
    /// use collector::*;
    /// let mut collect_data = Collect::new("localhost:3402");
    /// let mut p = Process::new();
    /// loop {
    ///     println!("ERROR::{:?}", collect_data.collect_data(&mut p));
    /// }
    ///
    pub fn collect_data(&mut self, cb: &mut impl FrameHandler) -> CollectError {
        let mut ppacket = Vec::with_capacity(cobs::MAX_PACKET_LEN);
        let mut stream = self.do_open(&self.address, cb);
        let mut iplen;
        let mut tokens = [0u8; cobs::MAX_ENC_PACKET_LEN];
        loop {
            match stream.read(&mut tokens) {
                Ok(n) => {
                    iplen = n;
                }
                Err(x) => {
                    if ErrorKind::Interrupted == x.kind() || ErrorKind::WouldBlock == x.kind() {
                        continue;
                    } else {
                        return self::CollectError::IoError(x);
                    }
                }
            }

            if 0 == iplen {
                return self::CollectError::Reset;
            }
            cb.state_ind(true);
            let mut s = tokens[..iplen.min(tokens.len())].iter();
            /* Have some data to feed into the currently being assembled packet */

            let _ = self.cobs_decoder.get_frame(&mut s, &mut ppacket);

            /* Constructed packet ownership goes to the decoder */
            let packet = mem::take(&mut ppacket);
            let oflow_frame = match self.oflow_decoder.decode(packet) {
                Ok(r) => r,
                Err(x) => return self::CollectError::OFlowError(x),
            };
            /* ...so we will need a new one for next time around */
            ppacket = Vec::with_capacity(cobs::MAX_PACKET_LEN);

            let mut i = oflow_frame.iter().peekable();

            while i.peek().is_some() {
                let itm_frame = match self.itm_decoder.get_frame(&mut i) {
                    Ok(f) => f,
                    Err(x) => {
                        if x == ITMError::ShortData {
                            // Being short of data isn't much of an error, just means we need more
                            continue;
                        } else {
                            return self::CollectError::ITMError(x);
                        }
                    }
                };
                if false == cb.process(itm_frame) {
                    return CollectError::ProcessingFailed;
                }
            }
            cb.state_ind(true);
        }
    }

    // Open a new connection and cofigure it for use
    fn do_open(&self, addr: &String, cb: &mut impl FrameHandler) -> TcpStream {
        cb.state_ind(false);
        loop {
            match TcpStream::connect(addr) {
                Ok(s) => {
                    // Want to wait 100ms for a packet to fill before returning
                    s.set_read_timeout(Some(Duration::from_millis(100)))
                        .expect("Couldn't set read timeout");
                    cb.state_ind(true);
                    return s;
                }
                Err(_x) => {
                    // Don't hog the CPU by continiously trying to connect
                    thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }
}
