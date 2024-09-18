//! Orbflow (OFLOW) Protocol Encode/Decode
//!
//! Coverts a orbflow packet into a valid frame for higher layers, and turns a higher layer
//! packet into an orbflow one. The encoder and decoder only work atomically on complete
//! frames, so there is no concept of state.
//!
//! OFLOW packets are characterised by a single byte stream number, followed by a number of
//! bytes of (stream specific) data, terminated by a twos compliment checksum byte that makes
//! the whole frame sum to zero.
//!
//!

use std::fmt;
use std::vec::Vec;
mod test_lib;

/// Default max packet length for unencoded oflow packet
pub const MAX_PACKET_LEN: usize = 8192;
const STREAM_LEN: usize = 1;
const CHECKSUM_LEN: usize = 1;

/// Errors from use of this crate
#[derive(Debug, Clone, Eq, Copy, PartialEq)]
pub enum OFlowError {
    /// Packet is too long
    Overlong,
    /// Insufficent data in buffer to complete the packet
    ShortData,
    /// Duff checksum
    BadChecksum,
    /// Function not implemented
    Unimplemented,
}

impl fmt::Display for OFlowError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            OFlowError::Overlong => write!(f, "Packet is too long"),
            OFlowError::ShortData => write!(f, "Packet is too short"),
            OFlowError::BadChecksum => write!(f, "Bad checksum"),
            OFlowError::Unimplemented => write!(f, "Unimplemented"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OFlowFrame {
    stream_number: u8,
    inner: Vec<u8>,
}

impl OFlowFrame {
    pub fn content(&self) -> &[u8] {
        &self.inner[STREAM_LEN..self.inner.len() - CHECKSUM_LEN]
    }
}

impl std::ops::Index<usize> for OFlowFrame {
    type Output = u8;
    
    fn index( &self, i: usize) -> &Self::Output {
        &self.inner[i+STREAM_LEN]
    }
}

impl std::ops::Deref for OFlowFrame {
    type Target = [u8];
    
    fn deref(&self) -> &Self::Target {
        &self.content()
    }
}

// The OFLOW encoder/decoder object
#[derive(Default, Debug, Clone, Eq, Copy, PartialEq)]
pub struct OFlow {
    /* Statistics maintained by this decoder */
    inbytestotal: u64,  // Number of bytes of input from source
    outbytestotal: u64, // Number of bytes sent out
    inpackets: u64,     // Number of input packets processed
    outpackets: u64,    // Number of output packets processed
    inerrpackets: u64,  // Number of input error packets
    outerrpackets: u64, // Number of output error packets
}

impl OFlow {
    // Encoded packet has a flow number at the start and a checksum at the end
    const OVERHEAD_LEN: usize = STREAM_LEN + CHECKSUM_LEN;
    const MAX_ENC_PACKET_LEN: usize = OFlow::OVERHEAD_LEN + MAX_PACKET_LEN;

    /// Create new instance of Oflow
    ///
    /// New instance will have zero'ed statistics.
    ///
    pub fn new() -> OFlow {
        Self { ..Default::default() }
    }

    // Decode the inner orbflow frame within the passed vector reference
    pub fn decode(&mut self, ip: Vec<u8>) -> Result<OFlowFrame, OFlowError> {
        if ip.len() < 3 {
            Err(OFlowError::ShortData)
        } else if ip.len() > OFlow::MAX_ENC_PACKET_LEN {
            Err(OFlowError::Overlong)
        } else {
            /* Create checksum */
            let mut sum: usize = 0;
            for c in ip[0..ip.len()].iter() {
                sum += *c as usize;
            }

            if sum & 0xff != 0 {
                /* Checksum didn't match (i.e. sum to zero), not worth going further */
                self.inerrpackets += 1;
                Err(OFlowError::BadChecksum)
            } else {
                /* All good, updating accounting and return the inner content */
                self.inpackets += 1;
                self.inbytestotal += (ip.len() - OFlow::OVERHEAD_LEN) as u64;
                Ok(OFlowFrame {
                    stream_number: ip[0],
                    inner: ip,
                })
            }
        }
    }

    // Create an encoded orbflow packet ready for transmission or storage
    pub fn encode<'a>(
        &mut self,
        stream_number: u8,
        mut _iter: impl Iterator<Item = &'a u8>,
    ) -> Result<Vec<u8>, OFlowError> {
        
        
        
        Err(OFlowError::Unimplemented)
    }
}
