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

/// Errors from use of this crate
#[derive(Debug, Clone, Eq, Copy, PartialEq)]
pub enum OFlowError {
    /// Packet is zero length
    ZeroLength,
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
            OFlowError::ZeroLength => write!(f, "Zero length message"),
            OFlowError::Overlong => write!(f, "Packet is too long"),
            OFlowError::ShortData => write!(f, "Packet is too short"),
            OFlowError::BadChecksum => write!(f, "Bad checksum"),
            OFlowError::Unimplemented => write!(f, "Unimplemented"),
        }
    }
}

impl std::error::Error for OFlowError {}

/// An OrbFlow frame
///
/// An orbflow frame consists of a stream number followed by the frame content. The last byte of this
/// content is a checksum.
///
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OFlowFrame {
    stream_number: u8,
    inner: Vec<u8>,
}

/// Access the data carried by the orbflow frame
impl OFlowFrame {
    pub fn content(&self) -> &[u8] {
        &self.inner[OFlow::STREAM_LEN..self.inner.len() - OFlow::CHECKSUM_LEN]
    }
}

/// Access the inner frame
///
/// This is a complete orbflow frame with stream number and checksum
impl OFlowFrame {
    pub fn oflow_frame(&self) -> &[u8] {
        &self.inner
    }
}

impl std::ops::Index<usize> for OFlowFrame {
    type Output = u8;

    fn index(&self, i: usize) -> &Self::Output {
        if self.inner.len() < 2 || i > self.inner.len() - 1 - OFlow::CHECKSUM_LEN {
            panic!("Index out of range");
        }
        &self.inner[i + OFlow::STREAM_LEN]
    }
}

impl std::ops::Deref for OFlowFrame {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.content()
    }
}

/// The OFLOW encoder/decoder object
///
/// This maintains statistics of packets encoded and decoded by the orbflow machine.
///
#[derive(Default, Debug, Clone, Eq, Copy, PartialEq)]
pub struct OFlow {
    /* Statistics maintained by this decoder */
    inbytestotal: u64, // Number of bytes of input from source
    inpackets: u64,    // Number of input packets processed
    inerrpackets: u64, // Number of input error packets
}

impl OFlow {
    /// Default max packet length for unencoded oflow packet
    pub const MAX_PACKET_LEN: usize = 8192;
    pub const STREAM_LEN: usize = 1;
    pub const CHECKSUM_LEN: usize = 1;

    // Encoded packet has a flow number at the start and a checksum at the end
    const OVERHEAD_LEN: usize = OFlow::STREAM_LEN + OFlow::CHECKSUM_LEN;
    const MAX_ENC_PACKET_LEN: usize = OFlow::OVERHEAD_LEN + OFlow::MAX_PACKET_LEN;

    /// Create new instance of Oflow
    ///
    /// New instance will have zero'ed statistics.
    ///
    pub fn new() -> OFlow {
        Self {
            ..Default::default()
        }
    }

    /// Return input statistics
    ///
    /// Returns the input statistics for the decoder. Note there are no output
    /// statistics as these can bypas the encoder if performed by the macro.
    ///
    /// #Example
    /// ```
    /// use oflow::OFlow;
    /// let of = OFlow::new();
    /// println!("{:?}",of.stats());
    /// ```
    ///
    pub fn stats(self) -> (u64, u64, u64) {
        (self.inbytestotal, self.inerrpackets, self.inpackets)
    }

    /// Decode the inner data frame within the passed orbflow vector reference
    ///
    /// Parses the input vector into a valid data frame, updating statistics appropriately.
    ///
    /// #Errors
    /// An error will be returned if the frame is too short to be decoded, if it is too long, or if the
    /// checksum for the frame is incorrect.
    ///
    /// #Example
    /// ```
    /// use oflow::OFlow;
    /// let of = OFlow::new();
    /// let ipvec = vec![27u8, 1, 2, 3, (256usize - (27 + 1 + 2 + 3)) as u8];
    /// let mut oflow = OFlow::new();
    /// let opvec_candidate = oflow.decode(ipvec).unwrap();
    ///
    pub fn decode(&mut self, ip: Vec<u8>) -> Result<OFlowFrame, OFlowError> {
        if ip.len() < 1 + OFlow::OVERHEAD_LEN {
            self.inerrpackets += 1;
            Err(OFlowError::ShortData)
        } else if ip.len() > OFlow::MAX_ENC_PACKET_LEN {
            self.inerrpackets += 1;
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

    /// Return the checksum for an orbflow data frame
    ///
    /// This is normally only used as part of the frame construction macro. It returns no
    /// errors and the checksum is always valid.
    ///
    /// # Example
    /// ```
    /// use oflow::OFlow;
    /// let data = vec![1u8,2,3];
    /// let oflow_packet = OFlow::get_checksum(42,&data);
    /// ```
    ///
    pub fn get_checksum(stream_number: u8, ip: &[u8]) -> u8 {
        //let mut sum: u8 = stream_number;
        let mut sum: u8 = ip.iter().sum();
        sum += stream_number;
        (256usize - (sum as usize)) as u8
    }

    /// Create an encoded orbflow vector ready for transmission or storage
    ///
    /// Orbflow frames can be constructed either as sequences of vectors using the
    /// [`oflow_frame`] macro, or directly into a vector by this call.
    ///
    /// # Errors
    ///
    /// Returns errors for no source data, or the source data being too long, otherwise
    /// returns a valid sequence of vectors.
    ///
    /// # Example
    /// ```
    /// use oflow::OFlow;
    /// let data = vec![1u8,2,3];
    /// let mut of = OFlow::new();
    /// let oflow_packet = of.encode_to_vec(42,data);
    /// ```
    ///
    pub fn encode_to_vec(
        &mut self,
        stream_number: u8,
        ip: Vec<u8>,
    ) -> Result<Vec<u8>, OFlowError> {
        if ip.is_empty() {
            Err(OFlowError::ZeroLength)
        } else if ip.len() > OFlow::MAX_PACKET_LEN {
            Err(OFlowError::Overlong)
        } else {
            let op_assy = oflow_frame!(stream_number, &ip);
            let mut constructed_frame = vec![0u8; 0];
            for o in op_assy {
                for i in o {
                    constructed_frame.push(i);
                }
            }
            Ok(constructed_frame)
        }
    }
}

/// Zero-copy creation of orbflow packet as sequence of slices
///
/// The first slice contains the `stream_number`, the second the
/// data and the third the checksum.  This can be transmitted directly
/// or can be flattened for storage etc.
///
/// # Errors
///
/// Panics for no source data, or the source data being too long, otherwise
/// returns a valid sequence of vectors.
///
/// # Example
/// ```
/// use oflow::OFlow;
/// let data = vec![1u8,2,3];
/// let oflow_packet = oflow::oflow_frame!(42,&data);
/// ```
///
#[macro_export]
macro_rules! oflow_frame {
    ($l:expr,&$m:expr) => {{
        if $m.len() == 0 {
            panic!("Zero length orbflow packet");
        }
        if $m.len() > OFlow::MAX_PACKET_LEN {
            panic!("Orbflow packet to long");
        }
        let sum = OFlow::get_checksum($l, &$m);
        vec![vec![$l], $m, vec![sum]]
    }};
}
