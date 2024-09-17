//! Consistent Overhead Byte Stream (COBS) Decoder
//!
//! Turns an arbitary stream into a sequence of packets.  COBS is a cheap and
//! easy mechanism to 'packetise' a stream. If sync is lost it will automatically
//! resynchronise at the start of the next packet.
//!
//! Each packet is returned in either the form of a filled `Vec<u8>` which is passed in by
//! the caller pre-set with the maximum capacity, or as a new `Vec<u8>`. Short or over-long
//! packets are automatically discarded and the stream re-syncronised. Statistics are
//! maintained on the construction and forwarding of packets over the link.
//!
//! This decoder is based on **Consistent Overhead Byte Stuffing**, Stuart Cheshire
//! and Mary Baker, IEEE/ACM TRANSACTIONS ON NETWORKING, VOL.7, NO. 2, APRIL 1999.
//! Available from <http://www.stuartcheshire.org/papers/COBSforToN.pdf>
//!

use std::fmt;
use std::vec::Vec;
mod test_lib;

/// Current state of the decoder
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecoderState {
    /// Waiting for a packet to start (i.e. a non-sentinel byte to arrive)
    Idle,
    /// In the process of receiving a packet
    Rxing,
    /// Waiting for a start of packet indication (a sentinel byte)
    Flushing,
}

/// Result of requesting the next packet from the stream
#[derive(Debug, PartialEq)]
enum TokenResult {
    /// Something wrong in the reception
    Error,
    /// We are flushing the stream
    Flushing,
    /// Store this
    Store,
    /// Ignore this (wait for more)
    NoAction,
    /// Reception is complete
    Complete,
}

// The decoder object
#[derive(Debug, Clone, Eq, Copy, PartialEq)]
pub struct Cobs {
    state: DecoderState, // Current state of the decoder
    sentinel: u8,        // Sentinel value to be used (normally 0)
    rxc: u8,             // Reception count..how many more to go in this run
    maxcount: bool,      // Was rxc special case of 0xff?

    /* Statistics maintained by this decoder */
    inbytes: u64,   // Number of bytes of input from source
    goodbytes: u64, // Number of good bytes returned to layer above
    badbytes: u64,  // Number of bad bytes abandoned and not returned
    packets: u64,   // Number of packets returned to layer above
    toolong: u64,   // Number of packets that were too long for their buffer
}

/// Indication of if the packet is complete based on submitting byte(s) to the packetiser
#[derive(Debug, Clone, Eq, Copy, PartialEq)]
pub enum ConsumeResult {
    /// The packet is not yet assembled
    Incomplete,
    /// The packet is assembled
    Complete,
}

/// Default value for sentinel byte (interpacket marker)
pub const DEFAULT_SENTINEL: u8 = 0;

/// Default max packet length for unencoded cobs packet
pub const MAX_PACKET_LEN: usize = 8192;
// Encoded packet has a start run length, a max of one extra byte per 254 bytes, and an end sentinel
const MAX_ENC_PACKET_LEN: usize = 1 + MAX_PACKET_LEN + MAX_PACKET_LEN / 254 + 1;

/// Errors from use of this crate
#[derive(Debug, Clone, Eq, Copy, PartialEq)]
pub enum CobsError {
    /// Enough data for packet not received
    Timeout,
    /// Packet is not yet complete
    Ongoing,
    /// Packet is too long
    Overlong,
    /// Insufficent data in buffer to complete the packet
    ShortData,
    /// Request to build packet of zero length
    ZeroLength,
    /// Too busy to perform requested action
    Busy,
}

impl fmt::Display for CobsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CobsError::Timeout => write!(f, "Timeout"),
            CobsError::Ongoing => write!(f, "Packet is ongoing"),
            CobsError::Overlong => write!(f, "Packet is too long"),
            CobsError::ShortData => write!(f, "Insuffient data to complete packet"),
            CobsError::ZeroLength => write!(f, "Zero length packet"),
            CobsError::Busy => write!(f, "Busy"),
        }
    }
}

impl Cobs {
    /// Create new instance of Cobs
    ///
    /// New instance will have zero'ed statistics, the sentinel value will be set to default and the packet
    /// handler state will be set to be waiting for the start of a packet.
    ///
    pub fn new() -> Cobs {
        Cobs {
            state: DecoderState::Idle,
            sentinel: DEFAULT_SENTINEL,
            rxc: 0,
            inbytes: 0,
            goodbytes: 0,
            badbytes: 0,
            packets: 0,
            toolong: 0,
            maxcount: false,
        }
    }

    /// Change the sentinel (packet end flag) value
    ///
    /// By default the sentinel value is 0x00, but this can be changed. By default changes are only permitted
    /// while the decoder is idle, to prevent impact on any packets in progress. This can be overridden
    /// by setting the `force` parameter.
    ///
    /// # Example
    ///
    /// ```
    /// use cobs::Cobs;
    /// let mut dec = Cobs::new();
    /// dec.set_sentinel(67,true);
    /// ```
    ///
    pub fn set_sentinel(&mut self, set_sentinel: u8, force: bool) -> Result<(), CobsError> {
        if DecoderState::Rxing != self.state || force {
            self.sentinel = set_sentinel;
            Ok(())
        } else {
            Err(CobsError::Busy)
        }
    }

    /// Return statistics representing the behaviour of the decoder
    ///
    /// Provides information how many bytes have received specific dispensations by the decoder.
    ///
    /// # Example
    ///
    /// ```
    /// use cobs::Cobs;
    /// let mut dec = Cobs::new();
    /// let stats = dec.stats();
    /// println!("Input Bytes={} Good Bytes={} Bad Bytes={} Packets={} Toolong={}",
    ///           stats.0,stats.1,stats.2,stats.3,stats.4);
    ///```
    ///
    pub fn stats(&mut self) -> (u64, u64, u64, u64, u64) {
        (
            self.inbytes,
            self.goodbytes,
            self.badbytes,
            self.packets,
            self.toolong,
        )
    }

    /// Interate through the packet assembler, returning a Vec
    ///
    /// Feeds iterated bytes through the packet assembler, until either the stream expires or
    /// the packet is complete.  In the case of expiry the packet is lost.
    /// A `Vec<u8>` is returned filled with the packet data.
    /// If the packet is overlong an error will be returned.
    ///
    /// Stats are updated and may be returned via [`Cobs::stats()`].
    ///
    /// # Return value
    ///
    /// If the packet is incomplete `CobsError::ShortData` will be returned, otherwise the `Vec<u8>` into
    /// which the packet has been assembled.
    ///
    /// # Example
    ///
    /// ```
    /// let input = vec![0x05u8, 0x11, 0x22, 0x33, 0x44, 0x00];
    /// let result = vec![0x11u8, 0x22, 0x33, 0x44];
    /// let mut dec = cobs::Cobs::new();
    /// let v = dec.get_frame_as_vec(input.iter()).unwrap();
    /// assert!(v == result);
    /// ```
    ///
    pub fn get_frame_as_vec<'a>(
        &mut self,
        iter: impl Iterator<Item = &'a u8>,
    ) -> Result<Vec<u8>, CobsError> {
        let mut op = Vec::<u8>::with_capacity(MAX_PACKET_LEN);
        match self.get_frame(iter, &mut op) {
            Ok(_s) => Ok(op),
            Err(r) => {
                if r == CobsError::ShortData {
                    /* Since the vector is ours there is no opportunity to extend it - its a bad frame */
                    self.badbytes += op.len() as u64;
                    self.state = DecoderState::Flushing;
                }
                Err(r)
            }
        }
    }

    /// Interate through the packet assembler, filling a pre-existing Vec
    ///
    /// Feeds iterated bytes through the packet assembler, until either the stream expires or
    /// the packet is complete.  In the case of expiry subsequent calls will further extend the
    /// packet until it _is_ complete. A `Vec<u8>` is passed to be filled with the packet data.
    /// It will not be extended if the length of the packet exceeds the capacity of the `Vec<u8>`,
    /// rather, the packet will be discarded.
    ///
    /// Stats are updated and may be returned via [`Cobs::stats()`].
    ///
    /// # Return value
    ///
    /// If the packet is incomplete `None` will be returned, otherwise a reference to the `Vec<u8>` into
    /// which the packet has been assembled. Note that there is no guarantee that a packet will linearly
    /// assemble - it may be reset to empty if an incomplete or overlong one is received, for example.
    ///
    /// # Example
    ///
    /// ```
    /// let input = vec![0x05u8, 0x11, 0x22, 0x33, 0x44, 0x00];
    /// let result = vec![0x11u8, 0x22, 0x33, 0x44];
    /// let mut dec = cobs::Cobs::new();
    /// let mut v = Vec::<u8>::with_capacity(10000);
    /// let _ = dec.get_frame(input.iter(), &mut v);
    /// assert!(v == result);
    /// ```
    ///
    pub fn get_frame<'a>(
        &mut self,
        mut iter: impl Iterator<Item = &'a u8>,
        op: &mut Vec<u8>,
    ) -> Result<(), CobsError> {
        loop {
            match iter.next() {
                Some(t) => match self.get_byte(*t, op) {
                    Ok(_s) => return Ok(()),
                    Err(r) => {
                        if r != CobsError::Ongoing {
                            return Err(r);
                        }
                    }
                },
                None => {
                    return Err(CobsError::ShortData);
                }
            };
        }
    }

    /// Pass a single byte through the packet assembler
    ///
    /// Feeds the passed byte through the packet assembler, and indicates if the packet is now complete.
    /// Subsequent calls will further extend the packet until it _is_ complete. A `Vec<u8>` is
    /// passed to be filled with the packet data. It will not be extended if the length of the
    /// packet exceeds the capacity of the `Vec<u8>`...rather, an error will be returned.
    ///
    /// Stats are updated and may be returned via [`Cobs::stats()`].
    ///
    /// # Errors
    /// If the packet is incomplete `None` will be returned, otherwise a reference to the `Vec<u8>` into
    /// which the packet has been assembled. Note that there is no guarantee that a packet will linearly
    /// assemble - it may be reset to empty if an incomplete or overlong one is received, for example.
    ///
    /// # Example
    /// ```
    /// let input = vec![0x05u8, 0x11, 0x22, 0x33, 0x44, 0x00];
    /// let result = vec![0x11u8, 0x22, 0x33, 0x44];
    /// let mut dec = cobs::Cobs::new();
    /// let mut v = Vec::<u8>::with_capacity(10000);
    /// for p in input {
    ///     let _ = dec.get_byte(p, &mut v);
    /// }
    /// assert!(v == result);
    /// ```
    ///
    pub fn get_byte<'a>(&mut self, c: u8, op: &'a mut Vec<u8>) -> Result<(), CobsError> {
        self.inbytes += 1;
        let (val, action) = self.process_token(c);
        match action {
            /* Something went wrong - accumulate the current captured bytes and flush */
            TokenResult::Error => {
                self.badbytes += op.len() as u64;
                op.clear();
            }

            /* We are still flushing, increment the bad bytes */
            TokenResult::Flushing => self.badbytes += 1,

            /* Nothing to see here, move along */
            TokenResult::NoAction => (),

            /* This token is to be stored, of there is room */
            TokenResult::Store => {
                if op.len() < op.capacity() {
                    op.push(val);
                } else {
                    self.badbytes += op.len() as u64;
                    self.toolong += 1;
                    op.clear();
                    self.state = DecoderState::Flushing;
                }
            }

            /* This frame is complete, return it */
            TokenResult::Complete => {
                self.packets += 1;
                self.goodbytes += op.len() as u64;
                return Ok(());
            }
        }
        /* If we fall out here then nothing interesting happened - need to keep building the packet */
        Err(CobsError::Ongoing)
    }

    /// Process an individual token from the stream, returning the action to be performed with it
    fn process_token(&mut self, tok: u8) -> (u8, TokenResult) {
        match self.state {
            /* === Waiting for a non-sentinel value. This will be the size of this run */
            DecoderState::Idle => {
                if tok != self.sentinel {
                    self.rxc = tok;
                    self.maxcount = tok == 255;
                    self.state = DecoderState::Rxing;
                }
                (0, TokenResult::NoAction)
            }

            /* === Receiving a run */
            DecoderState::Rxing => {
                self.rxc = self.rxc - 1;
                if 0 == self.rxc {
                    if self.sentinel == tok {
                        self.state = DecoderState::Idle;
                        (tok, TokenResult::Complete)
                    } else {
                        let action = if !self.maxcount {
                            TokenResult::Store
                        } else {
                            TokenResult::NoAction
                        };
                        self.rxc = tok;
                        self.maxcount = tok == 255;
                        (self.sentinel, action)
                    }
                } else {
                    if self.sentinel == tok {
                        self.state = DecoderState::Flushing;
                        (tok, TokenResult::Error)
                    } else {
                        (tok, TokenResult::Store)
                    }
                }
            }

            /* === Emptying the stream, and waiting for a sentinel to be received to start a new packet */
            DecoderState::Flushing => {
                if self.sentinel != tok {
                    (tok, TokenResult::Flushing)
                } else {
                    self.state = DecoderState::Idle;
                    (self.sentinel, TokenResult::NoAction)
                }
            }
        }
    }

    /// Calculate worst possible max packet size
    ///
    /// Returns the maximum packet size that is possible for the cobs encoding of this message
    /// assuming a worst-possible encoding. This occurs when a packet comprises a start run length
    /// and then there are no changes in data value. This nesseciates a new run length to be added
    /// into the packet every 254 bytes. The packet always terminates with a sentinel. Thus, the
    /// maximum length is 1+input_packet_len+input_packet_len/254+1.
    ///
    /// For the current implementation a maximum uncoded packet of [`MAX_PACKET_LEN`] is supported. This may
    /// change in future.
    ///
    /// # Errors
    /// No errors are returned.
    ///
    /// # Example
    /// ```
    /// println!("Maximum encoded packet length for packet of 4132 bytes is {}",
    ///           cobs::Cobs::max_possible_enc_len(4132));
    /// ```
    ///
    pub fn max_possible_enc_len(ip_len: usize) -> usize {
        1 + ip_len + ip_len / 256 + 1
    }

    /// Encode cobs packet into Vec
    ///
    /// Takes an input vector and returns a COBS packet suitable to go over the line.
    /// The input vector must be of a size that can be encoded into the output vector in the
    /// worst case. The `Cobs` instance is required so `Cobs::cobs_encode` knows what value
    /// to use for the sentinel.
    ///
    /// # Errors
    ///  `CobsError::ZeroLength` is returned for the case that a zero length input vector is
    /// passed. `CobsError::Overlong` is returned for the case that it was not possible to
    /// encode the input vector into the output vector.
    ///
    /// # Example
    /// ```
    /// let encoded = vec![0x05u8, 0x11, 0x22, 0x33, 0x44, 0x00];
    /// let unencoded = vec![0x11u8, 0x22, 0x33, 0x44];
    /// let mut dec = cobs::Cobs::new();
    /// let test_encoded = dec.cobs_encode_into_vec( &unencoded ).unwrap();
    /// assert!(encoded == test_encoded);
    ///
    pub fn cobs_encode_into_vec(self, ip: &Vec<u8>) -> Result<Vec<u8>, CobsError> {
        let mut e = Vec::<u8>::with_capacity(MAX_ENC_PACKET_LEN);
        match self.cobs_encode(ip, &mut e) {
            Ok(_s) => return Ok(e),
            Err(r) => return Err(r),
        };
    }

    /// Encode cobs packet
    ///
    /// Takes an input vector and encodes it into a COBS packet suitable to go over the line.
    /// The input vector must be of a size that can be encoded into the output vector in the
    /// worst case. The `Cobs` instance is required so `Cobs::cobs_encode` knows what value
    /// to use for the sentinel.
    ///
    /// # Errors
    ///  `CobsError::ZeroLength` is returned for the case that a zero length input vector is
    /// passed. `CobsError::Overlong` is returned for the case that it was not possible to
    /// encode the input vector into the output vector.
    ///
    /// # Example
    /// ```
    /// let encoded = vec![0x05u8, 0x11, 0x22, 0x33, 0x44, 0x00];
    /// let unencoded = vec![0x11u8, 0x22, 0x33, 0x44];
    /// let mut dec = cobs::Cobs::new();
    /// let mut v = Vec::<u8>::with_capacity(50);
    /// let _ = dec.cobs_encode( &unencoded, &mut v ).unwrap();
    /// assert!(encoded == v);
    ///
    pub fn cobs_encode<'a>(
        self,
        ip: &'a Vec<u8>,
        e: &'a mut Vec<u8>,
    ) -> Result<&'a mut Vec<u8>, CobsError> {
        if ip.len() == 0 {
            Err(CobsError::ZeroLength)
        } else if Self::max_possible_enc_len(ip.len()) > MAX_ENC_PACKET_LEN {
            Err(CobsError::Overlong)
        } else {
            let mut d: usize = 0; // Position for size pointer to end of slice
            e.push(self.sentinel); // Make room for initial stride byte

            for (_, i) in ip.iter().enumerate() {
                /* Deal with case of 0xff bytes with no sentinel - start a new run */
                if e.len() - d == 0xff {
                    e[d] = (e.len() - d) as u8;
                    d = e.len();
                    e.push(self.sentinel);
                }

                /* Deal with case that this is a sentinel - start a new run */
                if *i == self.sentinel {
                    e[d] = (e.len() - d) as u8;
                    d = e.len();
                }

                /* This appends either a data byte or a sentinel (which will be overwritten with a run length later) */
                e.push(*i);
            }
            e[d] = (e.len() - d) as u8;
            e.push(self.sentinel);
            Ok(e)
        }
    }
}
