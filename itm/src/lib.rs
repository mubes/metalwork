/// Based on Appendix F of DDI0553B.v (Arm v8-M Architecture Reference Manual Rel 22)
///
/// Decode of ITM flow from CORTEX-v8m microcontrollers.  This flow can either be delivered
/// cleanly out of the SWO pin, or encapsulated in TPIU frames. It can also be transported
/// using orbflow frames. In any case, this module decodes the unwrapped ITM flow and turns
/// it into individual messages for processing by higher layers.
///
use bitmatch::bitmatch;
use std::default::Default;
use std::fmt;
use std::fmt::Debug;
mod test_lib;

const ITM_SYNCMASK: u64 = 0xFFFFFFFFFFFF;
const ITM_SYNCPATTERN: u64 = 0x000000000080;
const TPIU_SYNCMASK: u64 = 0xFFFFFFFF;
const TPIU_SYNCPATTERN: u64 = 0xFFFFFF7F;

/// Errors from use of this crate
#[derive(Debug, Clone, Eq, Copy, PartialEq)]
pub enum ITMError {
    /// Not enough data available to complete operation
    ShortData,
    /// Function not implemented
    Unimplemented,
}

impl fmt::Display for ITMError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ITMError::ShortData => write!(f, "Packet is too short"),
            ITMError::Unimplemented => write!(f, "Unimplemented"),
        }
    }
}

impl std::error::Error for ITMError {}
/// Types of timestamp
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub enum TSType {
    #[default]
    /// Timestamp is synchronous to data
    Sync,
    /// Timestamp is delayed with respect to data
    TSDelayed,
    /// Data is delayed with respect to timestamp
    DataDelayed,
    /// Both data and timestamp are delayed
    BothDelayed,
}

/// Types of exception event
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub enum ExceptionEvent {
    #[default]
    /// Unknown
    Unknown,
    /// Entry into exception
    Entry,
    /// Exit from exception
    Exit,
    /// Return to exception handler
    Returned,
}

/// Results (found atoms in the stream)
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub enum ITMFrame {
    #[default]
    /// No content
    Empty,

    /// A valid (local) timestamp
    Timestamp { ttype: TSType, ts: u64 },

    /// A global timestamp, with indication if it has wrapped
    Globaltimestamp { has_wrapped: bool, ts: u64 },

    /// A general instrumentation packet
    Instrumentation { addr: u8, data: u32, len: u8 },

    /// An exception, and the event that occured on that exception
    Exception { no: u16, event: ExceptionEvent },

    /// Data trace indication (tied to DWT comparator index for shortened forms)
    DataTracePC { index: u8, addr: u32, len: u8 },

    /// Data trace address (tied to DWT comparator index for shortened forms)
    DataTraceAddr { index: u8, daddr: u32, len: u8 },

    /// Data trace value (tied to DWT comparator index for shortened forms)
    DataTraceValue {
        index: u8,
        addr: u32,
        len: u8,
        wnr: bool,
    },

    /// Indication of data trace match, with matching comparator
    DataTraceMatch { index: u8 },

    /// Asleep at the point where the PC was sampled, with indication if sleep was prohibited
    PCSleep { prohibited: bool },

    /// PC interval sample value
    PCSample { addr: u32 },

    /// Extension packet with source and ex value
    Xtn { source: bool, len: u8, ex: u32 },

    /// Indication that a TPIU sync has been received (this is not a good thing in an ITM flow)
    TPIUSync { count: u64 },

    /// Indication that sync has been received
    Sync { count: u64 },

    /// Overflow indication
    Overflow { count: u64 },

    /// Event counter wraparound indication
    EventC {
        cpicnt_wrapped: bool,
        exccnt_wrapped: bool,
        sleepcnt_wrapped: bool,
        lsucnt_wrapped: bool,
        foldcnt_wrapped: bool,
        postcnt_wrapped: bool,
    },

    /// PMU overflow indication
    PMUOverflow { ovf: u8 },
}

/// Statistics about decode that are maintained
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct ITMStats {
    /// Number of bytes of input from source
    pub inbytestotal: u64,
    /// Number of input packets processed
    pub inpackets: u64,
    /// Number of TPIU sync messages received
    pub tpiusync: u64,
    /// Number of ITM sync messages received
    pub itmsync: u64,
    /// Number of Instrumentation packets received
    pub instrupkts: u64,
    /// Number of overflow packets received
    pub overflow: u64,
    /// Number of local timestamp packets received
    pub ts: u64,
    /// Number of noise bytes received
    pub noise: u64,
}

/// Processing specific to a state - in this case, token handling
trait State: Debug {
    fn token(&mut self, tok: u8, i: &mut ITMInternal)
        -> (Option<Box<dyn State>>, Option<ITMFrame>);
}

/// Processing for state creation
trait StateMatch {
    fn matches(tok: u8, i: &mut ITMInternal) -> (Option<Box<dyn State>>, Option<ITMFrame>);
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
struct ITMInternal {
    last_bytes: u64,   // Sequence of last bytes received...used for sync purposes
    page_register: u8, // Page number register
    context_idlen: u8, // Length of context ID
    timestamp: u32,    // Local timestamp last valid value
    gtimestamp: u64,   // Global timestamp last valid value

    stats: ITMStats, // Statistics maintenance
}
/// The stateful ITM decoder
///
/// This maintains sticky state information and statistics of packets decoded by the ITM machine.
///
#[derive(Debug)]
pub struct ITMDecoder {
    state: Box<dyn State>,
    i: ITMInternal,
}

impl Default for ITMDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl ITMDecoder {
    /// Create new instance, initially in the unsynchronised state
    ///
    /// New instance will have zero'ed statistics.
    ///
    pub fn new() -> Self {
        ITMDecoder {
            state: Box::new(Unsynced),
            i: Default::default(),
        }
    }

    /// Provide statistical information about the performance of the decoder instance.
    ///
    /// # Return value
    ///
    /// A read-only reference to the structure containing the current statistics.
    ///
    /// # Example
    /// ```
    /// use itm::ITMDecoder;
    /// let mut i = ITMDecoder::new();
    /// println!("{:?}",i.stats());
    /// ```
    pub fn stats(&self) -> &ITMStats {
        &self.i.stats
    }

    /// Set the context id length
    ///
    /// This cannot be known by the decoder and has to be set explicitly.
    ///
    /// # Example
    /// ```
    /// use itm::ITMDecoder;
    /// let mut i = ITMDecoder::new();
    /// i.set_context_idlen(8);
    /// ```
    pub fn set_context_idlen(&mut self, l: u8) {
        self.i.context_idlen = l;
    }

    /// Interate through the packet assembler, returning an ITM message or exhaustion
    ///
    /// Feeds iterated bytes through the packet assembler, until either the stream expires or
    /// the packet is complete.  In the case of expiry subsequent calls will further extend the
    /// packet until it _is_ complete.
    ///
    /// Stats are updated and may be returned via [`ITMDecoder::stats()`]. Note that
    /// if you are working with a part with a context_id you must set that using
    /// [`ITMDecoder::set_context_idlen()`] before starting decode, otherwise corruption
    /// may occur.
    ///
    /// # Return value
    ///
    /// If the packet is incomplete `None` will be returned, otherwise an instance
    /// of a complete packet.
    ///
    /// # Example
    /// ```
    /// use itm::ITMDecoder;
    /// let mut i = ITMDecoder::new();
    /// let ip = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x80,];
    /// let mut v = ip.iter();
    /// println!("Returned frame={:?}",i.get_frame(&mut v));
    /// ```
    pub fn get_frame<'a, I>(&mut self, iter: &mut I) -> Result<ITMFrame, ITMError>
    where
        I: Iterator<Item = &'a u8>,
    {
        loop {
            match iter.next() {
                Some(t) => match self.token(*t) {
                    Some(s) => return Ok(s),
                    None => continue,
                },
                None => {
                    return Err(ITMError::ShortData);
                }
            }
        }
    }

    // Process single token from the stream and see if it returned a frame
    fn token(&mut self, tok: u8) -> Option<ITMFrame> {
        print!("{:02x} ", tok);
        // Keep a record of last 8 bytes...these are used for checking syncs
        self.i.last_bytes = self.i.last_bytes << 8 | tok as u64;
        self.i.stats.inbytestotal += 1;

        // ---- Check for TPIU sync. Shouldn't occur, so reset to unsynced case if it does
        if self.i.last_bytes & TPIU_SYNCMASK == TPIU_SYNCPATTERN {
            self.i.stats.tpiusync += 1;
            self.i.stats.inpackets += 1;
            self.state = Box::new(Unsynced);
            return Some(ITMFrame::TPIUSync {
                count: self.i.stats.tpiusync,
            });
        }

        // ---- Check for ITMSync
        if self.i.last_bytes & ITM_SYNCMASK == ITM_SYNCPATTERN {
            self.i.stats.itmsync += 1;
            self.i.page_register = 0;
            self.i.stats.inpackets += 1;
            self.state = Box::new(Idle);
            println!("Sync");
            return Some(ITMFrame::Sync {
                count: self.i.stats.itmsync,
            });
        }

        // ---- Call the current state for processing, updating as needed
        let (newstate, retval) = self.state.token(tok, &mut self.i);

        if retval.is_some() {
            self.i.stats.inpackets += 1;
        }
        if newstate.is_some() {
            print!("Transition from {:?} ", self.state);
            self.state = newstate.unwrap();
            println!("to {:?} ", self.state);
        }

        retval
    }
}

/* ---- We are idle ------------------------------------------- */
/* Section F1.2.1 of DDI0553B.v                                 */
/* ------------------------------------------------------------ */
#[derive(Debug, Clone, Eq, PartialEq)]
struct Idle;

impl State for Idle {
    #[bitmatch]
    fn token(
        &mut self,
        tok: u8,
        i: &mut ITMInternal,
    ) -> (Option<Box<dyn State>>, Option<ITMFrame>) {
        /* This dispatch table is defined in section F1.1.2 */
        #[bitmatch]
        match tok {
            "0000_0000" => (None, None),
            "0111_0000" => Overflow::matches(tok, i),
            "1001_0100" => Gts1::matches(tok, i),
            "1011_0100" => Gts2::matches(tok, i),
            "0???_0000" => Lts::matches(tok, i),
            "11??_0000" => Lts::matches(tok, i),
            "????_1?00" => Xtn::matches(tok, i),
            "0000_0101" => Event::matches(tok, i),
            "????_??00" => {
                i.stats.noise += 1;
                (None, None)
            }
            "01??_?1??" => DataTrace::matches(tok, i),
            "0000_1110" => Exception::matches(tok, i),
            "10??_?1??" => DataTrace::matches(tok, i),
            "????_?0??" => Instrumentation::matches(tok, i),
            "0001_01?1" => PCSample::matches(tok, i),
            "0001_1101" => PMUOverflow::matches(tok, i),
            _ => {
                i.stats.noise += 1;
                (None, None)
            }
        }
    }
}

/* ---- Unsynchronised ---------------------------------------- */
/* Section F1.2.16 of DDI0553B.v                                */
/* ------------------------------------------------------------ */
#[derive(Debug, Clone, Eq, PartialEq)]
struct Unsynced;

impl State for Unsynced {
    fn token(
        &mut self,
        _tok: u8,
        _i: &mut ITMInternal,
    ) -> (Option<Box<dyn State>>, Option<ITMFrame>) {
        // Don't actually do anything, the dispatcher deals with this case
        (None, None)
    }
}

/* ---- A source instrumentation packet ----------------------- */
/* Section F1.2.10 of DDI0553B.v                                */
/* ------------------------------------------------------------ */
#[derive(Debug, Clone, Eq, PartialEq)]
struct Instrumentation {
    target: u8,
    count: u8,
    addr: u8,
    data: u32,
}

impl State for Instrumentation {
    fn token(
        &mut self,
        tok: u8,
        i: &mut ITMInternal,
    ) -> (Option<Box<dyn State>>, Option<ITMFrame>) {
        if self.count <= 4 {
            self.data |= (tok as u32) << (8 * self.count);
            self.count += 1;
        }
        if self.count == self.target {
            (
                Some(Box::new(Idle)),
                Some(ITMFrame::Instrumentation {
                    addr: self.addr + i.page_register,
                    data: self.data,
                    len: self.target,
                }),
            )
        } else {
            (None, None)
        }
    }
}

impl StateMatch for Instrumentation {
    fn matches(tok: u8, i: &mut ITMInternal) -> (Option<Box<dyn State>>, Option<ITMFrame>) {
        i.stats.instrupkts += 1;

        (
            Some(Box::new(Instrumentation {
                target: if tok & 3 == 3 { 4 } else { tok & 3 },
                count: 0,
                addr: (tok >> 3) & 0x1f,
                data: 0,
            })),
            None,
        )
    }
}

/* ---- General Extension packet ------------------------------ */
/* Section F1.2.7 of DDI0553B.v                                 */
/* ------------------------------------------------------------ */
#[derive(Debug, Clone, Eq, PartialEq)]
struct Xtn {
    ex: u32,
    source: bool,
    bitcount: u8,
    count: u8,
}

impl State for Xtn {
    fn token(
        &mut self,
        tok: u8,
        _i: &mut ITMInternal,
    ) -> (Option<Box<dyn State>>, Option<ITMFrame>) {
        if self.count <= 4 {
            if self.count < 4 {
                self.ex |= ((tok & 0x7f) as u32) << self.bitcount;
            } else {
                self.ex |= (tok as u32) << self.bitcount;
            }
            self.count += 1;
            self.bitcount += 7;
        }

        if tok & 0x80 == 0 {
            (
                Some(Box::new(Idle)),
                Some(ITMFrame::Xtn {
                    source: self.source,
                    len: self.count,
                    ex: self.ex,
                }),
            )
        } else {
            (None, None)
        }
    }
}

impl StateMatch for Xtn {
    fn matches(tok: u8, i: &mut ITMInternal) -> (Option<Box<dyn State>>, Option<ITMFrame>) {
        if tok & 0x80 == 0 {
            if tok & 4 != 0 {
                /* Deal with page register case here */
                i.page_register = 32 * ((tok >> 4) & 7);
                (Some(Box::new(Idle)), None)
            } else {
                (
                    Some(Box::new(Idle)),
                    Some(ITMFrame::Xtn {
                        source: (tok & 4) != 0,
                        len: 0,
                        ex: (tok >> 4) as u32 & 7,
                    }),
                )
            }
        } else {
            (
                Some(Box::new(Xtn {
                    source: (tok & 4) != 0,
                    ex: (tok >> 4) as u32 & 7,
                    count: 0,
                    bitcount: 3,
                })),
                None,
            )
        }
    }
}

/* ---- A Local Timestamp packet ------------------------------ */
/* Section F1.2.11 and F1.2.12 of DDI0553B.v                    */
/* ------------------------------------------------------------ */
#[derive(Debug, Clone, Eq, PartialEq)]
struct Lts {
    count: u8,
    ttypen: u8,
    ts: u64,
}

impl State for Lts {
    fn token(
        &mut self,
        tok: u8,
        _i: &mut ITMInternal,
    ) -> (Option<Box<dyn State>>, Option<ITMFrame>) {
        if self.count < 4 {
            self.ts |= ((tok & 0x7f) as u64) << (7 * self.count);
            self.count += 1;
        }

        if tok & 0x80 == 0 {
            (
                Some(Box::new(Idle)),
                Some(ITMFrame::Timestamp {
                    ttype: match self.ttypen {
                        0 => TSType::Sync,
                        1 => TSType::TSDelayed,
                        2 => TSType::DataDelayed,
                        3 => TSType::BothDelayed,
                        _ => TSType::BothDelayed,
                    },

                    ts: self.ts,
                }),
            )
        } else {
            (None, None)
        }
    }
}

impl StateMatch for Lts {
    fn matches(tok: u8, i: &mut ITMInternal) -> (Option<Box<dyn State>>, Option<ITMFrame>) {
        i.stats.ts += 1;
        if tok & 0x80 == 0 {
            (
                /* This is a type 2 packet - single byte */
                Some(Box::new(Idle)),
                Some(ITMFrame::Timestamp {
                    ttype: TSType::Sync,
                    ts: ((tok >> 4) & 7) as u64,
                }),
            )
        } else {
            (
                /* This is a type 1 packet - multibyte */
                Some(Box::new(Lts {
                    ttypen: (tok >> 4) & 3,
                    ts: 0,
                    count: 0,
                })),
                None,
            )
        }
    }
}

/* ---- Global Timestamp packet type 2 ------------------------ */
/* Section F1.2.9 of DDI0553B.v                                 */
/* ------------------------------------------------------------ */
#[derive(Debug, Clone, Eq, PartialEq)]
struct Gts2 {
    count: u8,
    gts: u64,
}

impl State for Gts2 {
    fn token(
        &mut self,
        tok: u8,
        i: &mut ITMInternal,
    ) -> (Option<Box<dyn State>>, Option<ITMFrame>) {
        if self.count < 7 {
            let shift = 7 * self.count;
            self.gts |= ((tok & 0x7f) as u64) << shift;
            self.count += 1;
        }

        if tok & 0x80 == 0 {
            i.gtimestamp = self.gts;
            (
                Some(Box::new(Idle)),
                Some(ITMFrame::Globaltimestamp {
                    has_wrapped: false,
                    ts: self.gts,
                }),
            )
        } else {
            (None, None)
        }
    }
}

impl StateMatch for Gts2 {
    fn matches(_tok: u8, _i: &mut ITMInternal) -> (Option<Box<dyn State>>, Option<ITMFrame>) {
        (Some(Box::new(Gts2 { count: 0, gts: 0 })), None)
    }
}

/* ---- Global Timestamp packet type 1 ------------------------ */
/* Section F1.2.8 of DDI0553B.v                                 */
/* ------------------------------------------------------------ */
#[derive(Debug, Clone, Eq, PartialEq)]
struct Gts1 {
    count: u8,
    gts: u64,
    wrap: bool,
}

impl State for Gts1 {
    fn token(
        &mut self,
        tok: u8,
        i: &mut ITMInternal,
    ) -> (Option<Box<dyn State>>, Option<ITMFrame>) {
        if self.count <= 3 {
            let shift = 7 * self.count;
            self.count += 1;
            if self.count == 4 {
                self.wrap = (tok & 0x40) != 0;
                self.gts = (self.gts & !(0x1f_u64 << shift)) | (((tok & 0x1f) as u64) << shift);
            } else {
                self.gts = (self.gts & !(0x7f_u64 << shift)) | (((tok & 0x7f) as u64) << shift);
            }
        }
        if tok & 0x80 == 0 {
            i.gtimestamp = self.gts;
            (
                Some(Box::new(Idle)),
                Some(ITMFrame::Globaltimestamp {
                    has_wrapped: self.wrap,
                    ts: self.gts,
                }),
            )
        } else {
            (None, None)
        }
    }
}

impl StateMatch for Gts1 {
    fn matches(_tok: u8, i: &mut ITMInternal) -> (Option<Box<dyn State>>, Option<ITMFrame>) {
        (
            Some(Box::new(Gts1 {
                wrap: false,
                count: 0,
                gts: i.gtimestamp,
            })),
            None,
        )
    }
}

/* ---- Exception Trace --------------------------------------- */
/* Section F1.2.6 of DDI0553B.v                                 */
/* ------------------------------------------------------------ */
#[derive(Debug, Clone, Eq, PartialEq)]
struct Exception {
    no: u16,
    count: u8,
    event: u8,
}

impl State for Exception {
    fn token(
        &mut self,
        tok: u8,
        _i: &mut ITMInternal,
    ) -> (Option<Box<dyn State>>, Option<ITMFrame>) {
        self.count += 1;
        match self.count {
            1 => {
                self.no = tok as u16;
                (None, None)
            }
            2 => {
                self.no |= (tok as u16 & 1) << 8;
                let e = match (tok >> 4) & 3 {
                    1 => ExceptionEvent::Entry,
                    2 => ExceptionEvent::Exit,
                    3 => ExceptionEvent::Returned,
                    _ => ExceptionEvent::Unknown,
                };
                (
                    Some(Box::new(Idle)),
                    Some(ITMFrame::Exception {
                        no: self.no,
                        event: e,
                    }),
                )
            }
            _ => (None, None),
        }
    }
}

impl StateMatch for Exception {
    fn matches(_tok: u8, _i: &mut ITMInternal) -> (Option<Box<dyn State>>, Option<ITMFrame>) {
        (
            Some(Box::new(Exception {
                no: 0,
                count: 0,
                event: 0,
            })),
            None,
        )
    }
}

/* ---- Data Trace Match -------------------------------------- */
/* Section F1.2.1, F1.2.3 & F1.2.4 of DDI0553B.v                */
/* ------------------------------------------------------------ */
#[derive(Debug, Clone, Eq, PartialEq)]
enum DataMatchType {
    Match,
    PCMatch,
    DataAddrMatch,
    DataValMatch,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct DataTrace {
    index: u8,
    len: u8,
    count: u8,
    addr: u32,
    dt_type: DataMatchType,
    wnr: bool,
}

impl State for DataTrace {
    fn token(
        &mut self,
        tok: u8,
        _i: &mut ITMInternal,
    ) -> (Option<Box<dyn State>>, Option<ITMFrame>) {
        self.addr |= (tok as u32) << (self.count * 8);
        self.count += 1;

        if self.dt_type == DataMatchType::Match && self.len == 1 && (tok & 1 == 1) {
            (
                /* This is a data trace match packet */
                Some(Box::new(Idle)),
                Some(ITMFrame::DataTraceMatch { index: self.index }),
            )
        } else if self.count == self.len {
            match self.dt_type {
                DataMatchType::DataValMatch => (
                    Some(Box::new(Idle)),
                    Some(ITMFrame::DataTraceValue {
                        index: self.index,
                        addr: self.addr,
                        len: self.len,
                        wnr: self.wnr,
                    }),
                ),

                DataMatchType::Match => (
                    Some(Box::new(Idle)),
                    Some(ITMFrame::DataTracePC {
                        index: self.index,
                        addr: self.addr,
                        len: self.len,
                    }),
                ),

                DataMatchType::PCMatch => (
                    Some(Box::new(Idle)),
                    Some(ITMFrame::DataTracePC {
                        index: self.index,
                        addr: self.addr,
                        len: self.len,
                    }),
                ),

                DataMatchType::DataAddrMatch => (
                    Some(Box::new(Idle)),
                    Some(ITMFrame::DataTraceAddr {
                        index: self.index,
                        daddr: self.addr,
                        len: self.len,
                    }),
                ),
            }
        } else {
            (None, None)
        }
    }
}

impl StateMatch for DataTrace {
    #[bitmatch]
    fn matches(tok: u8, _i: &mut ITMInternal) -> (Option<Box<dyn State>>, Option<ITMFrame>) {
        (
            Some(Box::new(DataTrace {
                index: (tok >> 4) & 3,
                addr: 0,
                len: if tok & 3 == 3 { 4 } else { tok & 3 },
                count: 0,
                wnr: (tok & 8) != 0,
                dt_type: {
                    #[bitmatch]
                    match tok {
                        "01??_0101" => DataMatchType::Match,
                        "01??_01??" => DataMatchType::PCMatch,
                        "01??_11??" => DataMatchType::DataAddrMatch,
                        "10??_?1??" => DataMatchType::DataValMatch,
                        _ => {
                            panic!()
                        }
                    }
                },
            })),
            None,
        )
    }
}

/* ---- Periodic PC Sample ------------------------------------ */
/* Section F1.2.14 of DDI0553B.v                                */
/* ------------------------------------------------------------ */
#[derive(Debug, Clone, Eq, PartialEq)]
struct PCSample {
    len: u8,
    count: u8,
    addr: u32,
}

impl State for PCSample {
    fn token(
        &mut self,
        tok: u8,
        _i: &mut ITMInternal,
    ) -> (Option<Box<dyn State>>, Option<ITMFrame>) {
        if self.len == 1 {
            (
                Some(Box::new(Idle)),
                (Some(ITMFrame::PCSleep {
                    prohibited: tok == 0xff,
                })),
            )
        } else {
            self.addr |= (tok as u32) << (self.count * 8);
            self.count += 1;
            if self.count == self.len {
                (
                    Some(Box::new(Idle)),
                    (Some(ITMFrame::PCSample { addr: self.addr })),
                )
            } else {
                (None, None)
            }
        }
    }
}

impl StateMatch for PCSample {
    fn matches(tok: u8, _i: &mut ITMInternal) -> (Option<Box<dyn State>>, Option<ITMFrame>) {
        (
            Some(Box::new(PCSample {
                addr: 0,
                len: if tok & 3 == 3 { 4 } else { tok & 3 },
                count: 0,
            })),
            None,
        )
    }
}

/* ---- Event packet ------------------------------------------ */
/* Section F1.2.5 of DDI0553B.v                                 */
/* ------------------------------------------------------------ */
#[derive(Debug, Clone, Eq, PartialEq)]
struct Event;

impl State for Event {
    fn token(
        &mut self,
        tok: u8,
        _i: &mut ITMInternal,
    ) -> (Option<Box<dyn State>>, Option<ITMFrame>) {
        (
            Some(Box::new(Idle)),
            Some(ITMFrame::EventC {
                cpicnt_wrapped: tok & (1 << 0) != 0,
                exccnt_wrapped: tok & (1 << 1) != 0,
                sleepcnt_wrapped: tok & (1 << 2) != 0,
                lsucnt_wrapped: tok & (1 << 3) != 0,
                foldcnt_wrapped: tok & (1 << 4) != 0,
                postcnt_wrapped: tok & (1 << 5) != 0,
            }),
        )
    }
}

impl StateMatch for Event {
    fn matches(_tok: u8, _i: &mut ITMInternal) -> (Option<Box<dyn State>>, Option<ITMFrame>) {
        (Some(Box::new(Event)), None)
    }
}

/* ---- PMU packet -------------------------------------------- */
/* Section F1.2.15 of DDI0553B.v                                */
/* ------------------------------------------------------------ */
#[derive(Debug, Clone, Eq, PartialEq)]
struct PMUOverflow;

impl State for PMUOverflow {
    fn token(
        &mut self,
        tok: u8,
        _i: &mut ITMInternal,
    ) -> (Option<Box<dyn State>>, Option<ITMFrame>) {
        (
            Some(Box::new(Idle)),
            Some(ITMFrame::PMUOverflow { ovf: tok }),
        )
    }
}

impl StateMatch for PMUOverflow {
    fn matches(_tok: u8, _i: &mut ITMInternal) -> (Option<Box<dyn State>>, Option<ITMFrame>) {
        (Some(Box::new(PMUOverflow)), None)
    }
}

/* ---- An overflow packet ------------------------------------ */
/* Section F1.2.13 of DDI0553B.v                                */
/* ------------------------------------------------------------ */
#[derive(Debug, Clone, Eq, PartialEq)]
struct Overflow;

impl StateMatch for Overflow {
    fn matches(_tok: u8, i: &mut ITMInternal) -> (Option<Box<dyn State>>, Option<ITMFrame>) {
        i.stats.overflow += 1;
        (
            None,
            Some(ITMFrame::Overflow {
                count: i.stats.overflow,
            }),
        )
    }
}
