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
    Sync,
    TSDelayed,
    DataDelayed,
    BothDelayed,
}

/// Results that can returned (found atoms in the stream)
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub enum ITMFrame {
    #[default]
    Empty,
    Timestamp {
        ttype: TSType,
        ts: u64,
    },
    Globaltimestamp {
        has_wrapped: bool,
        ts: u64,
    },
    Sw {
        addr: u8,
        data: u32,
    },
    Hw {
        disc: u8,
        data: u32,
    },
    Xtn {
        source: bool,
        len: u8,
        ex: u32,
    },
    NISync {
        itype: u8,
        context: u32,
        addr: u32,
    },
    TPIUSync {
        count: u64,
    },
    Newsync {
        count: u64,
    },
    Overflow {
        count: u64,
    },
    Noise {
        count: u64,
    },
}

/// Statistics about decode that are maintained
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct ITMStats {
    /// Number of bytes of input from source
    inbytestotal: u64,
    /// Number of input packets processed
    inpackets: u64,
    /// Number of input error packets
    inerrpackets: u64,
    /// Number of TPIU sync messages received
    tpiusync: u64,
    /// Number of ITM sync messages received
    itmsync: u64,
    /// Number of SW packets received
    swpkts: u64,
    /// Number of HW packets received
    hwpkts: u64,
    /// Number of overflow packets received
    overflow: u64,
    /// Number of local timestamp packets received
    ts: u64,
    /// Number of noise bytes received
    noise: u64,
}

trait State: Debug {
    fn token(&mut self, tok: u8, i: &mut ITMInternal)
        -> (Option<Box<dyn State>>, Option<ITMFrame>);
}

type StateMatchFn = fn(tok: u8, i: &mut ITMInternal) -> (Option<Box<dyn State>>, Option<ITMFrame>);

trait StateMatch {
    fn matches(tok: u8, i: &mut ITMInternal) -> (Option<Box<dyn State>>, Option<ITMFrame>);
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct ITMInternal {
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

impl ITMDecoder {
    fn new() -> Self {
        ITMDecoder {
            state: Box::new(Unsynced { last_bytes: 0 }),
            i: Default::default(),
        }
    }

    /// Set the context id length
    ///
    /// This cannot be known by the decoder and has to be set explicitly. It isn't used on cortex-7m.
    ///
    pub fn set_context_idlen(&mut self, l: u8) {
        self.i.context_idlen = l;
    }

    /// Interate through the packet assembler, returning an ITM message or exhaustion
    ///
    /// Feeds iterated bytes through the packet assembler, until either the stream expires or
    /// the packet is complete.  In the case of expiry subsequent calls will further extend the
    /// packet until it _is_ complete.
    ///
    /// Stats are updated and may be returned via [`ITMDecoder::stats()`].
    ///
    /// # Return value
    ///
    /// If the packet is incomplete `None` will be returned, otherwise the complete packet.
    ///
    /// # Example
    ///
    //    pub fn get_frame<'a>(
    //      &mut self,
    //    &mut iter::<Item = &'a u8>: impl Iterator<Item = &'a u8>,
    // ) -> Result<ITMFrame, ITMError> {
    //
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

    fn token(&mut self, tok: u8) -> Option<ITMFrame> {
        //print!("{:02x} ", tok);
        // Keep a record of last 8 bytes...these are used for checking syncs
        self.i.last_bytes = self.i.last_bytes << 8 | tok as u64;

        // ---- Check for TPIU sync. Shouldn't occur, so reset to unsynced case if it does
        if self.i.last_bytes & TPIU_SYNCMASK == TPIU_SYNCPATTERN {
            self.i.stats.tpiusync += 1;
            return Some(ITMFrame::TPIUSync {
                count: self.i.stats.tpiusync,
            });
        }

        // ---- Check for ITMSync (Sect D4.2.1 of ARM DDI 0403E) and reset accordingly
        if self.i.last_bytes & ITM_SYNCMASK == ITM_SYNCPATTERN {
            self.i.stats.itmsync += 1;
            self.i.page_register = 0;
        }

        // ---- Call the current state for processing, updating as needed
        //     fn token(&mut self, tok: u8, decoder: &mut ITMDecoder) -> Option<ITMFrame>
        let (newstate, retval) = self.state.token(tok, &mut self.i);
        if newstate.is_some() {
            //print!("Transition from {:?} ", self.state);
            self.state = newstate.unwrap();
            //println!("to {:?} ", self.state);
        }

        retval
    }
}

/* Table of all states to be checked for matches from idle state. Place these in liklihood order to minimise tests */
const STATEMATCH: [StateMatchFn; 9] = [
    Sw::matches,
    Hw::matches,
    Lts::matches,
    Overflow::matches,
    Gts1::matches,
    Gts2::matches,
    NISync::matches,
    Xtn::matches,
    Noise::matches,
];

/* ---- We are idle ------------------------------------------- */
/* (Sect D4.2 of ARM DDI 0403E)                                 */
/* ------------------------------------------------------------ */
#[derive(Default, Debug, Clone, Eq, PartialEq)]
struct Idle;

impl State for Idle {
    fn token(
        &mut self,
        tok: u8,
        i: &mut ITMInternal,
    ) -> (Option<Box<dyn State>>, Option<ITMFrame>) {
        for j in STATEMATCH.iter() {
            let (state, frame) = j(tok, i);
            if state.is_some() || frame.is_some() {
                return (state, frame);
            }
        }
        (None, None)
    }
}

/* ---- Unsynchronised ---------------------------------------- */
/* (Sect D4.2.1 of ARM DDI 0403E)                               */
/* ------------------------------------------------------------ */
#[derive(Default, Debug, Clone, Eq, PartialEq)]
struct Unsynced {
    last_bytes: u64,
}

impl State for Unsynced {
    fn token(
        &mut self,
        tok: u8,
        i: &mut ITMInternal,
    ) -> (Option<Box<dyn State>>, Option<ITMFrame>) {
        self.last_bytes = (self.last_bytes << 8) | tok as u64;
        if self.last_bytes & ITM_SYNCMASK == ITM_SYNCPATTERN {
            (
                Some(Box::new(Idle)),
                Some(ITMFrame::Newsync {
                    count: i.stats.itmsync,
                }),
            )
        } else {
            (None, None)
        }
    }
}

/* ---- A source instrumentation packet - SW ------------------ */
/* (Sect D4.2.8 of ARM DDI 0403E)                               */
/* ------------------------------------------------------------ */
#[derive(Default, Debug, Clone, Eq, PartialEq)]
struct Sw {
    target: u8,
    count: u8,
    addr: u8,
    data: u32,
}

impl State for Sw {
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
                Some(ITMFrame::Sw {
                    addr: self.addr + i.page_register,
                    data: self.data,
                }),
            )
        } else {
            (None, None)
        }
    }
}

impl StateMatch for Sw {
    fn matches(tok: u8, i: &mut ITMInternal) -> (Option<Box<dyn State>>, Option<ITMFrame>) {
        if tok & 0b0000_0011 != 0 && tok & 0b0000_0100 == 0 {
            i.stats.swpkts += 1;

            (
                Some(Box::new(Sw {
                    target: if tok & 3 == 3 { 4 } else { tok & 3 },
                    count: 0,
                    addr: (tok >> 3) & 0x1f,
                    data: 0,
                })),
                None,
            )
        } else {
            (None, None)
        }
    }
}

/* ---- A source instrumentation packet - HW ------------------ */
/* (Sect D4.2.9 of ARM DDI 0403E)                               */
/* ------------------------------------------------------------ */
#[derive(Default, Debug, Clone, Eq, PartialEq)]
struct Hw {
    target: u8,
    count: u8,
    disc: u8,
    data: u32,
}

impl State for Hw {
    fn token(
        &mut self,
        tok: u8,
        _i: &mut ITMInternal,
    ) -> (Option<Box<dyn State>>, Option<ITMFrame>) {
        if self.count <= 4 {
            self.data |= (tok as u32) << (8 * self.count);
            self.count += 1;
        }
        if self.count == self.target {
            (
                Some(Box::new(Idle)),
                Some(ITMFrame::Hw {
                    disc: self.disc,
                    data: self.data,
                }),
            )
        } else {
            (None, None)
        }
    }
}

impl StateMatch for Hw {
    fn matches(tok: u8, _i: &mut ITMInternal) -> (Option<Box<dyn State>>, Option<ITMFrame>) {
        if tok & 0b0000_0011 != 0 && tok & 0b0000_0100 != 0 {
            (
                Some(Box::new(Hw {
                    target: if tok & 3 == 3 { 4 } else { tok & 3 },
                    count: 0,
                    disc: (tok >> 3) & 0x1f,
                    data: 0,
                })),
                None,
            )
        } else {
            (None, None)
        }
    }
}

/* ---------------------------------------------------------------------- */
/* State handler for noise                                                */
/* ---------------------------------------------------------------------- */
#[derive(Default, Debug, Clone, Eq, PartialEq)]
struct Noise;

impl State for Noise {
    fn token(
        &mut self,
        tok: u8,
        i: &mut ITMInternal,
    ) -> (Option<Box<dyn State>>, Option<ITMFrame>) {
        if tok & 0x80 == 0 {
            (
                Some(Box::new(Idle)),
                Some(ITMFrame::Noise {
                    count: i.stats.noise,
                }),
            )
        } else {
            (None, None)
        }
    }
}

impl StateMatch for Noise {
    fn matches(tok: u8, i: &mut ITMInternal) -> (Option<Box<dyn State>>, Option<ITMFrame>) {
        i.stats.noise += 1;
        if tok & 0x80 != 0 {
            (Some(Box::new(Noise)), None)
        } else {
            (
                None,
                Some(ITMFrame::Noise {
                    count: i.stats.noise,
                }),
            )
        }
    }
}

/* ---- ISYNC packet ------------------------------------------ */
/* (Sect D4.2.5 of ARM DDI 0403E)                               */
/* ------------------------------------------------------------ */
#[derive(Default, Debug, Clone, Eq, PartialEq)]
struct NISync {
    target: u8,
    count: u8,
    addr: u32,
    context: u32,
    itype: u8,
}

impl State for NISync {
    fn token(
        &mut self,
        tok: u8,
        _i: &mut ITMInternal,
    ) -> (Option<Box<dyn State>>, Option<ITMFrame>) {
        self.target -= 1;

        match self.count {
            2 => self.itype = tok,
            3..5 => self.addr |= (tok as u32) << (8 * (self.count - 1)),
            _ => self.context |= (tok as u32) << (8 * (self.count - 5)),
        };

        if self.target == 0 {
            (
                Some(Box::new(Idle)),
                Some(ITMFrame::NISync {
                    itype: self.itype,
                    context: self.context,
                    addr: self.addr,
                }),
            )
        } else {
            (None, None)
        }
    }
}

impl StateMatch for NISync {
    fn matches(tok: u8, i: &mut ITMInternal) -> (Option<Box<dyn State>>, Option<ITMFrame>) {
        if tok == 0b00001000 {
            (
                Some(Box::new(NISync {
                    target: 5 + i.context_idlen,
                    itype: 0,
                    addr: 0,
                    context: 0,
                    count: 0,
                })),
                None,
            )
        } else {
            (None, None)
        }
    }
}

/* ---- General Extension packet ------------------------------ */
/* (Sect D4.2.5 of ARM DDI 0403E)                               */
/* ------------------------------------------------------------ */
#[derive(Default, Debug, Clone, Eq, PartialEq)]
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
        if tok & 0b00001011 == 0b00001000 {
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
        } else {
            {
                (None, None)
            }
        }
    }
}

/* ---- A Local Timestamp packet ------------------------------ */
/* (Sect D4.2.4 of ARM DDI 0403E)                               */
/* ------------------------------------------------------------ */
#[derive(Default, Debug, Clone, Eq, PartialEq)]
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
        if tok & 0b00001111 == 0 && tok != 0 && tok & 0b0111_1111 != 0b0111_0000 {
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
                        ttypen: (tok >> 5) & 3,
                        ts: 0,
                        count: 0,
                    })),
                    None,
                )
            }
        } else {
            (None, None)
        }
    }
}

/* ---- Global Timestamp packet type 2 ------------------------ */
/* (Sect D4.2.5 of ARM DDI 0403E)                               */
/* ------------------------------------------------------------ */
#[derive(Default, Debug, Clone, Eq, PartialEq)]
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
    fn matches(tok: u8, _i: &mut ITMInternal) -> (Option<Box<dyn State>>, Option<ITMFrame>) {
        if tok == 0b10110100 {
            (Some(Box::new(Gts2 { count: 0, gts: 0 })), None)
        } else {
            (None, None)
        }
    }
}

/* ---- Global Timestamp packet type 1 ------------------------ */
/* (Sect D4.2.5 of ARM DDI 0403E)                               */
/* ------------------------------------------------------------ */
#[derive(Default, Debug, Clone, Eq, PartialEq)]
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
    fn matches(tok: u8, i: &mut ITMInternal) -> (Option<Box<dyn State>>, Option<ITMFrame>) {
        if tok == 0b1001_0100 {
            (
                Some(Box::new(Gts1 {
                    wrap: false,
                    count: 0,
                    gts: i.gtimestamp,
                })),
                None,
            )
        } else {
            (None, None)
        }
    }
}

/* ---- An overflow packet ------------------------------------ */
/* (Sect D4.2.3 of ARM DDI 0403E)                               */
/* ------------------------------------------------------------ */
#[derive(Default, Debug, Clone, Eq, PartialEq)]
struct Overflow;

impl StateMatch for Overflow {
    fn matches(tok: u8, i: &mut ITMInternal) -> (Option<Box<dyn State>>, Option<ITMFrame>) {
        if tok == 0b01110000 {
            i.stats.overflow += 1;
            (
                None,
                Some(ITMFrame::Overflow {
                    count: i.stats.overflow,
                }),
            )
        } else {
            (None, None)
        }
    }
}
