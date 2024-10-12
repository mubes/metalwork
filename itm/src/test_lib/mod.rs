#[cfg(test)]
use super::*;

#[test]
fn test_sync() {
    let mut i = ITMDecoder::new();
    let ip = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x80];

    let g = i.get_frame(&mut ip.iter());
    assert_eq!(Ok(ITMFrame::Sync { count: 1 }), g);
}

#[test]
fn test_nosync() {
    let mut i = ITMDecoder::new();
    let ip = vec![0x00, 0x00, 0x00, 0x00, 0x20, 0x80];

    let g = i.get_frame(&mut ip.iter());
    assert_eq!(Err(ITMError::ShortData), g);
}

#[test]
fn test_tpiusync() {
    let mut i = ITMDecoder::new();
    let ip = vec![0x00, 0xff, 0xff, 0xff, 0x7f, 0x80];

    let g = i.get_frame(&mut ip.iter());
    assert_eq!(Ok(ITMFrame::TPIUSync { count: 1 }), g);
}

#[test]
fn test_overflow() {
    let mut i = ITMDecoder::new();
    let ip = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x70];
    let mut v = ip.iter();

    let g = i.get_frame(&mut v);
    assert_eq!(Ok(ITMFrame::Sync { count: 1 }), g);
    let g = i.get_frame(&mut v);
    assert_eq!(Ok(ITMFrame::Overflow { count: 1 }), g);
}

#[test]
fn test_local_ts_2() {
    let mut i = ITMDecoder::new();
    let ip = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x30];
    let mut v = ip.iter();

    let g = i.get_frame(&mut v);
    assert_eq!(Ok(ITMFrame::Sync { count: 1 }), g);
    let g = i.get_frame(&mut v);
    assert_eq!(
        Ok(ITMFrame::Timestamp {
            ttype: TSType::Sync,
            ts: 3
        }),
        g
    );
}

#[test]
fn test_local_ts_1() {
    let mut i = ITMDecoder::new();
    let ip = vec![
        0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // Sync
        0xD0, 0x85, 0x82, 0x01, // TS Type 1 value 0x4105
        0xE0, 0x85, 0x85, 0x85, 0x85, 0x85, 0x00, // Type 1 with extra byte
    ];
    let mut v = ip.iter();

    let g = i.get_frame(&mut v);
    assert_eq!(Ok(ITMFrame::Sync { count: 1 }), g);
    let g = i.get_frame(&mut v);
    assert_eq!(
        Ok(ITMFrame::Timestamp {
            ttype: TSType::TSDelayed,
            ts: 0x4105
        }),
        g
    );
    let g = i.get_frame(&mut v);
    assert_eq!(
        Ok(ITMFrame::Timestamp {
            ttype: TSType::DataDelayed,
            ts: 0xa14285
        }),
        g
    );
}

#[test]
fn test_gts_1() {
    let mut i = ITMDecoder::new();
    let ip = vec![
        0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // Sync
        0x94, 0x42, // Simple short packet
        0x94, 0xf3, 0x92, 0xd0, 0x4f, // Full length 48 bit with wrap
        0x94, 0xf3, 0x92, 0xd0, 0xff, 0x22, // Non-compliant
        0x94, 0xff, 0x7f, // Change 14 bits
    ];
    let mut v = ip.iter();
    let g = i.get_frame(&mut v);
    assert_eq!(Ok(ITMFrame::Sync { count: 1 }), g);

    let g = i.get_frame(&mut v);
    assert_eq!(
        Ok(ITMFrame::Globaltimestamp {
            has_wrapped: false,
            ts: 0x42
        }),
        g,
        "Simple short packet"
    );
    let g = i.get_frame(&mut v);
    assert_eq!(
        Ok(ITMFrame::Globaltimestamp {
            has_wrapped: true,
            ts: 0x1f40973
        }),
        g,
        "48 bit packet with wrap"
    );
    let g = i.get_frame(&mut v);
    assert_eq!(
        Ok(ITMFrame::Globaltimestamp {
            has_wrapped: true,
            ts: 0x3f40973
        }),
        g,
        "Non-compliant overlong packet with wrap"
    );
    let g = i.get_frame(&mut v);
    assert_eq!(
        Ok(ITMFrame::Globaltimestamp {
            has_wrapped: false,
            ts: 0x3f43fff
        }),
        g,
        "Replace bottom 14 bits"
    );
}

#[test]
fn test_gts_2() {
    let mut i = ITMDecoder::new();
    let ip = vec![
        0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // Sync
        0xb4, 0x84, 0x81, 0x82, 0x83, 0x01, // 48 bit format, good packet
        0xb4, 0x84, 0x81, 0x82, 0x83, 0x81, 0x01, // Illegal, but we handle it
        0xb4, 0x84, 0x81, 0x82, 0x83, 0x81, 0x81, 0x07, // Full length 64 bit packet
    ];
    let mut v = ip.iter();
    let g = i.get_frame(&mut v);
    assert_eq!(Ok(ITMFrame::Sync { count: 1 }), g);

    let g = i.get_frame(&mut v);
    assert_eq!(
        Ok(ITMFrame::Globaltimestamp {
            has_wrapped: false,
            ts: 0x10608084
        }),
        g,
        "Simple 48-bit test"
    );

    let g = i.get_frame(&mut v);
    assert_eq!(
        Ok(ITMFrame::Globaltimestamp {
            has_wrapped: false,
            ts: 0x810608084
        }),
        g,
        "Illegal length frame"
    );

    let g = i.get_frame(&mut v);
    assert_eq!(
        Ok(ITMFrame::Globaltimestamp {
            has_wrapped: false,
            ts: 0x1C0810608084
        }),
        g,
        "64 bit frame"
    );
}

#[test]
fn test_instrumentation_source() {
    let mut i = ITMDecoder::new();
    let ip = vec![
        0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // Sync
        0x01, 0x22, // Simple software source packet
        0x93, 0x11, 0x22, 0x33, 0x44, // 4 Bytes
        0xF2, 0x99, 0x12, // 2 Bytes
    ];
    let mut v = ip.iter();
    let g = i.get_frame(&mut v);
    assert_eq!(Ok(ITMFrame::Sync { count: 1 }), g);

    let g = i.get_frame(&mut v);
    assert_eq!(
        Ok(ITMFrame::Instrumentation {
            addr: 0,
            data: 0x22,
            len: 1,
        }),
        g,
        "Single byte to port 0"
    );

    let g = i.get_frame(&mut v);
    assert_eq!(
        Ok(ITMFrame::Instrumentation {
            addr: 18,
            data: 0x44332211,
            len: 4,
        }),
        g,
        "Four bytes to port 18"
    );

    let g = i.get_frame(&mut v);
    assert_eq!(
        Ok(ITMFrame::Instrumentation {
            addr: 30,
            data: 0x1299,
            len: 2,
        }),
        g,
        "Two bytes to port 30"
    );
}

#[test]
fn test_sw_page_no() {
    let mut i = ITMDecoder::new();
    let ip = vec![
        0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // Sync
        0x1C, // Set page 1 (Nos 32..63)
        0x01, 0x22, // Simple software source packet
        0x7C, // Set page 7 (Nos 224..255)
        0x93, 0x11, 0x22, 0x33, 0x44, // 4 Bytes
    ];
    let mut v = ip.iter();
    let g = i.get_frame(&mut v);
    assert_eq!(Ok(ITMFrame::Sync { count: 1 }), g);

    let g = i.get_frame(&mut v);
    assert_eq!(
        Ok(ITMFrame::Instrumentation {
            addr: 32,
            data: 0x22,
            len: 1,
        }),
        g,
        "Single byte to port 0"
    );

    let g = i.get_frame(&mut v);
    assert_eq!(
        Ok(ITMFrame::Instrumentation {
            addr: 224 + 18,
            data: 0x44332211,
            len: 4,
        }),
        g,
        "Four bytes to port 242"
    );
}

#[test]
fn test_xtn() {
    let mut i = ITMDecoder::new();
    let ip = vec![
        0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // Sync
        0x88, 0x22, // Single byte extension packet
        0xa8, 0x93, 0x82, 0x23, // Three byte packet
        0xac, 0x93, 0x82, 0x23, // Three byte packet with source set
    ];
    let mut v = ip.iter();
    let g = i.get_frame(&mut v);
    assert_eq!(Ok(ITMFrame::Sync { count: 1 }), g);

    let g = i.get_frame(&mut v);
    assert_eq!(
        Ok(ITMFrame::Xtn {
            source: false,
            len: 1,
            ex: 0x110
        }),
        g,
        "Single byte to port 0"
    );

    let g = i.get_frame(&mut v);
    assert_eq!(
        Ok(ITMFrame::Xtn {
            source: false,
            len: 3,
            ex: 0x46089a
        }),
        g,
        "Three bytes to port 2"
    );

    let g = i.get_frame(&mut v);
    assert_eq!(
        Ok(ITMFrame::Xtn {
            source: true,
            len: 3,
            ex: 0x46089a
        }),
        g,
        "Three bytes to port 2 with source"
    );
}

#[test]
fn test_event() {
    let mut i = ITMDecoder::new();
    let ip = vec![
        0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // Sync
        0x05, 0x01, // CPI Wrap Event
        0x05, 0x02, // Exc Wrap Event
        0x05, 0x04, // Sleep Wrap Event
        0x05, 0x08, // LSU Wrap Event
        0x05, 0x10, // FOLD Wrap Event
        0x05, 0x20, // POST Wrap Event
        0x05, 0x00, // No Wrap
        0x05, 0x3F, // All wrap
    ];
    let mut v = ip.iter();
    let g = i.get_frame(&mut v);
    assert_eq!(Ok(ITMFrame::Sync { count: 1 }), g);

    let g = i.get_frame(&mut v);
    assert_eq!(
        Ok(ITMFrame::EventC {
            cpicnt_wrapped: true,
            exccnt_wrapped: false,
            sleepcnt_wrapped: false,
            lsucnt_wrapped: false,
            foldcnt_wrapped: false,
            postcnt_wrapped: false,
        }),
        g,
        "CPI Rollover"
    );

    let g = i.get_frame(&mut v);
    assert_eq!(
        Ok(ITMFrame::EventC {
            cpicnt_wrapped: false,
            exccnt_wrapped: true,
            sleepcnt_wrapped: false,
            lsucnt_wrapped: false,
            foldcnt_wrapped: false,
            postcnt_wrapped: false,
        }),
        g,
        "EXC Rollover"
    );

    let g = i.get_frame(&mut v);
    assert_eq!(
        Ok(ITMFrame::EventC {
            cpicnt_wrapped: false,
            exccnt_wrapped: false,
            sleepcnt_wrapped: true,
            lsucnt_wrapped: false,
            foldcnt_wrapped: false,
            postcnt_wrapped: false,
        }),
        g,
        "SLEEP Rollover"
    );

    let g = i.get_frame(&mut v);
    assert_eq!(
        Ok(ITMFrame::EventC {
            cpicnt_wrapped: false,
            exccnt_wrapped: false,
            sleepcnt_wrapped: false,
            lsucnt_wrapped: true,
            foldcnt_wrapped: false,
            postcnt_wrapped: false,
        }),
        g,
        "LSU Rollover"
    );

    let g = i.get_frame(&mut v);
    assert_eq!(
        Ok(ITMFrame::EventC {
            cpicnt_wrapped: false,
            exccnt_wrapped: false,
            sleepcnt_wrapped: false,
            lsucnt_wrapped: false,
            foldcnt_wrapped: true,
            postcnt_wrapped: false,
        }),
        g,
        "FOLD Rollover"
    );

    let g = i.get_frame(&mut v);
    assert_eq!(
        Ok(ITMFrame::EventC {
            cpicnt_wrapped: false,
            exccnt_wrapped: false,
            sleepcnt_wrapped: false,
            lsucnt_wrapped: false,
            foldcnt_wrapped: false,
            postcnt_wrapped: true,
        }),
        g,
        "POST Rollover"
    );

    let g = i.get_frame(&mut v);
    assert_eq!(
        Ok(ITMFrame::EventC {
            cpicnt_wrapped: false,
            exccnt_wrapped: false,
            sleepcnt_wrapped: false,
            lsucnt_wrapped: false,
            foldcnt_wrapped: false,
            postcnt_wrapped: false,
        }),
        g,
        "No Rollover"
    );

    let g = i.get_frame(&mut v);
    assert_eq!(
        Ok(ITMFrame::EventC {
            cpicnt_wrapped: true,
            exccnt_wrapped: true,
            sleepcnt_wrapped: true,
            lsucnt_wrapped: true,
            foldcnt_wrapped: true,
            postcnt_wrapped: true,
        }),
        g,
        "ALL Rollover"
    );
}

#[test]
fn test_pmuovf() {
    let mut i = ITMDecoder::new();
    let ip = vec![
        0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // Sync
        0x1d, 0x42, // PMU Overflow
    ];
    let mut v = ip.iter();
    let g = i.get_frame(&mut v);
    assert_eq!(Ok(ITMFrame::Sync { count: 1 }), g);

    let g = i.get_frame(&mut v);
    assert_eq!(Ok(ITMFrame::PMUOverflow { ovf: 0x42 }), g);
}

#[test]
fn test_exception() {
    let mut i = ITMDecoder::new();
    let ip = vec![
        0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // Sync
        0x0e, 0x42, 0x11, // Exception 0x142, Entry
        0x0e, 0x99, 0x20, // Exception 0x99, Exit
        0x0e, 0x01, 0x31, // Exception 0x101, Resume
    ];

    let mut v = ip.iter();
    let g = i.get_frame(&mut v);
    assert_eq!(Ok(ITMFrame::Sync { count: 1 }), g);

    let g = i.get_frame(&mut v);
    assert_eq!(
        Ok(ITMFrame::Exception {
            no: 0x142,
            event: ExceptionEvent::Entry
        }),
        g
    );

    let g = i.get_frame(&mut v);
    assert_eq!(
        Ok(ITMFrame::Exception {
            no: 0x99,
            event: ExceptionEvent::Exit
        }),
        g
    );
    let g = i.get_frame(&mut v);
    assert_eq!(
        Ok(ITMFrame::Exception {
            no: 0x101,
            event: ExceptionEvent::Returned
        }),
        g
    )
}

#[test]
fn test_datatrace_match() {
    let mut i = ITMDecoder::new();
    let ip = vec![
        0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // Sync
        0x45, 0x01, 0x75, 0x01,
    ];

    let mut v = ip.iter();
    let g = i.get_frame(&mut v);
    assert_eq!(Ok(ITMFrame::Sync { count: 1 }), g);

    let g = i.get_frame(&mut v);
    assert_eq!(Ok(ITMFrame::DataTraceMatch { index: 0 }), g);

    let g = i.get_frame(&mut v);
    assert_eq!(Ok(ITMFrame::DataTraceMatch { index: 3 }), g);
}

#[test]
fn test_datatrace_pc() {
    let mut i = ITMDecoder::new();
    let ip = vec![
        0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // Sync
        0x45, 0x40, // Short PC packet
        0x76, 0x02, 0x43, // Medium PC packet
        0x77, 0x02, 0x04, 0x08, 0x10, // Long PC packet
    ];

    let mut v = ip.iter();
    let g = i.get_frame(&mut v);
    assert_eq!(Ok(ITMFrame::Sync { count: 1 }), g);

    let g = i.get_frame(&mut v);
    assert_eq!(
        Ok(ITMFrame::DataTracePC {
            index: 0,
            addr: 0x40,
            len: 1
        }),
        g
    );

    let g = i.get_frame(&mut v);
    assert_eq!(
        Ok(ITMFrame::DataTracePC {
            index: 3,
            addr: 0x4302,
            len: 2
        }),
        g
    );

    let g = i.get_frame(&mut v);
    assert_eq!(
        Ok(ITMFrame::DataTracePC {
            index: 3,
            addr: 0x10080402,
            len: 4
        }),
        g
    );
}

#[test]
fn test_datatrace_addr() {
    let mut i = ITMDecoder::new();
    let ip = vec![
        0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // Sync
        0x4d, 0x40, // Short DataAddr packet
        0x7e, 0x02, 0x43, // Medium DataAddr packet
        0x7f, 0x02, 0x04, 0x08, 0x10, // Long DataAddr packet
    ];

    let mut v = ip.iter();
    let g = i.get_frame(&mut v);
    assert_eq!(Ok(ITMFrame::Sync { count: 1 }), g);

    let g = i.get_frame(&mut v);
    assert_eq!(
        Ok(ITMFrame::DataTraceAddr {
            index: 0,
            daddr: 0x40,
            len: 1
        }),
        g
    );

    let g = i.get_frame(&mut v);
    assert_eq!(
        Ok(ITMFrame::DataTraceAddr {
            index: 3,
            daddr: 0x4302,
            len: 2
        }),
        g
    );

    let g = i.get_frame(&mut v);
    assert_eq!(
        Ok(ITMFrame::DataTraceAddr {
            index: 3,
            daddr: 0x10080402,
            len: 4
        }),
        g
    );
}

#[test]
fn test_datatrace_value() {
    let mut i = ITMDecoder::new();
    let ip = vec![
        0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // Sync
        0x8d, 0x40, // Short, write, len=1, idx=0
        0x96, 0x02, 0x43, // Medium
        0xaf, 0x02, 0x04, 0x08, 0x10, // Long
    ];

    let mut v = ip.iter();
    let g = i.get_frame(&mut v);
    assert_eq!(Ok(ITMFrame::Sync { count: 1 }), g);

    let g = i.get_frame(&mut v);
    assert_eq!(
        Ok(ITMFrame::DataTraceValue {
            index: 0,
            addr: 0x40,
            len: 1,
            wnr: true
        }),
        g
    );

    let g = i.get_frame(&mut v);
    assert_eq!(
        Ok(ITMFrame::DataTraceValue {
            index: 1,
            addr: 0x4302,
            len: 2,
            wnr: false
        }),
        g
    );
    let g = i.get_frame(&mut v);
    assert_eq!(
        Ok(ITMFrame::DataTraceValue {
            index: 2,
            addr: 0x10080402,
            len: 4,
            wnr: true
        }),
        g
    );
}
#[test]
fn test_trace_pc() {
    let mut i = ITMDecoder::new();
    let ip = vec![
        0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // Sync
        0x15, 0x00, // Sleeping, not prohib
        0x15, 0xff, // Sleeping, prohib
        0x17, 0x01, 0x02, 0x03, 0x04, // Sample address
        0x17, 0xfa, 0xfb, 0xfc, 0xfd, // Sample address
    ];

    let mut v = ip.iter();
    let g = i.get_frame(&mut v);
    assert_eq!(Ok(ITMFrame::Sync { count: 1 }), g);

    let g = i.get_frame(&mut v);
    assert_eq!(Ok(ITMFrame::PCSleep { prohibited: false }), g);

    let g = i.get_frame(&mut v);
    assert_eq!(Ok(ITMFrame::PCSleep { prohibited: true }), g);

    let g = i.get_frame(&mut v);
    assert_eq!(Ok(ITMFrame::PCSample { addr: 0x04030201 }), g);

    let g = i.get_frame(&mut v);
    assert_eq!(Ok(ITMFrame::PCSample { addr: 0xfdfcfbfa }), g);
}

#[test]
fn test_futz() {
    let mut i = ITMDecoder::new();
    let ip = vec![
        0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // Sync
    ];

    let mut v = ip.iter();
    let _ = i.get_frame(&mut v);
    let randomv: Vec<u8> = (1..20000).map(|_| fastrand::u8(0..255)).collect();

    let mut r = randomv.as_slice().iter();
    loop {
        let g = i.get_frame(&mut r);
        if g.is_err() {
            break;
        }
    }
    let mut v = ip.iter().peekable();
    let mut g = i.get_frame(&mut v);
    println!("Last Frame:{:?}", g);

    /* See if there was anything left, so this wasn't the end sync */
    if v.peek().is_some() {
        g = i.get_frame(&mut v);
        println!("Very Last Frame:{:?}", g);
    }

    /* It is _possible_ there would be a sync in the regular flow, but */
    /* given that its 6 bytes long the chance is 1 in (1/256)^6 */
    assert_eq!(Ok(ITMFrame::Sync { count: 2 }), g);
}
