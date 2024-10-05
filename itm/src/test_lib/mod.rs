#[cfg(test)]
use super::*;

#[test]
fn test_sync() {
    let mut i = ITMDecoder::new();
    let ip = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x80];

    let g = i.get_frame(&mut ip.iter());
    assert_eq!(Ok(ITMFrame::Newsync { count: 1 }), g);
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
    assert_eq!(Ok(ITMFrame::Newsync { count: 1 }), g);
    let g = i.get_frame(&mut v);
    assert_eq!(Ok(ITMFrame::Overflow { count: 1 }), g);
}

#[test]
fn test_local_ts_2() {
    let mut i = ITMDecoder::new();
    let ip = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x30];
    let mut v = ip.iter();

    let g = i.get_frame(&mut v);
    assert_eq!(Ok(ITMFrame::Newsync { count: 1 }), g);
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
        0xA0, 0x85, 0x82, 0x01, // TS Type 1 value 0x4105
        0xA0, 0x85, 0x85, 0x85, 0x85, 0x85, 0x00, // Type 1 with extra byte
    ];
    let mut v = ip.iter();

    let g = i.get_frame(&mut v);
    assert_eq!(Ok(ITMFrame::Newsync { count: 1 }), g);
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
            ttype: TSType::TSDelayed,
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
    assert_eq!(Ok(ITMFrame::Newsync { count: 1 }), g);

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
    assert_eq!(Ok(ITMFrame::Newsync { count: 1 }), g);

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
fn test_sw_source() {
    let mut i = ITMDecoder::new();
    let ip = vec![
        0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // Sync
        0x01, 0x22, // Simple software source packet
        0x93, 0x11, 0x22, 0x33, 0x44, // 4 Bytes
        0xF2, 0x99, 0x12, // 2 Bytes
    ];
    let mut v = ip.iter();
    let g = i.get_frame(&mut v);
    assert_eq!(Ok(ITMFrame::Newsync { count: 1 }), g);

    let g = i.get_frame(&mut v);
    assert_eq!(
        Ok(ITMFrame::Sw {
            addr: 0,
            data: 0x22
        }),
        g,
        "Single byte to port 0"
    );

    let g = i.get_frame(&mut v);
    assert_eq!(
        Ok(ITMFrame::Sw {
            addr: 18,
            data: 0x44332211
        }),
        g,
        "Four bytes to port 18"
    );

    let g = i.get_frame(&mut v);
    assert_eq!(
        Ok(ITMFrame::Sw {
            addr: 30,
            data: 0x1299
        }),
        g,
        "Two bytes to port 30"
    );
}

#[test]
fn test_hw_source() {
    let mut i = ITMDecoder::new();
    let ip = vec![
        0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // Sync
        0x05, 0x22, // Simple hardware source packet
        0x97, 0x11, 0x22, 0x33, 0x44, // 4 Bytes
        0xF6, 0x99, 0x12, // 2 Bytes
    ];
    let mut v = ip.iter();
    let g = i.get_frame(&mut v);
    assert_eq!(Ok(ITMFrame::Newsync { count: 1 }), g);

    let g = i.get_frame(&mut v);
    assert_eq!(
        Ok(ITMFrame::Hw {
            disc: 0,
            data: 0x22
        }),
        g,
        "Single byte to port 0"
    );

    let g = i.get_frame(&mut v);
    assert_eq!(
        Ok(ITMFrame::Hw {
            disc: 18,
            data: 0x44332211
        }),
        g,
        "Four bytes to port 18"
    );

    let g = i.get_frame(&mut v);
    assert_eq!(
        Ok(ITMFrame::Hw {
            disc: 30,
            data: 0x1299
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
    assert_eq!(Ok(ITMFrame::Newsync { count: 1 }), g);

    let g = i.get_frame(&mut v);
    assert_eq!(
        Ok(ITMFrame::Sw {
            addr: 32,
            data: 0x22
        }),
        g,
        "Single byte to port 0"
    );

    let g = i.get_frame(&mut v);
    assert_eq!(
        Ok(ITMFrame::Sw {
            addr: 224 + 18,
            data: 0x44332211
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
    assert_eq!(Ok(ITMFrame::Newsync { count: 1 }), g);

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
