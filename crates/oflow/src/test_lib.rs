#[cfg(test)]
use super::*;

#[test]
fn decode_good_packet() {
    let ipvec = vec![27u8, 1, 2, 3, (256usize - (27 + 1 + 2 + 3)) as u8];

    let mut oflow = OFlow::new();
    let opvec_candidate = oflow.decode(ipvec).unwrap();
    assert_eq!(&[1u8, 2, 3], opvec_candidate.content());
    assert_eq!(&[1u8, 2, 3], &*opvec_candidate);
    assert_eq!(1, opvec_candidate[0]);
    assert_eq!(2, opvec_candidate[1]);
    assert_eq!(3, opvec_candidate[2]);
    assert_eq!(3, opvec_candidate.len());
}

#[test]
fn decode_bad_packet() {
    let ipvec = vec![27u8, 1, 2, 3, 27 + 1 + 2 + 3 + 1];
    let mut oflow = OFlow::new();
    let opvec_candidate = oflow.decode(ipvec);
    assert_eq!(opvec_candidate, Err(OFlowError::BadChecksum));
}

#[test]
fn decode_short_packet() {
    let ipvec = vec![27u8, 1];
    let mut oflow = OFlow::new();
    let opvec_candidate = oflow.decode(ipvec);
    assert_eq!(opvec_candidate, Err(OFlowError::ShortData));
}

#[test]
fn decode_overlong_packet() {
    let ipvec = vec![27u8; 8195];
    let mut oflow = OFlow::new();
    let opvec_candidate = oflow.decode(ipvec);
    assert_eq!(opvec_candidate, Err(OFlowError::Overlong));
}

#[test]
fn encode_good_packet() {
    let opvec = vec![27u8, 1, 2, 3, (256usize - (27 + 1 + 2 + 3)) as u8];

    let mut oflow = OFlow::new();
    let ipvec_candidate = oflow.encode_to_vec(27, vec![1u8, 2, 3]).unwrap();
    assert_eq!(opvec, ipvec_candidate);
}

#[test]
fn encode_zero_packet() {
    let mut oflow = OFlow::new();
    let ipvec_candidate = oflow.encode_to_vec(27, vec![0u8; 0]);
    assert_eq!(ipvec_candidate, Err(OFlowError::ZeroLength));
}

#[test]
fn create_macro_frame() {
    let v = vec![1u8, 2, 3];
    let opvec = vec![
        vec![27u8],
        vec![1u8, 2, 3],
        vec![(256usize - (27 + 1 + 2 + 3)) as u8],
    ];
    let d = crate::oflow_frame!(27u8, &v);
    assert_eq!(opvec, d);
}
