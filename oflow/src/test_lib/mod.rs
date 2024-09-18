#[cfg(test)]
use super::*;

#[test]
fn decode_good_packet( ) {
    let ipvec = vec![ 27u8, 1, 2, 3, (256usize-(27+1+2+3)) as u8 ];
    
    let mut oflow = OFlow::new();
    let opvec_candidate = oflow.decode( ipvec ).unwrap();
    assert_eq!(&[1u8,2,3],opvec_candidate.content());
    assert_eq!(&[1u8,2,3],&*opvec_candidate);
    assert_eq!(1,opvec_candidate[0]);
    assert_eq!(2,opvec_candidate[1]);
    assert_eq!(3,opvec_candidate[2]);
    assert_eq!(3,opvec_candidate.len());
}

#[test]
fn decode_bad_packet( ) {
    let ipvec = vec![ 27u8, 1, 2, 3, 27+1+2+3+1 ];
    let mut oflow = OFlow::new();
    let opvec_candidate = oflow.decode( ipvec );
    assert_eq!(opvec_candidate,Err(OFlowError::BadChecksum));
}

#[test]
fn decode_short_packet( ) {
    let ipvec = vec![ 27u8, 1 ];
    let mut oflow = OFlow::new();
    let opvec_candidate = oflow.decode( ipvec );
    assert_eq!(opvec_candidate,Err(OFlowError::ShortData));
}

#[test]
fn decode_overlong_packet( ) {
    let ipvec = vec![ 27u8; 8195 ];
    let mut oflow = OFlow::new();
    let opvec_candidate = oflow.decode( ipvec );
    assert_eq!(opvec_candidate,Err(OFlowError::Overlong));
}
