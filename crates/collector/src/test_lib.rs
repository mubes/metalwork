#[cfg(test)]
use super::*;

#[test]
fn url_test1() {
    let r = Collect::calculate_url(&None, &None, &None);
    assert_eq!(r, "oflow://localhost:3402")
}

#[test]
fn url_test2() {
    let r = Collect::calculate_url(&None, &None, &Some("itm".to_string()));
    assert_eq!(r, "itm://localhost:3402")
}

#[test]
fn url_test3() {
    let r = Collect::calculate_url(&None, &None, &Some("abc".to_string()));
    assert_eq!(r, "abc://localhost:3402")
}

#[test]
fn url_test4() {
    let r = Collect::calculate_url(&Some("isfile".to_string()), &None, &None);
    assert_eq!(r, "file://isfile")
}

#[test]
fn url_test5() {
    let r = Collect::calculate_url(&None,&Some("address".to_string()), &None);
    assert_eq!(r, "itm://address:3402")
}

#[test]
fn url_test6() {
    let r = Collect::calculate_url(&None,&Some("address:1234".to_string()), &None);
    assert_eq!(r, "itm://address:1234")
}

#[test]
fn url_test7() {
    let r = Collect::calculate_url(&None,&Some("address".to_string()), &Some("ttt".to_string()));
    assert_eq!(r, "ttt://address:3402")
}
