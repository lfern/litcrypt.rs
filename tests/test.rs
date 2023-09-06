#[macro_use]
extern crate litcrypt;

use_litcrypt!("MY-SECRET-SPELL");

#[test]
pub fn test_literal1() {
    assert_eq!(lc!("Kucing Garong"), "Kucing Garong");
}

#[test]
pub fn test_literal2() {
    assert_eq!(lc!("Very secret word"), "Very secret word");
}

#[test]
pub fn test_file() {
    assert_eq!(lc_text_file!("tests/text_file.json"), "{\"prueba\": 1}");
}

