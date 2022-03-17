mod utils;
mod sha256;

use wasm_bindgen::prelude::*;
use sha256::SHA256;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;


#[wasm_bindgen]
pub fn get_hash(text:&str) -> String {
    let mut sha = SHA256::new();
    return sha.generate_hash(text);
}
