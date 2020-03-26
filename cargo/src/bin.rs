mod lib; mod crypto;

use std::ffi::{CString};

fn main(){
    let world = lib::benchmarkCode();
    let world_ptr = unsafe { CString::from_raw(world) };
    let rust_string = world_ptr.to_str().unwrap();
    println!("{}", rust_string);
}

