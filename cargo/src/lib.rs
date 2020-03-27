mod crypto;

use std::os::raw::{c_char};
use std::ffi::{CString};
use crypto::ServerData;
use crypto::PunchCard;
use std::time::{Duration, Instant};

#[no_mangle]
pub extern fn benchmarkCode() -> *mut c_char {
    //call and time crypto code here
    //write performance numbers to the string that gets returned
    
    //set up server
    let (pub_secret, mut server) = ServerData::server_setup();
    
    //fill up database of used cards
    server.cheat_setup_db(100);
    
    println!("number of used punchcards: {}", server.count_cards());
    
    //create new punchcard
    let (mut current_card, mut client) = PunchCard::card_setup();
    
    //punch the card 10 times
    for _ in 0..10 {
    	
    	//server punches
    	let (new_card, proof) = server.server_punch(current_card);
    	
    	//client verifies punch, prepares for next punch	
    	let res = client.verify_remask(new_card, pub_secret, proof);
    	current_card = res.0;
    	let punch_success = res.1;
    
    	println!("punch succeeded? {}", punch_success);
    	println!("punch count: {}", client.get_count());	
    	//println!("card data: {:?}", client);
    }
    
    //client redeems card
    let (card_secret, final_card) = client.unmask_redeem();
    
    
    //server verifies card
    let redeem_success = server.server_verify(final_card, card_secret);
    
    println!("card redemption succeeded? {}", redeem_success);
    println!("number of used punchcards: {}", server.count_cards());

    CString::new("Hello".to_owned()).unwrap().into_raw()
}

/// Expose the JNI interface for android below
#[cfg(target_os="android")]
#[allow(non_snake_case)]
pub mod android {
    extern crate jni;

    use super::*;
    use self::jni::JNIEnv;
    use self::jni::objects::{JClass};
    use self::jni::sys::{jstring};

    #[no_mangle]
    pub unsafe extern fn Java_com_example_punchcard_RustPunchCard_benchmarkCode(env: JNIEnv, _: JClass) -> jstring {
        // Our Java companion code might pass-in "world" as a string, hence the name.
        let world = benchmarkCode();
        // Retake pointer so that we can use it below and allow memory to be freed when it goes out of scope.
        let world_ptr = CString::from_raw(world);
        let output = env.new_string(world_ptr.to_str().unwrap()).expect("Couldn't create java string!");

        output.into_inner()
    }
}

