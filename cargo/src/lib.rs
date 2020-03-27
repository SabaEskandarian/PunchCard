mod crypto;

use std::os::raw::{c_char};
use std::ffi::{CString};
use crypto::ServerData;
use crypto::PunchCard;
use std::time::Instant;

struct Times {
	num_iterations: u32,
	num_punches: u32,
	setup_rows: u32,
	server_setup: u128,
	client_setup: u128,
	server_punch: u128,
	client_punch: u128,
	client_redeem: u128,
	server_redeem: u128,
}

#[no_mangle]
pub extern fn benchmarkCode() -> *mut c_char {
    //call and time crypto code here
    //write performance numbers to the string that gets returned
    
    let mut times = Times {
    	num_iterations: 1000, //how many iterations to average over
    	num_punches: 10, //how many punches before a card is redeemed
    	setup_rows: 1000000, //change to larger number to test with used cards in db
    	server_setup: 0,
 		client_setup: 0,
		server_punch: 0,
		client_punch: 0,
		client_redeem: 0,
		server_redeem: 0,
    };
    
    for j in 0..times.num_iterations {
    
    	if j % 10 == 0 {println!("10 more done!\n");}
        
    	//set up server
    	let now = Instant::now();
    	let (pub_secret, mut server) = ServerData::server_setup();
    	let elapsed = now.elapsed().as_micros();
		//println!("time elapsed in server setup: {}", elapsed);
		times.server_setup += elapsed;
		
		//fill up database of used cards
		server.cheat_setup_db(times.setup_rows);
		
		//println!("number of used punchcards: {}", server.count_cards());
		
		//create new punchcard
		let now = Instant::now();
		let (mut current_card, mut client) = PunchCard::card_setup();
		let elapsed = now.elapsed().as_micros();
		//println!("time elapsed in punchcard setup: {}", elapsed);
		times.client_setup += elapsed;
		
		
		//punch the card
		for i in 0..times.num_punches {
			
			//server punches
			let now = Instant::now();
			let (new_card, proof) = server.server_punch(current_card);
			let elapsed = now.elapsed().as_micros();
			//println!("time elapsed in server punch: {}", elapsed);
			times.server_punch += elapsed;
		
			//client verifies punch, prepares for next punch	
			let now = Instant::now();
			let res = client.verify_remask(new_card, pub_secret, proof);
			current_card = res.0;
			let punch_success = res.1;
			let elapsed = now.elapsed().as_micros();
			if !punch_success {panic!("punch failed");}
			//println!("time elapsed in client punch: {}", elapsed);
			times.client_punch += elapsed;
		
			//println!("punch succeeded? {}", punch_success);
			//println!("punch count: {}", client.get_count());	
			if client.get_count() != i+1 {panic!("punch count wrong");}
		}

		
		//client redeems card
		let now = Instant::now();
		let (card_secret, final_card) = client.unmask_redeem();
		let elapsed = now.elapsed().as_micros();
		//println!("time elapsed in redemption (client): {}", elapsed);
		times.client_redeem += elapsed;
		
		//server verifies card
		let now = Instant::now();
		let redeem_success = server.server_verify(final_card, card_secret, times.num_punches);
		if !redeem_success {panic!("redemption failed");}
		let elapsed = now.elapsed().as_micros();
		//println!("time elapsed in redemption (server): {}", elapsed);
		times.server_redeem += elapsed;
		
		//println!("card redemption succeeded? {}", redeem_success);
		//println!("number of used punchcards: {}", server.count_cards());
		if server.count_cards() != (times.setup_rows + 1) as usize {panic!("wrong number of rows in card database");}
    }

	let perf_string = "Performance Results\nEach operation is repeated for ".to_owned()
						+ &times.num_iterations.to_string().to_owned() +
						&" iterations, except punches, which are done ".to_owned()
						+ &(times.num_iterations*times.num_punches).to_string().to_owned() + 
						&" times (".to_owned() 
						+ &times.num_punches.to_string().to_owned() + 
						&" punches per iteration). \nThe server database starts with ".to_owned()
						+ &times.setup_rows.to_string().to_owned() + 
						&" used punchcards in each iteration.".to_owned() +
						&" \nNumbers are cumulative over all runs, in microseconds.\n".to_owned() +
						&"Server setup: ".to_owned() + &times.server_setup.to_string().to_owned() + 
						&"\nClient setup: ".to_owned() + &times.client_setup.to_string().to_owned() + 
						&"\nServer punch: ".to_owned() + &times.server_punch.to_string().to_owned() + 
						&"\nClient punch: ".to_owned() + &times.client_punch.to_string().to_owned() + 
						&"\nClient redeem: ".to_owned() + &times.client_redeem.to_string().to_owned() + 
						&"\nServer redeem: ".to_owned() + &times.server_redeem.to_string().to_owned() + 
						&"\n".to_owned();

    CString::new(perf_string.to_owned()).unwrap().into_raw()
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

