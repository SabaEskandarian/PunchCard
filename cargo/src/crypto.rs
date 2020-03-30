use sha2::Sha512;
use rand_core::{RngCore, OsRng};
use curve25519_dalek::constants;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use std::collections::HashSet;

#[derive(Debug)]
pub struct ServerData {
	secret: Scalar,
	used_cards: HashSet<[u8; 32]>,
	pub_secret: CompressedRistretto,
}

#[derive(Debug)]
pub struct PunchCard {
	card_secret: [u8; 32], 
	punch_card: RistrettoPoint,
	last_mask: Scalar,
	count: u32,
}

//notation from Figure 19.7 in Boneh-Shoup textbook v0.5
#[derive(Debug)]
pub struct Proof {
	v_t: CompressedRistretto,
	w_t: CompressedRistretto,
	beta_z: [u8; 32],
}

fn scalar_exponentiate(base: Scalar, exp: u32) -> Scalar{
	if exp == 1 {
		base
	} else if exp % 2 == 1{
		base * scalar_exponentiate(base, exp - 1)
	} else {
		let val = scalar_exponentiate(base, exp/2);
		val * val
	}
}


impl ServerData {

	//set up the server secret and redeemed card db
	pub fn server_setup() -> (CompressedRistretto, ServerData) {
	
		let secret = Scalar::random(&mut OsRng);
		let used_cards = HashSet::new();
		let pub_secret = &secret * &constants::RISTRETTO_BASEPOINT_TABLE;
		let pub_secret = pub_secret.compress();
		let new_server = ServerData {
			secret,
			used_cards,
			pub_secret,
		};
		
		(pub_secret, new_server)
	}
	
	//punch card by multiplying by secret
	//prove that this was done honestly
	pub fn server_punch(&self, card: CompressedRistretto) -> (CompressedRistretto, Proof) {
	
		let card_dec = card.decompress().expect("couldn't decompress point in server_punch");
		let new_card_dec = card_dec * self.secret;
		let new_card = new_card_dec.compress();
		
		//generate Chaum-Pedersen proof
		//see Boneh Shoup textbook v0.5 Figure 19.7
		let beta_t = Scalar::random(&mut OsRng);
		let v_t = &beta_t * &constants::RISTRETTO_BASEPOINT_TABLE;
		let v_t_compress = v_t.compress();
		let w_t = card_dec * beta_t;
		let w_t_compress = w_t.compress();

		let mut hashinput: Vec<u8> = Vec::new();
		hashinput.extend_from_slice(&self.pub_secret.to_bytes());
		hashinput.extend_from_slice(&card.to_bytes());
		hashinput.extend_from_slice(&new_card.to_bytes());
		hashinput.extend_from_slice(&v_t_compress.to_bytes());
		hashinput.extend_from_slice(&w_t_compress.to_bytes());
		let hashinput_bytes: &[u8] = &hashinput;
		let chal = Scalar::hash_from_bytes::<Sha512>(hashinput_bytes);
		let beta_z = beta_t + self.secret * chal;
		
		let proof = Proof {
			v_t: v_t_compress,
			w_t: w_t_compress,
			beta_z: beta_z.to_bytes(),
		};
		
		(new_card, proof)
	}
	
	//check that the punch card is valid with num_punches
	//check that the punch card secret is new
	pub fn server_verify(&mut self, card: CompressedRistretto, card_secret: [u8; 32], num_punches: u32) -> bool {
		
		let num_punches = scalar_exponentiate(self.secret, num_punches);
		let expected_card = RistrettoPoint::hash_from_bytes::<Sha512>(&card_secret) * num_punches;
		
		
		if card == expected_card.compress() {
			//returns true if this was not in the set
			self.used_cards.insert(card_secret)
		} else {
			false
		}
	}
	
	pub fn count_cards(&self) -> usize {
		self.used_cards.len()
	}
	
	//preload the database of used cards with num entries
	pub fn cheat_setup_db(&mut self, num:u32) {
		for i in 0..num {
			let temp = Scalar::from(i).to_bytes();
			self.used_cards.insert(temp);
		}
	}
	
	pub fn lookup_test(&self, input: [u8; 32]) -> bool {
        self.used_cards.contains(&input)
	}
}


impl PunchCard {

	//create a new punchcard
	//punch card is already masked after this function
	pub fn card_setup() -> (CompressedRistretto, PunchCard) {
		
		let mut card_secret = [0u8; 32];
		OsRng.fill_bytes(&mut card_secret);
		
		let last_mask = Scalar::random(&mut OsRng);
		
		//the punch card is already masked at this point
		let punch_card = RistrettoPoint::hash_from_bytes::<Sha512>(&card_secret) * last_mask;
		
		let new_punch_card = PunchCard {
			card_secret,
			punch_card,
			last_mask,
			count: 0,
		};
		
		(new_punch_card.punch_card.compress(), new_punch_card)
	}
	
	//verify proof from the server
	//if accepted, unmask punchcard, remask with new mask, increment count
	//otherwise reuse old punchcard, same count
	pub fn verify_remask(&mut self, card: CompressedRistretto, pub_secret: CompressedRistretto,
						 proof: Proof) -> (CompressedRistretto, bool) {
		
		//verify Chaum-Pedersen proof
		//see Boneh Shoup textbook v0.5 Figure 19.7
		let mut hashinput: Vec<u8> = Vec::new();
		hashinput.extend_from_slice(&pub_secret.to_bytes());
		hashinput.extend_from_slice(&self.punch_card.compress().to_bytes());
		hashinput.extend_from_slice(&card.to_bytes());
		hashinput.extend_from_slice(&proof.v_t.to_bytes());
		hashinput.extend_from_slice(&proof.w_t.to_bytes());
		let hashinput_bytes: &[u8] = &hashinput;
		let chal = Scalar::hash_from_bytes::<Sha512>(hashinput_bytes);
		
		let gbz: RistrettoPoint = &Scalar::from_bytes_mod_order(proof.beta_z) * &constants::RISTRETTO_BASEPOINT_TABLE;
		let vtvc = proof.v_t.decompress().expect("couldn't decompress in verify_remask") 
					+ (pub_secret.decompress().expect("couldn't decompress pub_secret in verify_remask")
							 * chal);
		let ubz = self.punch_card * Scalar::from_bytes_mod_order(proof.beta_z);
		let wtwc = proof.w_t.decompress().expect("couldn't decompress in verify_remask") 
					+ (card.decompress().expect("couldn't decompress in verify_remask") * chal);
					

		let mut success = true;
		if gbz == vtvc && ubz == wtwc {
		//if true { //for debugging
			let unmasked_card = card.decompress()
				.expect("couldn't decompress point in verify_remask") 
				* self.last_mask.invert();
			self.last_mask = Scalar::random(&mut OsRng);
			self.punch_card = unmasked_card * self.last_mask;
			self.count += 1;
		} else {
			success = false;
		}

		(self.punch_card.compress(), success)
	}
	
	//unmask the punch card and return its relevant contents
	pub fn unmask_redeem(&mut self) -> ([u8; 32], CompressedRistretto) {
	
		self.punch_card = self.punch_card * self.last_mask.invert();
		
		(self.card_secret, self.punch_card.compress())
	}
	
	pub fn get_count(&self) -> u32 {
		self.count
	}
	
	pub fn exp_test(&self) -> RistrettoPoint{
        self.punch_card * self.last_mask
	}
}
