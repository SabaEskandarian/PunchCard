use sha2::Sha512;
use rand_core::{RngCore, OsRng};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use std::collections::HashSet;

//TODO: maybe store g^secret in the struct too?
pub struct ServerData {
	secret: Scalar,
	used_cards: HashSet<[u8; 32]>,
}

pub struct PunchCard {
	card_secret: [u8; 32], 
	punch_card: RistrettoPoint,
	last_mask: Scalar,
	count: i32,
}

pub struct Proof {
	placeholder: i32,
}


impl ServerData {

	//set up the server secret and redeemed card db
	//TODO: also raise known base to the secret scalar, see above
	pub fn server_setup() -> ServerData {
	
		let secret = Scalar::random(&mut OsRng);
		let used_cards = HashSet::new();
		let new_server = ServerData {
			secret,
			used_cards,
		};
		
		new_server
	}
	
	//punch card by multiplying by secret
	//prove that this was done honestly
	pub fn server_punch(&self, card: &mut RistrettoPoint) -> Proof {
		
		*card = *card * self.secret;
		
		//TODO generate proof
		
		Proof{
			placeholder: 0,
		}
	}
	
	//check that 
	pub fn server_verify(&mut self, card: RistrettoPoint, card_secret: [u8; 32]) -> bool {
		//TODO
		true
	}
}


impl PunchCard {

	//create a new punchcard
	//punch card is already masked after this function
	pub fn card_setup() -> PunchCard {
		
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
		
		new_punch_card
	}
	
	//verify proof from the server
	//if accepted, unmask punchcard, remask with new mask, increment count
	pub fn verify_remask(&mut self, card: RistrettoPoint, proof: Proof) -> bool {
		//TODO verify proof
		
		self.punch_card = card * self.last_mask.invert();
		self.last_mask = Scalar::random(&mut OsRng);
		self.punch_card = self.punch_card * self.last_mask;
		
		self.count += 1;
		true
	}
	
	//unmask the punch card and return its relevant contents
	pub fn unmask_redeem(&mut self) -> ([u8; 32], RistrettoPoint) {
	
		self.punch_card = self.punch_card * self.last_mask.invert();
		self.count = -1; //mark this card as spent
		(self.card_secret, self.punch_card)
	}
	
	pub fn get_count(&self) -> i32 {
		self.count
	}
	
	pub fn is_spent(&self) -> bool {
		if self.count == -1 {
			true
		} else {
			false
		}
	}
}

