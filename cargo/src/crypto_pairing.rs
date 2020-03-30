use sha2::Sha512;
use rand_core::{RngCore, OsRng};
use std::collections::HashSet;
use curve25519_dalek::scalar::Scalar;
use ff_zeroize::Field;
use ff_zeroize::PrimeField;
use pairing_plus::hash_to_field::ExpandMsgXmd;
use pairing_plus::CurveProjective;
use pairing_plus::serdes::SerDes;
use pairing_plus::hash_to_curve::HashToCurve;
use pairing_plus::bls12_381::Bls12;
use pairing_plus::bls12_381::Fr;
use pairing_plus::bls12_381::G1;
use pairing_plus::bls12_381::G2;
use pairing_plus::bls12_381::Fq12;


//Making a second module with all the same functions used in crypto.rs 
//but for the version that uses pairings to merge 2 cards
//Not the right way to do this, but it will do for now

#[derive(Debug)]
pub struct PairServerData {
	secret: Fr,
	used_cards: HashSet<[u8; 32]>,
	pub_secret_g1: Vec<u8>, //compressed form of g1^secret
	pub_secret_g2: Vec<u8>, //compressed form of g2^secret
}

//this holds the two parts of one punch card
#[derive(Debug)]
pub struct PairPunchCard {
    g1card: PairPunchCardPart<G1>,
    g2card: PairPunchCardPart<G2>,
}

//This is one punch card part
#[derive(Debug)]
pub struct PairPunchCardPart<T> {
	card_secret: [u8; 32], 
	punch_card: T,
	last_mask: Fr,
	count: u32,
}

//we'll use two proofs, one for the exponentiation in each group
//notation from Figure 19.7 in Boneh-Shoup textbook v0.5
#[derive(Debug)]
pub struct PairProof {
	v_t: Vec<u8>,//compressed points in G1 or G2 (depending on proof)
	w_t: Vec<u8>,
	beta_z: Fr,
}

impl PairServerData {

	//set up the server secret and redeemed card db
    pub fn pair_server_setup() -> (Vec<u8>, Vec<u8>, PairServerData){
        let secret = Fr::random(&mut OsRng);
		let used_cards = HashSet::new();
        let mut pub_secret_g1 = Vec::<u8>::new();
        let mut pub_secret_g2 = Vec::<u8>::new();
        let mut temp = G1::one();
        temp.mul_assign(secret);
        temp.serialize(&mut pub_secret_g1, true).expect("couldn't serialize");
        let mut temp = G2::one();
        temp.mul_assign(secret);
        temp.serialize(&mut pub_secret_g2, true).expect("couldn't serialize");
        let new_server = PairServerData {
            secret,
            used_cards,
            pub_secret_g1: pub_secret_g1.clone(),
            pub_secret_g2: pub_secret_g2.clone(),
        };
        (pub_secret_g1, pub_secret_g2, new_server)
    }
    
    //punch card by multiplying by secret
	//prove that this was done honestly
    pub fn pair_server_punch() { //TODO
    
    }
    
	//check that the punch card is valid with num_punches
	//check that the punch card secret is new
    pub fn pair_server_verify() { //TODO
    
    }

	//preload the database of used cards with num entries
	pub fn pair_cheat_setup_db(&mut self, num:u32) {
		for i in 0..num {
            //this is weird, but it's a hack anyway
			let temp = Scalar::from(i).to_bytes();
			self.used_cards.insert(temp);
		}
	}

	pub fn pair_count_cards(&self) -> usize {
		self.used_cards.len()
	}

}

impl PairPunchCard {

    //new mergable punchcard
    pub fn card_setup() -> (Vec<u8>, Vec<u8>, PairPunchCard) {
        
        let (card1, client1) = Self::card_part_setup::<G1>();
        let (card2, client2) = Self::card_part_setup::<G2>();
        
        let new_card = PairPunchCard {
            g1card: client1,
            g2card: client2,
        };
        
        (card1, card2, new_card)
        
    }

	//create a new punchcard part
	//punch card is already masked after this function
	fn card_part_setup<T>() -> (Vec<u8>, PairPunchCardPart::<T>) 
        where T: CurveProjective + SerDes + HashToCurve<ExpandMsgXmd<Sha512>>,
              <<T as CurveProjective>::Scalar as PrimeField>::Repr: std::convert::From<Fr>
    {
        let mut card_secret = [0u8; 32];
		OsRng.fill_bytes(&mut card_secret);
		
        let last_mask = Fr::random(&mut OsRng);
        
        let csuite = [0u8; 4];
        
        let mut punch_card = <T as HashToCurve<ExpandMsgXmd<Sha512>>>::hash_to_curve(&card_secret, &csuite);
        punch_card.mul_assign(last_mask);
        
        let new_punch_card = PairPunchCardPart::<T> {
            card_secret,
            punch_card,
            last_mask,
            count: 0,
        };

        let mut card_compressed = Vec::<u8>::new();
        new_punch_card.punch_card.serialize(&mut card_compressed, true).expect("couldn't serialize");


        (card_compressed, new_punch_card)
		
	}
	
	//verify proof from the server
	//if accepted, unmask punchcard, remask with new mask, increment count
	//otherwise reuse old punchcard, same count
	pub fn verify_remask(&mut self) { //TODO

	}
	
	//unmask the punch card and return its relevant contents
	pub fn pair_unmask_redeem(&mut self) { //TODO
	
	}
	
	pub fn pair_get_count(&self) -> u32 {
		if self.g1card.count != self.g2card.count {panic!("card counts misaligned!")}
		
		self.g1card.count
	}

}
