use sha2::Sha512;
use rand_core::{RngCore, OsRng};
use std::collections::HashSet;
use curve25519_dalek::scalar::Scalar;
use ff_zeroize::Field;
use ff_zeroize::PrimeField;
use pairing_plus::Engine;
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
    pub fn pair_server_punch() { //TODO (this should take a generic type to apply for both G1 and G2)
    
    }
    
    /*
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
    */
    
	//check that the punch card is valid with num_punches
	//check that the punch card secret is new
    pub fn pair_server_verify(&mut self, compressed_card1: &mut Vec<u8>, compressed_card2: &mut Vec<u8>, secret1: [u8; 32], secret2: [u8; 32], num_punches: u32) -> bool { //TODO
    
        let csuite1 = [0u8; 4];
        let csuite2 = [1u8, 0u8, 0u8, 0u8];
    
        //compute the values and pairings you would expect
        let num_punches = self.secret.pow([num_punches as u64]);
        let mut expcard_1_1 = <G1 as HashToCurve<ExpandMsgXmd<Sha512>>>::hash_to_curve(&secret1, &csuite1);
        let expcard_1_2 = <G2 as HashToCurve<ExpandMsgXmd<Sha512>>>::hash_to_curve(&secret1, &csuite2);
        let mut expcard_2_1 = <G1 as HashToCurve<ExpandMsgXmd<Sha512>>>::hash_to_curve(&secret2, &csuite1);
        let expcard_2_2 = <G2 as HashToCurve<ExpandMsgXmd<Sha512>>>::hash_to_curve(&secret2, &csuite2);
        
        expcard_1_1.mul_assign(num_punches);
        expcard_2_1.mul_assign(num_punches);
        
        let exp_pairing_1 = Bls12::pairing(expcard_1_1, expcard_2_2);
        let exp_pairing_2 = Bls12::pairing(expcard_2_1, expcard_1_2);
        
        
        //deserialize the cards given as parameters
        let card1 = Fq12::deserialize(&mut &compressed_card1[..], true).expect("couldn't deserialize");
        let card2 = Fq12::deserialize(&mut &compressed_card2[..], true).expect("couldn't deserialize");
        
        //check that the card is valid (real and expected values match)
        if card1 == exp_pairing_1 && card2 == exp_pairing_2 {
            //check that the secrets are new
            //returns true if this was not in the set
            self.used_cards.insert(secret1) && self.used_cards.insert(secret2)
        } else {
            false
        }
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
    
        //giving the same secret to both cards
        //different domain separators
        let mut card_secret = [0u8; 32];
		OsRng.fill_bytes(&mut card_secret);
        let csuite1 = [0u8; 4];
        let csuite2 = [1u8, 0u8, 0u8, 0u8];
        
        let (card1, client1) = Self::card_part_setup::<G1>(card_secret, csuite1);
        let (card2, client2) = Self::card_part_setup::<G2>(card_secret, csuite2);
        
        let new_card = PairPunchCard {
            g1card: client1,
            g2card: client2,
        };
        
        (card1, card2, new_card)
        
    }

	//create a new punchcard part
	//punch card is already masked after this function
	fn card_part_setup<T>(card_secret: [u8; 32], csuite: [u8; 4]) -> (Vec<u8>, PairPunchCardPart::<T>) 
        where T: CurveProjective + SerDes + HashToCurve<ExpandMsgXmd<Sha512>>,
              <<T as CurveProjective>::Scalar as PrimeField>::Repr: std::convert::From<Fr>
    {
		
        let last_mask = Fr::random(&mut OsRng);
        
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
	
	/*
			self.punch_card = self.punch_card * self.last_mask.invert();
		
		(self.card_secret, self.punch_card.compress())
	*/
	
	//unmask the punch card, use pairings to merge, and return relevant contents
	pub fn pair_unmask_redeem(&mut self, mut other: PairPunchCard) -> ([u8; 32], [u8; 32], Vec<u8>, Vec<u8>) {
        
        //unmask the punch cards
        self.g1card.punch_card.mul_assign(self.g1card.last_mask.inverse().expect("couldn't invert!"));
        self.g2card.punch_card.mul_assign(self.g2card.last_mask.inverse().expect("couldn't invert!"));
        other.g1card.punch_card.mul_assign(other.g1card.last_mask.inverse().expect("couldn't invert!"));
        other.g2card.punch_card.mul_assign(other.g2card.last_mask.inverse().expect("couldn't invert!"));

        
        //pairings of the parts of the punch cards
        let pairing1 = Bls12::pairing(self.g1card.punch_card, other.g2card.punch_card);
        let pairing2 = Bls12::pairing(other.g1card.punch_card, self.g2card.punch_card);
	
        //serialize pairing outputs
        let mut pairing1_compressed = Vec::<u8>::new();
        let mut pairing2_compressed = Vec::<u8>::new();
        pairing1.serialize(&mut pairing1_compressed, true).expect("couldn't serialize");
        pairing2.serialize(&mut pairing2_compressed, true).expect("couldn't serialize");

        
        //return the secrets from the punch cards and the results of the pairings
        //since both parts of each card use the same secret, we only need one from each
        (self.g1card.card_secret, other.g1card.card_secret, pairing1_compressed, pairing2_compressed)
	}
	
	pub fn pair_get_count(&self) -> u32 {
		if self.g1card.count != self.g2card.count {panic!("card counts misaligned!")}
		
		self.g1card.count
	}

}
