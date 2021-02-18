//use sha2::Sha512;
use sha2::Sha256;
use rand_core::{RngCore, OsRng};
use std::collections::HashSet;
use curve25519_dalek::scalar::Scalar;
use ff_zeroize::Field;
use ff_zeroize::PrimeField;
use pairing_plus::Engine;
use pairing_plus::hash_to_field::ExpandMsgXmd;
use pairing_plus::CurveProjective;
use pairing_plus::serdes::SerDes;
use pairing_plus::hash_to_field::hash_to_field;
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
	pub pub_secret_g1: Vec<u8>, //compressed form of g1^secret
	pub pub_secret_g2: Vec<u8>, //compressed form of g2^secret
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
	beta_z: Vec<u8>,//compressed point in Fr
}

impl PairServerData {

	//set up the server secret and redeemed card 
    pub fn pair_server_setup() -> PairServerData{
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
            pub_secret_g1,
            pub_secret_g2,
        };
        new_server
    }
    
    pub fn pair_server_punch(&self, compressed_card1: &mut Vec<u8>, compressed_card2: &mut Vec<u8>) -> (Vec<u8>, Vec<u8>, PairProof, PairProof)  {
            let dst1 = [3u8, 0u8, 0u8, 0u8];
            let dst2 = [4u8, 0u8, 0u8, 0u8];
            
            let (card1, proof1) = self.pair_server_punch_part::<G1>(compressed_card1, dst1);
            let (card2, proof2) = self.pair_server_punch_part::<G2>(compressed_card2, dst2);
            
            (card1, card2, proof1, proof2)
    }
    
    //this will have to be called twice, once for each piece of the card
    //dst is also 3,0,0,0 the first time and 4,0,0,0 the second time
    //punch card by multiplying by secret
	//prove that this was done honestly
    fn pair_server_punch_part<T>(&self, compressed_card: &mut Vec<u8>, dst: [u8; 4]) -> (Vec<u8>, PairProof) 
        where T: CurveProjective + SerDes,
        <<T as pairing_plus::CurveProjective>::Scalar as ff_zeroize::PrimeField>::Repr: std::convert::From<pairing_plus::bls12_381::Fr>
    { 
    
        let pub_secret: &[u8];
        if dst[0] == 3 {
            pub_secret = &self.pub_secret_g1;
        } else if dst[0] == 4 {
            pub_secret = &self.pub_secret_g2;
        } else {
            panic!("bad dst");
        }
    
        //deserialize the card given as parameter
        let card = T::deserialize(&mut &compressed_card[..], true).expect("couldn't deserialize");
        let mut new_card = card.clone();
        new_card.mul_assign(self.secret);
        let mut new_compressed_card = Vec::<u8>::new();
        new_card.serialize(&mut new_compressed_card, true).expect("couldn't serialize");
        
        //generate Chaum-Pedersen proof
		//see Boneh Shoup textbook v0.5 Figure 19.7
        let beta_t = Fr::random(&mut OsRng);
        let mut v_t = T::one();
        v_t.mul_assign(beta_t);
        let mut v_t_compressed = Vec::<u8>::new();
        v_t.serialize(&mut v_t_compressed, true).expect("couldn't serialize");
        
        let mut w_t = card.clone();
        w_t.mul_assign(beta_t);
        let mut w_t_compressed = Vec::<u8>::new();
        w_t.serialize(&mut w_t_compressed, true).expect("couldn't serialize");
        
		let mut hashinput: Vec<u8> = Vec::new();
		hashinput.extend_from_slice(pub_secret);
		hashinput.extend_from_slice(&compressed_card);
		hashinput.extend_from_slice(&new_compressed_card);
		hashinput.extend_from_slice(&v_t_compressed);
		hashinput.extend_from_slice(&w_t_compressed);
		let hashinput_bytes: &[u8] = &hashinput;
		
		let chal = hash_to_field::<Fr, ExpandMsgXmd<Sha256>>(hashinput_bytes, &dst, 1)[0];
		
		let mut beta_z = chal;
		beta_z.mul_assign(&self.secret);
		beta_z.add_assign(&beta_t);
		
        let mut beta_z_compressed = Vec::<u8>::new();
        beta_z.serialize(&mut beta_z_compressed, true).expect("couldn't serialize");
				
		//println!("size of Fr compressed: {}", beta_z_compressed.len());//it's 32
		let proof = PairProof {
			v_t: v_t_compressed,
			w_t: w_t_compressed,
			beta_z: beta_z_compressed,
		};
		
		(new_compressed_card, proof)
        
    }
    
    
	//check that the punch card is valid with num_punches
	//check that the punch card secret is new
    pub fn pair_server_verify(&mut self, compressed_card1: &mut Vec<u8>, secret1: [u8; 32], secret2: [u8; 32], num_punches: u32) -> bool {
    
        let csuite1 = [0u8; 4];
        let csuite2 = [1u8, 0u8, 0u8, 0u8];
    
        //compute the values and pairings you would expect
        let num_punches = self.secret.pow([num_punches as u64]);
        let mut expcard_1_1 = <G1 as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(&secret1, &csuite1);
        //let expcard_1_2 = <G2 as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(&secret1, &csuite2);
        //let mut expcard_2_1 = <G1 as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(&secret2, &csuite1);
        let expcard_2_2 = <G2 as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(&secret2, &csuite2);
        
        expcard_1_1.mul_assign(num_punches);
        //expcard_2_1.mul_assign(num_punches);
        
        let exp_pairing_1 = Bls12::pairing(expcard_1_1, expcard_2_2);
        //let exp_pairing_2 = Bls12::pairing(expcard_2_1, expcard_1_2);
        
        
        //deserialize the cards given as parameters
        let card1 = Fq12::deserialize(&mut &compressed_card1[..], true).expect("couldn't deserialize");
        //let card2 = Fq12::deserialize(&mut &compressed_card2[..], true).expect("couldn't deserialize");
        
        //check that the card is valid (real and expected values match)
        if card1 == exp_pairing_1 {
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
        where T: CurveProjective + SerDes + HashToCurve<ExpandMsgXmd<Sha256>>,
              <<T as CurveProjective>::Scalar as PrimeField>::Repr: std::convert::From<Fr>
    {
		
        let last_mask = Fr::random(&mut OsRng);
        
        let mut punch_card = <T as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(&card_secret, &csuite);
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
	
	pub fn verify_remask(&mut self, compressed_card1: Vec<u8>, compressed_card2: Vec<u8>, pub_secret_g1: &Vec<u8>, pub_secret_g2: &Vec<u8>, proof1: PairProof, proof2: PairProof) -> (Vec<u8>, Vec<u8>, bool) {
	
            let dst1 = [3u8, 0u8, 0u8, 0u8];
            let dst2 = [4u8, 0u8, 0u8, 0u8];
            
            let (card1, success1) = Self::verify_remask_part::<G1>(&mut self.g1card, compressed_card1, pub_secret_g1, proof1, dst1);
            let (card2, success2) = Self::verify_remask_part::<G2>(&mut self.g2card, compressed_card2, pub_secret_g2, proof2, dst2);
            
            if success1 != success2 {panic!("success values don't match");}
            
            (card1, card2, success1)
	}
	
	//verify proof from the server
	//if accepted, unmask punchcard, remask with new mask, increment count
	//otherwise reuse old punchcard, same count
	fn verify_remask_part<T>(card: &mut PairPunchCardPart<T>, new_compressed_card: Vec<u8>, pub_secret: &Vec<u8>, proof: PairProof, dst: [u8; 4]) -> (Vec<u8>, bool) 
        where T: CurveProjective + SerDes,
        <<T as pairing_plus::CurveProjective>::Scalar as ff_zeroize::PrimeField>::Repr: std::convert::From<pairing_plus::bls12_381::Fr>
	{
	
        //serialize the punch card so it can be used here
        let mut compressed_card = Vec::<u8>::new();
        card.punch_card.serialize(&mut compressed_card, true).expect("couldn't serialize");
	
        //verify Chaum-Pedersen proof
		//see Boneh Shoup textbook v0.5 Figure 19.7
		let mut hashinput: Vec<u8> = Vec::new();
		hashinput.extend_from_slice(pub_secret);
		hashinput.extend_from_slice(&compressed_card);
		hashinput.extend_from_slice(&new_compressed_card);
		hashinput.extend_from_slice(&proof.v_t);
		hashinput.extend_from_slice(&proof.w_t);
		let hashinput_bytes: &[u8] = &hashinput;
		let chal = hash_to_field::<Fr, ExpandMsgXmd<Sha256>>(hashinput_bytes, &dst, 1)[0];
		
		//decompress proof elements and remaining inputs
		let pub_secret = T::deserialize(&mut &pub_secret[..], true).expect("couldn't deserialize");
        let v_t = T::deserialize(&mut &proof.v_t[..], true).expect("couldn't deserialize");
		let w_t = T::deserialize(&mut &proof.w_t[..], true).expect("couldn't deserialize");
		let mut new_card = T::deserialize(&mut &new_compressed_card[..], true).expect("couldn't deserialize");
        let beta_z = Fr::deserialize(&mut &proof.beta_z[..], true).expect("couldn't deserialize");

		let mut gbz = T::one();
		gbz.mul_assign(beta_z);
        
        let mut vtvc = v_t;
        let mut part = pub_secret;
        part.mul_assign(chal);
        vtvc.add_assign(&part);
        
        let mut ubz = card.punch_card;
        ubz.mul_assign(beta_z);
        
        let mut wtwc = w_t;
        let mut part = new_card;
        part.mul_assign(chal);
        wtwc.add_assign(&part);
        
        let mut success = true;
        if gbz == vtvc && ubz == wtwc {
            new_card.mul_assign(card.last_mask.inverse().expect("couldn't invert!"));
            card.last_mask = Fr::random(&mut OsRng);
            new_card.mul_assign(card.last_mask);
            card.punch_card = new_card;
            card.count += 1;
        } else {
            success = false;
        }
        
        //serialize new card
        let mut new_card_compressed = Vec::<u8>::new();
        new_card.serialize(&mut new_card_compressed, true).expect("couldn't serialize");
        
        (new_card_compressed, success)
	}
	
	//unmask the punch card, use pairings to merge, and return relevant contents
	pub fn pair_unmask_redeem(&mut self, mut other: PairPunchCard) -> ([u8; 32], [u8; 32], Vec<u8>) {
        
        //unmask the punch cards
        self.g1card.punch_card.mul_assign(self.g1card.last_mask.inverse().expect("couldn't invert!"));
        //self.g2card.punch_card.mul_assign(self.g2card.last_mask.inverse().expect("couldn't invert!"));
        //other.g1card.punch_card.mul_assign(other.g1card.last_mask.inverse().expect("couldn't invert!"));
        other.g2card.punch_card.mul_assign(other.g2card.last_mask.inverse().expect("couldn't invert!"));
        
        //pairings of the parts of the punch cards
        let pairing1 = Bls12::pairing(self.g1card.punch_card, other.g2card.punch_card);
        //let pairing2 = Bls12::pairing(other.g1card.punch_card, self.g2card.punch_card);
	
        //serialize pairing outputs
        let mut pairing1_compressed = Vec::<u8>::new();
        //let mut pairing2_compressed = Vec::<u8>::new();
        pairing1.serialize(&mut pairing1_compressed, true).expect("couldn't serialize");
        //pairing2.serialize(&mut pairing2_compressed, true).expect("couldn't serialize");

        
        //return the secrets from the punch cards and the results of the pairings
        //since both parts of each card use the same secret, we only need one from each
        (self.g1card.card_secret, other.g1card.card_secret, pairing1_compressed)//, pairing2_compressed)
	}
	
	pub fn pair_get_count(&self) -> u32 {
		if self.g1card.count != self.g2card.count {panic!("card counts misaligned!")}
		
		self.g1card.count
	}
	
    pub fn exp_test_g1(&mut self) -> G1{
        self.g1card.punch_card.mul_assign(self.g1card.last_mask);
        self.g1card.punch_card
	}
	
    pub fn exp_test_g2(&mut self) -> G2{
        self.g2card.punch_card.mul_assign(self.g2card.last_mask);
        self.g2card.punch_card
	}
	
	pub fn pair_test(&mut self) -> Fq12{
        Bls12::pairing(self.g1card.punch_card, self.g2card.punch_card)
    }

}
