extern crate cryptography_utils;
extern crate kms;
extern crate multi_party_ecdsa;
extern crate paillier;

use self::cryptography_utils::cryptographic_primitives::proofs::dlog_zk_protocol::DLogProof;
use self::cryptography_utils::cryptographic_primitives::twoparty::*;
use self::cryptography_utils::GE;
use self::kms::two_party::lindell_2017::*;
use self::kms::two_party::lindell_2017::traits::ManagementSystem;
use self::multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;
use self::paillier::*;
use serde_json;
use utilities::json_utils::*;

#[derive(Serialize, Deserialize)]
struct Party1SecondMessageBindings {
    pub pk_commitment_blind_factor: BigInt,
    pub zk_pok_blind_factor: BigInt,
    pub public_share: GE,
    pub d_log_proof: DLogProof,
    pub paillier_key_pair: party_one::PaillierKeyPair,
    pub encrypted_pairs: EncryptedPairs,
    pub challenge: ChallengeBits,
    pub proof: Proof,
}

#[derive(Serialize, Deserialize)]
struct PartyTwoSecondMessageBindings {
    party_two_second_message: party_two::KeyGenSecondMsg,
    paillier_key_pair: party_two::PaillierPublic,
    pub challenge: Challenge,
    verification_aid: VerificationAid,
}

pub fn party_one_first_message() -> String {
    to_json_str(MasterKey1::key_gen_first_message())
}

pub fn party_two_first_message() -> String {
    to_json_str(MasterKey2::key_gen_first_message())
}

pub fn party_one_second_message(
    party_one_first_message_str: String,
    party_two_first_message_proof_str: String) -> String
{
    let party_one_first_message: party_one::KeyGenFirstMsg = serde_json::from_str(&party_one_first_message_str).unwrap();
    let party_two_first_message_proof: DLogProof = serde_json::from_str(&party_two_first_message_proof_str).unwrap();

    let party_one_second_message = MasterKey1::key_gen_second_message(
        &party_one_first_message,
        &party_two_first_message_proof,
    );

    to_json_str(Party1SecondMessageBindings {
        pk_commitment_blind_factor: party_one_second_message.0.pk_commitment_blind_factor,
        zk_pok_blind_factor: party_one_second_message.0.zk_pok_blind_factor,
        public_share: party_one_second_message.0.public_share,
        d_log_proof: party_one_second_message.0.d_log_proof,
        paillier_key_pair: party_one_second_message.1,
        encrypted_pairs: party_one_second_message.2,
        challenge: party_one_second_message.3,
        proof: party_one_second_message.4,
    })
}

pub fn party_two_second_message(
    party_one_first_message_pk_commitment_str: String,
    party_one_first_message_zk_pok_commitment_str: String,
    party_one_second_message_zk_pok_blind_factor_str: String,
    party_one_second_message_public_share_str: String,
    party_one_second_message_pk_commitment_blind_factor_str: String,
    party_one_second_message_d_log_proof_str: String,
    paillier_encryption_key_str: String,
    paillier_encrypted_share_str: String,
    rp_encrypted_pairs_str: String,
    rp_challenge_str: String,
    rp_proof_str: String
) -> String {
    let party_one_first_message_pk_commitment: BigInt =
        serde_json::from_str(&party_one_first_message_pk_commitment_str).unwrap();

    let party_one_first_message_zk_pok_commitment: BigInt =
        serde_json::from_str(&party_one_first_message_zk_pok_commitment_str).unwrap();

    let party_one_second_message_zk_pok_blind_factor: BigInt =
        serde_json::from_str(&party_one_second_message_zk_pok_blind_factor_str).unwrap();

    let party_one_second_message_public_share: GE =
        serde_json::from_str(&party_one_second_message_public_share_str).unwrap();

    let party_one_second_message_pk_commitment_blind_factor: BigInt =
        serde_json::from_str(&party_one_second_message_pk_commitment_blind_factor_str).unwrap();

    let party_one_second_message_d_log_proof: DLogProof =
        serde_json::from_str(&party_one_second_message_d_log_proof_str).unwrap();

    let paillier_encryption_key: EncryptionKey =
        serde_json::from_str(&paillier_encryption_key_str).unwrap();

    let paillier_encrypted_share: BigInt =
        serde_json::from_str(&paillier_encrypted_share_str).unwrap();

    let rp_encrypted_pairs: EncryptedPairs =
        serde_json::from_str(&rp_encrypted_pairs_str).unwrap();

    let rp_challenge: ChallengeBits = serde_json::from_str(&rp_challenge_str).unwrap();

    let rp_proof: Proof = serde_json::from_str(&rp_proof_str).unwrap();

    let key_gen_second_message = MasterKey2::key_gen_second_message(
        &party_one_first_message_pk_commitment,
        &party_one_first_message_zk_pok_commitment,
        &party_one_second_message_zk_pok_blind_factor,
        &party_one_second_message_public_share,
        &party_one_second_message_pk_commitment_blind_factor,
        &party_one_second_message_d_log_proof,
        &paillier_encryption_key,
        &paillier_encrypted_share,
        &rp_challenge,
        &rp_encrypted_pairs,
        &rp_proof,
    );

    assert!(key_gen_second_message.is_ok());

    let key_gen_second_message_raw = key_gen_second_message.unwrap();
    assert!(key_gen_second_message_raw.0.is_ok());

    to_json_str(PartyTwoSecondMessageBindings {
        party_two_second_message: key_gen_second_message_raw.0.unwrap(),
        paillier_key_pair: key_gen_second_message_raw.1,
        challenge: key_gen_second_message_raw.2,
        verification_aid: key_gen_second_message_raw.3,
    })
}

pub fn party_one_third_message(paillier_key_pair_str: String, challenge_str: String) -> String {
    let paillier_key_pair: party_one::PaillierKeyPair = serde_json::from_str(&paillier_key_pair_str).unwrap();
    let challenge: Challenge = serde_json::from_str(&challenge_str).unwrap();
    let digest = MasterKey1::key_gen_third_message(&paillier_key_pair, &challenge);

    assert!(digest.is_ok());
    to_json_str(digest.unwrap())
}

pub fn party_two_third_message(party_one_third_message_str: String, verification_aid_str: String) -> String {
    let party_one_third_message: CorrectKeyProof = serde_json::from_str(&party_one_third_message_str).unwrap();
    let verification_aid: VerificationAid = serde_json::from_str(&verification_aid_str).unwrap();

    let key_gen_third_message =
        MasterKey2::key_gen_third_message(&party_one_third_message, &verification_aid);

    assert!(key_gen_third_message.is_ok());
    to_json_str(true)
}


pub fn party_one_get_master_key(
    cc_party_one_first_message_str: String,
    cc_party_two_first_message_public_share_str: String,
    kg_party_one_first_message_str: String,
    kg_party_two_first_message_public_share_str: String,
    paillier_key_pair_str: String) -> String
{
    let cc_party_one_first_message: dh_key_exchange::Party1FirstMessage = serde_json::from_str(&cc_party_one_first_message_str).unwrap();
    let cc_party_two_first_message_public_share: GE = serde_json::from_str(&cc_party_two_first_message_public_share_str).unwrap();
    let kg_party_one_first_message: party_one::KeyGenFirstMsg = serde_json::from_str(&kg_party_one_first_message_str).unwrap();
    let kg_party_two_first_message_public_share: GE = serde_json::from_str(&kg_party_two_first_message_public_share_str).unwrap();
    let paillier_key_pair: party_one::PaillierKeyPair = serde_json::from_str(&paillier_key_pair_str).unwrap();

    let party1_cc = MasterKey1::compute_chain_code(
        &cc_party_one_first_message,
        &cc_party_two_first_message_public_share,
    );

    let party_one_master_key = MasterKey1::set_master_key(
        &party1_cc,
        &kg_party_one_first_message,
        &kg_party_two_first_message_public_share,
        &paillier_key_pair,
    );

    to_json_str(party_one_master_key)
}

pub fn party_two_get_master_key(
    cc_party_two_first_message_str: String,
    cc_party_one_first_message_public_share_str: String,
    kg_party_two_first_message_str: String,
    kg_party_one_first_message_public_share_str: String,
    party_two_paillier_str: String) -> String
{
    let cc_party_two_first_message: dh_key_exchange::Party2FirstMessage = serde_json::from_str(&cc_party_two_first_message_str).unwrap();
    let cc_party_one_first_message_public_share: GE = serde_json::from_str(&cc_party_one_first_message_public_share_str).unwrap();
    let kg_party_two_first_message: party_two::KeyGenFirstMsg = serde_json::from_str(&kg_party_two_first_message_str).unwrap();
    let kg_party_one_first_message_public_share: GE = serde_json::from_str(&kg_party_one_first_message_public_share_str).unwrap();
    let party_two_paillier: party_two::PaillierPublic = serde_json::from_str(&party_two_paillier_str).unwrap();

    let party2_cc = MasterKey2::compute_chain_code(
        &cc_party_one_first_message_public_share,
        &cc_party_two_first_message,
    );

    let party_two_master_key = MasterKey2::set_master_key(
        &party2_cc,
        &kg_party_two_first_message,
        &kg_party_one_first_message_public_share,
        &party_two_paillier,
    );

    to_json_str(party_two_master_key)
}

pub fn party_two_compute_partial_signature(
    party_two_paillier_ek_str: String,
    party_two_master_key_public_c_key_str: String,
    party_two_master_key_private_str: String,
    ep_party_two_first_message_str: String,
    ep_party_one_first_message_public_share_str: String,
    message: String,
) -> String {
    let party_two_paillier_ek: EncryptionKey = serde_json::from_str(&party_two_paillier_ek_str).unwrap();
    let party_two_master_key_public_c_key: BigInt = serde_json::from_str(&party_two_master_key_public_c_key_str).unwrap();
    let party_two_master_key_private: party_two::Party2Private = serde_json::from_str(&party_two_master_key_private_str).unwrap();
    let ep_party_two_first_message: party_two::KeyGenFirstMsg = serde_json::from_str(&ep_party_two_first_message_str).unwrap();
    let ep_party_one_first_message_public_share: GE = serde_json::from_str(&ep_party_one_first_message_public_share_str).unwrap();
    let message: BigInt = serde_json::from_str(&message).unwrap();

    let partial_sig = party_two::PartialSig::compute(
        &party_two_paillier_ek,
        &party_two_master_key_public_c_key,
        &party_two_master_key_private,
        &ep_party_two_first_message,
        &ep_party_one_first_message_public_share,
        &message,
    );

    to_json_str(partial_sig)
}

pub fn party_one_sign(
    party_one_private_str: String,
    c3_str: String,
    ep_party_one_first_message_str: String,
    ep_party_two_first_message_public_share_str: String,
) -> String {
    let party_one_private: party_one::Party1Private = serde_json::from_str(&party_one_private_str).unwrap();
    let c3: BigInt = serde_json::from_str(&c3_str).unwrap();
    let ep_party_one_first_message: party_one::KeyGenFirstMsg = serde_json::from_str(&ep_party_one_first_message_str).unwrap();
    let ep_party_two_first_message_public_share: GE = serde_json::from_str(&ep_party_two_first_message_public_share_str).unwrap();

    let signature = party_one::Signature::compute(
        &party_one_private,
        &c3,
        &ep_party_one_first_message,
        &ep_party_two_first_message_public_share,
    );

    to_json_str(signature)
}


pub fn party_two_get_child_master_key(
    party_two_master_key_str: String,
    x_str: String,
    y_str: String
) -> String {
    let party_two_master_key: MasterKey2 = serde_json::from_str(&party_two_master_key_str).unwrap();
    let x: BigInt = serde_json::from_str(&x_str).unwrap();
    let y: BigInt = serde_json::from_str(&y_str).unwrap();

    to_json_str(party_two_master_key.get_child(vec![x, y]))
}

pub fn party_one_get_child_master_key(
    party_one_master_key_str: String,
    x_str: String,
    y_str: String
) -> String {
    let party_one_master_key: MasterKey1 = serde_json::from_str(&party_one_master_key_str).unwrap();
    let x: BigInt = serde_json::from_str(&x_str).unwrap();
    let y: BigInt = serde_json::from_str(&y_str).unwrap();

    to_json_str(party_one_master_key.get_child(vec![x, y]))
}

pub fn party_one_verify_signatures(
    signature_str: String,
    party_one_master_key_public_q_str: String,
    message_str: String,
) -> String {
    let signature: party_one::Signature = serde_json::from_str(&signature_str).unwrap();
    let party_one_master_key_public_q: GE = serde_json::from_str(&party_one_master_key_public_q_str).unwrap();
    let message: BigInt = serde_json::from_str(&message_str).unwrap();

    let is_valid = party_one::verify(&signature, &party_one_master_key_public_q, &message);

    assert!(is_valid.is_ok());

    to_json_str(true)
}
