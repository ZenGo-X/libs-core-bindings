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
use serde::de;
use std::collections::HashMap;
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