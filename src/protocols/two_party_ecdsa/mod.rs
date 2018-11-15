extern crate cryptography_utils;
extern crate kms;
extern crate multi_party_ecdsa;
extern crate paillier;

use self::cryptography_utils::cryptographic_primitives::proofs::dlog_zk_protocol::DLogProof;
use self::cryptography_utils::cryptographic_primitives::twoparty::*;
use self::cryptography_utils::GE;
use self::kms::chain_code;
use self::kms::ecdsa::two_party::*;
use protocols::two_party_ecdsa::kms::ManagementSystem;

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
    pub correct_key_proof: NICorrectKeyProof,
}

#[derive(Serialize, Deserialize)]
struct PartyTwoSecondMessageBindings {
    paillier_key_pair: party_two::PaillierPublic,
    pub pdl_challenge: party_two::PDLchallenge,
}

pub fn party_one_first_message() -> String {
    to_json_str(MasterKey1::key_gen_first_message())
}

pub fn party_two_first_message() -> String {
    to_json_str(MasterKey2::key_gen_first_message())
}

pub fn party_one_second_message(
    party_one_first_message_str: String,
    party_two_first_message_proof_str: String,
) -> String {
    let party_one_first_message: party_one::KeyGenFirstMsg =
        serde_json::from_str(&party_one_first_message_str).unwrap();
    let party_two_first_message_proof: DLogProof =
        serde_json::from_str(&party_two_first_message_proof_str).unwrap();

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
        correct_key_proof: party_one_second_message.5,
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
    rp_proof_str: String,
    correct_key_proof_str: String,
) -> String {
    let party_one_first_message_pk_commitment: BigInt =
        match serde_json::from_str(&party_one_first_message_pk_commitment_str) {
            Ok(v) => v,
            Err(e) => panic!(
                "Unable to serialize party_one_first_message_pk_commitment {}, due to {}",
                &party_one_first_message_pk_commitment_str,
                e.to_string()
            ),
        };

    let party_one_first_message_zk_pok_commitment: BigInt =
        match serde_json::from_str(&party_one_first_message_zk_pok_commitment_str) {
            Ok(v) => v,
            Err(e) => panic!(
                "Unable to serialize party_one_first_message_zk_pok_commitment {}, due to {}",
                &party_one_first_message_zk_pok_commitment_str,
                e.to_string()
            ),
        };

    let party_one_second_message_zk_pok_blind_factor: BigInt =
        match serde_json::from_str(&party_one_second_message_zk_pok_blind_factor_str) {
            Ok(v) => v,
            Err(e) => panic!(
                "Unable to serialize party_one_second_message_zk_pok_blind_factor {}, due to {}",
                &party_one_second_message_zk_pok_blind_factor_str,
                e.to_string()
            ),
        };

    let party_one_second_message_public_share: GE =
        match serde_json::from_str(&party_one_second_message_public_share_str) {
            Ok(v) => v,
            Err(e) => panic!(
                "Unable to serialize party_one_second_message_public_share {}, due to {}",
                &party_one_second_message_public_share_str,
                e.to_string()
            ),
        };

    let party_one_second_message_pk_commitment_blind_factor: BigInt =
        match serde_json::from_str(&party_one_second_message_pk_commitment_blind_factor_str) {
            Ok(v) => v,
            Err(e) => panic!(
            "Unable to serialize party_one_second_message_pk_commitment_blind_factor {}, due to {}",
            &party_one_second_message_pk_commitment_blind_factor_str,
            e.to_string()
        ),
        };

    let party_one_second_message_d_log_proof: DLogProof =
        match serde_json::from_str(&party_one_second_message_d_log_proof_str) {
            Ok(v) => v,
            Err(e) => panic!(
                "Unable to serialize party_one_second_message_d_log_proof {}, due to {}",
                &party_one_second_message_d_log_proof_str,
                e.to_string()
            ),
        };

    let paillier_encryption_key: EncryptionKey =
        match serde_json::from_str(&paillier_encryption_key_str) {
            Ok(v) => v,
            Err(e) => panic!(
                "Unable to serialize paillier_encryption_key_str {}, due to {}",
                &paillier_encryption_key_str,
                e.to_string()
            ),
        };

    let paillier_encrypted_share: BigInt = match serde_json::from_str(&paillier_encrypted_share_str)
    {
        Ok(v) => v,
        Err(e) => panic!(
            "Unable to serialize paillier_encrypted_share {}, due to {}",
            &paillier_encrypted_share_str,
            e.to_string()
        ),
    };

    let rp_encrypted_pairs: EncryptedPairs = match serde_json::from_str(&rp_encrypted_pairs_str) {
        Ok(v) => v,
        Err(e) => panic!(
            "Unable to serialize rp_encrypted_pairs_str {}, due to {}",
            &rp_encrypted_pairs_str,
            e.to_string()
        ),
    };

    let rp_challenge: ChallengeBits = match serde_json::from_str(&rp_challenge_str) {
        Ok(v) => v,
        Err(e) => panic!(
            "Unable to serialize rp_challenge_str {}, due to {}",
            &rp_challenge_str,
            e.to_string()
        ),
    };

    let rp_proof: Proof = match serde_json::from_str(&rp_proof_str) {
        Ok(v) => v,
        Err(e) => panic!(
            "Unable to serialize proof {}, due to {}",
            &rp_proof_str,
            e.to_string()
        ),
    };

    let correct_key_proof: NICorrectKeyProof = match serde_json::from_str(&correct_key_proof_str) {
        Ok(v) => v,
        Err(e) => panic!(
            "Unable to serialize proof {}, due to {}",
            &correct_key_proof_str,
            e.to_string()
        ),
    };

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
        &correct_key_proof,
    );

    assert!(key_gen_second_message.is_ok());

    let key_gen_second_message_raw = key_gen_second_message.unwrap();
    assert!(key_gen_second_message_raw.0.is_ok());

    to_json_str(PartyTwoSecondMessageBindings {
        paillier_key_pair: key_gen_second_message_raw.1,
        pdl_challenge: key_gen_second_message_raw.2,
    })
}

pub fn party_one_third_message(paillier_key_pair_str: String, pdl_challenge_str: String) -> String {
    let paillier_key_pair: party_one::PaillierKeyPair =
        serde_json::from_str(&paillier_key_pair_str).unwrap();
    let pdl_challenge: party_two::PDLchallenge = serde_json::from_str(&pdl_challenge_str).unwrap();
    let pdl_prover = MasterKey1::key_gen_third_message(&paillier_key_pair, &pdl_challenge.c_tag);

    to_json_str(pdl_prover)
}

pub fn party_two_third_message(pdl_challenge_str: String) -> String {
    let pdl_challenge: party_two::PDLchallenge = serde_json::from_str(&pdl_challenge_str).unwrap();
    let pdl_decom_party2 = MasterKey2::key_gen_third_message(&pdl_challenge);

    to_json_str(pdl_decom_party2)
}

pub fn party_one_fourth_message(
    kg_party_one_first_message_str: String,
    pdl_challenge_c_tag_tag_str: String,
    pdl_prover_str: String,
    pdl_decom_party2_str: String,
) -> String {
    let kg_party_one_first_message: party_one::KeyGenFirstMsg =
        serde_json::from_str(&kg_party_one_first_message_str).unwrap();
    let pdl_challenge_c_tag_tag: BigInt =
        serde_json::from_str(&pdl_challenge_c_tag_tag_str).unwrap();
    let pdl_prover: party_one::PDL = serde_json::from_str(&pdl_prover_str).unwrap();
    let pdl_decom_party2: party_two::PDLdecommit =
        serde_json::from_str(&pdl_decom_party2_str).unwrap();

    let pdl_decom_party1 = MasterKey1::key_gen_fourth_message(
        &pdl_prover,
        &pdl_challenge_c_tag_tag,
        &kg_party_one_first_message,
        &pdl_decom_party2.a,
        &pdl_decom_party2.b,
        &pdl_decom_party2.blindness,
    );

    assert!(pdl_decom_party1.is_ok());
    to_json_str(pdl_decom_party1.unwrap())
}

pub fn party_two_fourth_message(
    pdl_challenge_str: String,
    pdl_prover_str: String,
    pdl_decom_party1_str: String,
) -> String {
    let pdl_challenge: party_two::PDLchallenge = serde_json::from_str(&pdl_challenge_str).unwrap();
    let pdl_prover: party_one::PDL = serde_json::from_str(&pdl_prover_str).unwrap();
    let pdl_decom_party1: party_one::PDLdecommit =
        serde_json::from_str(&pdl_decom_party1_str).unwrap();

    assert!(
        MasterKey2::key_gen_fourth_message(
            &pdl_challenge,
            &pdl_decom_party1.blindness,
            &pdl_decom_party1.q_hat,
            &pdl_prover.c_hat,
        ).is_ok()
    );

    to_json_str(true)
}

pub fn party_one_get_master_key(
    cc_party_one_first_message_str: String,
    cc_party_two_first_message_public_share_str: String,
    kg_party_one_first_message_str: String,
    kg_party_two_first_message_public_share_str: String,
    paillier_key_pair_str: String,
) -> String {
    let cc_party_one_first_message: dh_key_exchange::Party1FirstMessage =
        serde_json::from_str(&cc_party_one_first_message_str).unwrap();
    let cc_party_two_first_message_public_share: GE =
        serde_json::from_str(&cc_party_two_first_message_public_share_str).unwrap();
    let kg_party_one_first_message: party_one::KeyGenFirstMsg =
        serde_json::from_str(&kg_party_one_first_message_str).unwrap();
    let kg_party_two_first_message_public_share: GE =
        serde_json::from_str(&kg_party_two_first_message_public_share_str).unwrap();
    let paillier_key_pair: party_one::PaillierKeyPair =
        serde_json::from_str(&paillier_key_pair_str).unwrap();

    let party1_cc = chain_code::two_party::party1::ChainCode1::compute_chain_code(
        &cc_party_one_first_message,
        &cc_party_two_first_message_public_share,
    );

    let party_one_master_key = MasterKey1::set_master_key(
        &party1_cc.chain_code,
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
    party_two_paillier_str: String,
) -> String {
    let cc_party_two_first_message: dh_key_exchange::Party2FirstMessage =
        serde_json::from_str(&cc_party_two_first_message_str).unwrap();
    let cc_party_one_first_message_public_share: GE =
        serde_json::from_str(&cc_party_one_first_message_public_share_str).unwrap();
    let kg_party_two_first_message: party_two::KeyGenFirstMsg =
        serde_json::from_str(&kg_party_two_first_message_str).unwrap();
    let kg_party_one_first_message_public_share: GE =
        serde_json::from_str(&kg_party_one_first_message_public_share_str).unwrap();
    let party_two_paillier: party_two::PaillierPublic =
        serde_json::from_str(&party_two_paillier_str).unwrap();

    let party2_cc = chain_code::two_party::party2::ChainCode2::compute_chain_code(
        &cc_party_one_first_message_public_share,
        &cc_party_two_first_message,
    );

    let party_two_master_key = MasterKey2::set_master_key(
        &party2_cc.chain_code,
        &kg_party_two_first_message,
        &kg_party_one_first_message_public_share,
        &party_two_paillier,
    );

    to_json_str(party_two_master_key)
}

pub fn party_two_sign_first_message() -> String {
    to_json_str(MasterKey2::sign_first_message())
}

pub fn party_two_sign_second_message(
    party_two_master_key_str: String,
    sign_party_two_first_message_str: String,
    ep_party_one_first_message_d_log_proof_str: String,
    ep_party_one_first_message_public_share_str: String,
    message: String,
) -> String {
    let party_two_master_key: MasterKey2 = serde_json::from_str(&party_two_master_key_str).unwrap();

    let sign_party_two_first_message: party_two::EphKeyGenFirstMsg =
        serde_json::from_str(&sign_party_two_first_message_str).unwrap();

    let ep_party_one_first_message_public_share: GE =
        serde_json::from_str(&ep_party_one_first_message_public_share_str).unwrap();

    let ep_party_one_first_message_d_log_proof: DLogProof =
        serde_json::from_str(&ep_party_one_first_message_d_log_proof_str).unwrap();

    let message: BigInt = serde_json::from_str(&message).unwrap();

    let sign_party_two_second_message = party_two_master_key.sign_second_message(
        &sign_party_two_first_message,
        &ep_party_one_first_message_public_share,
        &ep_party_one_first_message_d_log_proof,
        &message,
    );

    to_json_str(sign_party_two_second_message)
}

pub fn party_one_sign_first_message() -> String {
    to_json_str(MasterKey1::sign_first_message())
}

pub fn party_one_sign_second_message(
    party_one_master_key_str: String,
    sign_party_one_first_message_str: String,
    eph_key_gen_first_message_party_two_pk_commitment_str: String,
    eph_key_gen_first_message_party_two_zk_pok_commitment_str: String,
    eph_key_gen_first_message_party_two_public_share_str: String,
    sign_party_two_second_message_str: String,
    message: String,
) -> String {

    let party_one_master_key: MasterKey1 = serde_json::from_str(&party_one_master_key_str).unwrap();

    let sign_party_one_first_message: party_one::EphKeyGenFirstMsg =
        serde_json::from_str(&sign_party_one_first_message_str).unwrap();

    let eph_key_gen_first_message_party_two_pk_commitment =
        serde_json::from_str(&eph_key_gen_first_message_party_two_pk_commitment_str).unwrap();

    let eph_key_gen_first_message_party_two_zk_pok_commitment =
        serde_json::from_str(&eph_key_gen_first_message_party_two_zk_pok_commitment_str).unwrap();

    let eph_key_gen_first_message_party_two_public_share =
        serde_json::from_str(&eph_key_gen_first_message_party_two_public_share_str).unwrap();

    let sign_party_two_second_message: party2::SignMessage =
        serde_json::from_str(&sign_party_two_second_message_str).unwrap();

    let message: BigInt = serde_json::from_str(&message).unwrap();

    let sign_party_one_second_message = party_one_master_key.sign_second_message(
        &sign_party_two_second_message,
        &eph_key_gen_first_message_party_two_pk_commitment,
        &eph_key_gen_first_message_party_two_zk_pok_commitment,
        &eph_key_gen_first_message_party_two_public_share,
        &sign_party_one_first_message,
        &message,
    );

    assert!(sign_party_one_second_message.is_ok());

    to_json_str(sign_party_one_second_message.unwrap())
}

pub fn party_two_get_child_master_key(
    party_two_master_key_str: String,
    x_str: String,
    y_str: String,
) -> String {
    let party_two_master_key: MasterKey2 = serde_json::from_str(&party_two_master_key_str).unwrap();
    let x: BigInt = serde_json::from_str(&x_str).unwrap();
    let y: BigInt = serde_json::from_str(&y_str).unwrap();

    to_json_str(party_two_master_key.get_child(vec![x, y]))
}

pub fn party_one_get_child_master_key(
    party_one_master_key_str: String,
    x_str: String,
    y_str: String,
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
    let party_one_master_key_public_q: GE =
        serde_json::from_str(&party_one_master_key_public_q_str).unwrap();
    let message: BigInt = serde_json::from_str(&message_str).unwrap();

    let is_valid = party_one::verify(&signature, &party_one_master_key_public_q, &message);

    assert!(is_valid.is_ok());

    to_json_str(true)
}
