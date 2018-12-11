extern crate curv;
extern crate kms;
extern crate multi_party_ecdsa;
extern crate paillier;

use self::curv::cryptographic_primitives::proofs::dlog_zk_protocol::DLogProof;
use self::curv::cryptographic_primitives::twoparty::*;
use self::curv::GE;
use self::kms::chain_code;
use self::kms::ecdsa::two_party::*;
use protocols::two_party_ecdsa::kms::ManagementSystem;

use self::multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_one::KeyGenFirstMsg as Party1KeyGenFirstMsg;
use self::multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_one::KeyGenSecondMsg as Party1KeyGenSecondMsg;
use self::multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;
use self::paillier::*;
use serde_json;
use utilities::json_utils::*;

pub fn party_one_first_message() -> String {
    to_json_str(MasterKey1::key_gen_first_message())
}

pub fn party_two_first_message() -> String {
    to_json_str(MasterKey2::key_gen_first_message())
}

pub fn party_one_second_message(
    comm_witness_str: String,
    ec_key_pair_party1_str: String,
    proof_str: String,
) -> String {
    let comm_witness: party_one::CommWitness = serde_json::from_str(&comm_witness_str).unwrap();

    let ec_key_pair_party1: party_one::EcKeyPair =
        serde_json::from_str(&ec_key_pair_party1_str).unwrap();

    let proof: DLogProof = serde_json::from_str(&proof_str).unwrap();

    let party_one_second_message =
        MasterKey1::key_gen_second_message(comm_witness, &ec_key_pair_party1, &proof);

    to_json_str(party_one_second_message)
}

pub fn party_two_second_message(
    party_one_first_message_str: String,
    party_one_second_message_str: String,
    paillier_encryption_key_str: String,
    paillier_encrypted_share_str: String,
    challenge_str: String,
    encrypted_pairs_str: String,
    proof_str: String,
    correct_key_proof_str: String,
) -> String {
    let party_one_first_message: Party1KeyGenFirstMsg =
        serde_json::from_str(&party_one_first_message_str).unwrap();

    let party_one_second_message: Party1KeyGenSecondMsg =
        serde_json::from_str(&party_one_second_message_str).unwrap();

    let paillier_encryption_key: EncryptionKey =
        serde_json::from_str(&paillier_encryption_key_str).unwrap();

    let paillier_encrypted_share: BigInt =
        serde_json::from_str(&paillier_encrypted_share_str).unwrap();

    let challenge: ChallengeBits = serde_json::from_str(&challenge_str).unwrap();

    let encrypted_pairs: EncryptedPairs = serde_json::from_str(&encrypted_pairs_str).unwrap();

    let proof: Proof = serde_json::from_str(&proof_str).unwrap();

    let correct_key_proof: NICorrectKeyProof =
        serde_json::from_str(&correct_key_proof_str).unwrap();

    let key_gen_second_message = MasterKey2::key_gen_second_message(
        &party_one_first_message,
        &party_one_second_message,
        &paillier_encryption_key,
        &paillier_encrypted_share,
        &challenge,
        &encrypted_pairs,
        &proof,
        &correct_key_proof,
    );

    assert!(key_gen_second_message.is_ok());

    let key_gen_second_message_raw = key_gen_second_message.unwrap();
    assert!(key_gen_second_message_raw.0.is_ok());

    to_json_str((
        key_gen_second_message_raw.0.unwrap(),
        key_gen_second_message_raw.1,
        key_gen_second_message_raw.2,
    ))
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
    ec_key_pair_str: String,
    pdl_challenge_c_tag_tag_str: String,
    pdl_prover_str: String,
    pdl_decom_party2_str: String,
) -> String {
    let ec_key_pair: party_one::EcKeyPair = serde_json::from_str(&ec_key_pair_str).unwrap();
    let pdl_challenge_c_tag_tag: BigInt =
        serde_json::from_str(&pdl_challenge_c_tag_tag_str).unwrap();
    let pdl_prover: party_one::PDL = serde_json::from_str(&pdl_prover_str).unwrap();
    let pdl_decom_party2: party_two::PDLdecommit =
        serde_json::from_str(&pdl_decom_party2_str).unwrap();

    let pdl_decom_party1 = MasterKey1::key_gen_fourth_message(
        &pdl_prover,
        &pdl_challenge_c_tag_tag,
        ec_key_pair,
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

    assert!(MasterKey2::key_gen_fourth_message(
        &pdl_challenge,
        &pdl_decom_party1.blindness,
        &pdl_decom_party1.q_hat,
        &pdl_prover.c_hat,
    )
    .is_ok());

    to_json_str(true)
}

pub fn party_one_chain_code_first_message() -> String {
    let cc_party_one_first_message: (dh_key_exchange::Party1FirstMessage, dh_key_exchange::CommWitness, dh_key_exchange::EcKeyPair) =
        chain_code::two_party::party1::ChainCode1::chain_code_first_message();

    to_json_str(cc_party_one_first_message)
}

pub fn party_two_chain_code_first_message() -> String {
    let cc_party_two_first_message: (dh_key_exchange::Party2FirstMessage, dh_key_exchange::EcKeyPair) =
        chain_code::two_party::party2::ChainCode2::chain_code_first_message();

    to_json_str(cc_party_two_first_message)
}

pub fn party_one_chain_code_second_message(
    cc_comm_witness: dh_key_exchange::CommWitness,
    cc_party_two_first_message_d_log_proof: &DLogProof
) -> String {
    let cc_party_one_second_message: dh_key_exchange::Party1SecondMessage =
        chain_code::two_party::party1::ChainCode1::chain_code_second_message(cc_comm_witness, cc_party_two_first_message_d_log_proof);

    to_json_str(cc_party_one_second_message)
}

pub fn party_two_chain_code_second_message(
    cc_party_one_first_message: &dh_key_exchange::Party1FirstMessage,
    cc_party_one_second_message: &dh_key_exchange::Party1SecondMessage
) -> String {
    let cc_party_two_second_message: Result<dh_key_exchange::Party2SecondMessage, curv::cryptographic_primitives::proofs::ProofError> =
        chain_code::two_party::party2::ChainCode2::chain_code_second_message(cc_party_one_first_message, cc_party_one_second_message);

    to_json_str(cc_party_two_second_message)
}

pub fn party_one_get_master_key(
    cc_party_one_first_message_str: String,
    cc_party_two_first_message_public_share_str: String,
    ec_key_pair_str: String,
    kg_party_two_first_message_public_share_str: String,
    paillier_key_pair_str: String,
) -> String {
    let cc_party_one_first_message: dh_key_exchange::Party1FirstMessage =
        serde_json::from_str(&cc_party_one_first_message_str).unwrap();
    let cc_party_two_first_message_public_share: GE =
        serde_json::from_str(&cc_party_two_first_message_public_share_str).unwrap();
    let ec_key_pair: party_one::EcKeyPair = serde_json::from_str(&ec_key_pair_str).unwrap();
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
        &ec_key_pair,
        &kg_party_two_first_message_public_share,
        &paillier_key_pair,
    );

    to_json_str(party_one_master_key)
}

pub fn party_two_get_master_key(
    cc_party_two_first_message_str: String,
    cc_party_one_first_message_public_share_str: String,
    ec_key_pair_str: String,
    kg_party_one_first_message_public_share_str: String,
    party_two_paillier_str: String,
) -> String {
    let cc_party_two_first_message: dh_key_exchange::Party2FirstMessage =
        serde_json::from_str(&cc_party_two_first_message_str).unwrap();
    let cc_party_one_first_message_public_share: GE =
        serde_json::from_str(&cc_party_one_first_message_public_share_str).unwrap();
    let ec_key_pair: party_two::EcKeyPair = serde_json::from_str(&ec_key_pair_str).unwrap();
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
        &ec_key_pair,
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
    eph_ec_key_pair_str: String,
    eph_comm_witness_str: String,
    ep_party_one_first_message_d_log_proof_str: String,
    ep_party_one_first_message_public_share_str: String,
    message: String,
) -> String {
    let party_two_master_key: MasterKey2 = serde_json::from_str(&party_two_master_key_str).unwrap();

    let eph_ec_key_pair: party_two::EphEcKeyPair =
        serde_json::from_str(&eph_ec_key_pair_str).unwrap();

    let eph_comm_witness: party_two::EphCommWitness =
        serde_json::from_str(&eph_comm_witness_str).unwrap();

    let ep_party_one_first_message_public_share: GE =
        serde_json::from_str(&ep_party_one_first_message_public_share_str).unwrap();

    let ep_party_one_first_message_d_log_proof: DLogProof =
        serde_json::from_str(&ep_party_one_first_message_d_log_proof_str).unwrap();

    let message: BigInt = serde_json::from_str(&message).unwrap();

    let sign_party_two_second_message = party_two_master_key.sign_second_message(
        &eph_ec_key_pair,
        eph_comm_witness,
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
    party_two_sign_message_str: String,
    eph_key_gen_first_message_party_two_str: String,
    eph_ec_key_pair_party1_str: String,
    message: String,
) -> String {
    let party_one_master_key: MasterKey1 = serde_json::from_str(&party_one_master_key_str).unwrap();

    let party_two_sign_message: party2::SignMessage =
        serde_json::from_str(&party_two_sign_message_str).unwrap();

    let eph_key_gen_first_message_party_two: party_two::EphKeyGenFirstMsg =
        serde_json::from_str(&eph_key_gen_first_message_party_two_str).unwrap();

    let eph_ec_key_pair_party1: party_one::EphEcKeyPair =
        serde_json::from_str(&eph_ec_key_pair_party1_str).unwrap();

    let message: BigInt = serde_json::from_str(&message).unwrap();

    let sign_party_one_second_message = party_one_master_key.sign_second_message(
        &party_two_sign_message,
        &eph_key_gen_first_message_party_two,
        &eph_ec_key_pair_party1,
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
