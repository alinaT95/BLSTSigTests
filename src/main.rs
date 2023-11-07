use blst::*;

// Benchmark min_pk
use blst::min_pk::*;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::time::{Instant, Duration};

use std::{ptr, slice};

struct BenchData {
    sk: SecretKey,
    pk: PublicKey,
    msg: Vec<u8>,
    dst: Vec<u8>,
    sig: Signature,
}

pub fn gen_random_key(
  /*  rng: &mut rand_chacha::ChaCha20Rng,*/
) -> SecretKey {
    let mut ikm = [0u8; 32];

   // println!("ikm length: {:?}", ikm.len());

    let seed = [0u8; 32];

  //  println!("seed length: {:?}", seed.len());

    let mut rng = ChaCha20Rng::from_seed(seed);

    rng.fill_bytes(&mut ikm);

    let sk = SecretKey::key_gen(&ikm, &[]).unwrap();

    return sk;
}

fn print_type_of<T>(_: &T) {
    println!("{}", std::any::type_name::<T>())
}

fn main() {
    println!("===========================================================");
    println!("===========================================================");
    println!("Test simple BLS sign/verify...");
    println!("===========================================================");

    let sk = gen_random_key(); //SecretKey::key_gen(&ikm, &[]).unwrap();

    let now0 = Instant::now();

    let pk = sk.sk_to_pk();

    let duration0 = now0.elapsed();

    println!("Time elapsed in sk.sk_to_pk is: {:?}", duration0);

    //let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
    let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

    let msg = b"hello foo";

    let now1 = Instant::now();

    let sig = sk.sign(msg, dst, &[]);

    let duration1 = now1.elapsed();

    println!("Time elapsed in sk.sign is: {:?}", duration1);

    let now2 = Instant::now();

    let err = sig.verify(true, msg, dst, &[], &pk, true);

    let duration2 = now2.elapsed();

    println!("Time elapsed in sig.verify is: {:?}", duration2);

    assert_eq!(err, BLST_ERROR::BLST_SUCCESS);

    println!("===========================================================");
    println!("===========================================================");

    println!("Test aggregation BLS sign/verify (for 1 message)...");

    println!("===========================================================");
    //Here we test case when we sign 1 message by multiple keypairs.
    //Then we aggregate signatures for 1 message on different keys.
    //And we aggregate all public keys.
    //Then we verify aggregated signature by aggregated public key.

    let num_pks_per_sig = 500;
    let num_sigs = 10; //here we mean aggregated sig, total number of messages

    let seed = [0u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);

    let mut msgs: Vec<Vec<u8>> = vec![vec![]; num_sigs];
    let mut sigs: Vec<Signature> = Vec::with_capacity(num_sigs);
    let mut pks: Vec<PublicKey> = Vec::with_capacity(num_sigs);
    let mut rands: Vec<blst_scalar> = Vec::with_capacity(num_sigs);
    for i in 0..num_sigs {
        println!("=========================================================");
        // Create secret keys
        let sks_i: Vec<_> = (0..num_pks_per_sig)
            .map(|_| gen_random_key())
            .collect();

        println!("Iteration# {:?}", i);
        println!("sks_i.len = {}", sks_i.len());

        // print_type_of(&sks_i);
        // Create public keys
        let pks_i = sks_i
            .iter()
            .map(|sk| sk.sk_to_pk())
            .collect::<Vec<_>>();

        let pks_refs_i: Vec<&PublicKey> =
            pks_i.iter().map(|pk| pk).collect();

        // Create random message for pks to all sign
        let msg_len = (rng.next_u64() & 0x3F) + 1;
        println!("Msg len = {}", msg_len);
        msgs[i] = vec![0u8; msg_len as usize];
        rng.fill_bytes(&mut msgs[i]);

        // Generate signature for each key pair and message m[i]
        let sigs_i = sks_i
            .iter()
            .map(|sk| sk.sign(&msgs[i], dst, &[]))
            .collect::<Vec<Signature>>();

        // Test each current single signature
        let errs = sigs_i
            .iter()
            .zip(pks_i.iter())
            .map(|(s, pk)| {
                (s.verify(true, &msgs[i], dst, &[], pk, true))
            })
            .collect::<Vec<BLST_ERROR>>();
        assert_eq!(
            errs,
            vec![BLST_ERROR::BLST_SUCCESS; num_pks_per_sig]
        );

        let sig_refs_i =
            sigs_i.iter().map(|s| s).collect::<Vec<&Signature>>();

        println!("sig_refs_i.len = {}", sig_refs_i.len());

        let now3 = Instant::now();

        let agg_i =
            match AggregateSignature::aggregate(&sig_refs_i, false)
                {
                    Ok(agg_i) => agg_i,
                    Err(err) => panic!("aggregate failure: {:?}", err),
                };

        let duration3 = now3.elapsed();

        println!("Time elapsed in AggregateSignature::aggregate is: {:?}", duration3);

        // Test current aggregate signature
        sigs.push(agg_i.to_signature());

        let now4 = Instant::now();

        let mut result = sigs[i].fast_aggregate_verify(
            false,
            &msgs[i],
            dst,
            &pks_refs_i,
        );

        let duration4 = now4.elapsed();

        println!("Time elapsed in fast_aggregate_verify is: {:?}", duration4);

        assert_eq!(result, BLST_ERROR::BLST_SUCCESS);

        let now5 = Instant::now();

        let agg_pk_i =
            match AggregatePublicKey::aggregate(&pks_refs_i, false)
                {
                    Ok(agg_pk_i) => agg_pk_i,
                    Err(err) => panic!("aggregate failure: {:?}", err),
                };

        let duration5 = now5.elapsed();

        println!("Time elapsed in AggregatePublicKey::aggregate is: {:?}", duration5);

        pks.push(agg_pk_i.to_public_key());

        let now6 = Instant::now();

        // Test current aggregate signature with aggregated pks
        result = sigs[i].fast_aggregate_verify_pre_aggregated(
            false, &msgs[i], dst, &pks[i],
        );

        let duration6 = now6.elapsed();

        println!("Time elapsed in fast_aggregate_verify_pre_aggregated is: {:?}", duration6);

        assert_eq!(result, BLST_ERROR::BLST_SUCCESS);
        println!("=========================================================");
    }

    let msgs_refs: Vec<&[u8]> =
        msgs.iter().map(|m| m.as_slice()).collect();
    let sig_refs =
        sigs.iter().map(|s| s).collect::<Vec<&Signature>>();
    let pks_refs: Vec<&PublicKey> =
        pks.iter().map(|pk| pk).collect();


    let now7 = Instant::now();

    let mut result =
        Signature::verify_multiple_aggregate_signatures(
            &msgs_refs, dst, &pks_refs, false, &sig_refs, true,
            &rands, 64,
        );

    let duration7 = now7.elapsed();

    //assert_eq!(result, BLST_ERROR::BLST_SUCCESS);

    println!("Time elapsed in verify_multiple_aggregate_signatures is: {:?}", duration7);


    println!("===========================================================");
    println!("===========================================================");

    println!("Test aggregation BLS sign/verify (for multiple message)...");

    println!("===========================================================");
    //Here we test case when we sign n messages by n keypairs respectively.
    //Then we aggregate signatures for n message on different keys.
    //And we aggregate all public keys.
    //Then we verify aggregated signature by aggregated public key.

    let num_msgs = 500;

    let sks: Vec<_> =
        (0..num_msgs).map(|_| gen_random_key()).collect();
    let pks =
        sks.iter().map(|sk| sk.sk_to_pk()).collect::<Vec<_>>();
    let pks_refs: Vec<&PublicKey> =
        pks.iter().map(|pk| pk).collect();

    let pk_comp = pks[0].compress();
    let pk_uncomp = PublicKey::uncompress(&pk_comp);
    assert_eq!(pk_uncomp.is_ok(), true);

    let mut msgs: Vec<Vec<u8>> = vec![vec![]; num_msgs];
    for i in 0..num_msgs {
        let msg_len = (rng.next_u64() & 0x3F) + 1;
        msgs[i] = vec![0u8; msg_len as usize];
        rng.fill_bytes(&mut msgs[i]);
    }

    let msgs_refs: Vec<&[u8]> =
        msgs.iter().map(|m| m.as_slice()).collect();

    let sigs = sks
        .iter()
        .zip(msgs.iter())
        .map(|(sk, m)| (sk.sign(m, dst, &[])))
        .collect::<Vec<Signature>>();

    let mut errs = sigs
        .iter()
        .zip(msgs.iter())
        .zip(pks.iter())
        .map(|((s, m), pk)| (s.verify(true, m, dst, &[], pk, true)))
        .collect::<Vec<BLST_ERROR>>();
    assert_eq!(errs, vec![BLST_ERROR::BLST_SUCCESS; num_msgs]);

    let sig_refs =
        sigs.iter().map(|s| s).collect::<Vec<&Signature>>();


    let now8 = Instant::now();

    let agg = match AggregateSignature::aggregate(&sig_refs, true) {
        Ok(agg) => agg,
        Err(err) => panic!("aggregate failure: {:?}", err),
    };

    let duration8 = now8.elapsed();

    println!("Time elapsed in aggregate is: {:?}", duration8);

    let agg_sig = agg.to_signature();

    let now9 = Instant::now();

    let mut result = agg_sig
        .aggregate_verify(false, &msgs_refs, dst, &pks_refs, false);

    let duration9 = now9.elapsed();

    println!("Time elapsed in aggregate_verify is: {:?}", duration9);

    assert_eq!(result, BLST_ERROR::BLST_SUCCESS);



}
