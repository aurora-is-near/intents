mod common;
use base64::{Engine, engine::general_purpose::STANDARD};
use common::{FixtureScheme, each_scheme, key, stored, vectors, verify};
use defuse_wallet_sui::{
    SuiPublicKey,
    crypto::{p256::P256, secp256k1::Secp256k1},
    protocol::personal_message_digest,
};
// Native NEAR host mocks are needed by the shared message formatter.
use near_sdk as _;

#[test]
fn sdk_addresses_hashes_and_native_intent_boundaries() {
    fn check<C: FixtureScheme>() {
        for v in vectors::<C>() {
            let key = key::<C>(&v);

            assert_eq!(key.address(), v["address"]);
            assert_eq!(key.to_string(), v["public_key"]);
            assert_eq!(serde_json::to_value(key).unwrap(), v["public_key"]);

            // The flag is in the native bytes, but not in the stored state.
            assert_eq!(key.to_sui_bytes(), [&[C::FLAG], key.raw_bytes()].concat());
            assert_eq!(borsh::to_vec(&key).unwrap(), key.raw_bytes());
            assert_eq!(stored::<C>(key.raw_bytes()), key);

            let message = v["message"].as_str().unwrap().as_bytes();

            assert_eq!(
                hex::encode(personal_message_digest(message).unwrap()),
                v["digest_hex"]
            );
            assert!(key.verify_personal_message(message, v["proof"].as_str().unwrap()));
            assert!(
                !key.verify_personal_message(message, v["transaction_proof"].as_str().unwrap())
            );

            if let Some(proof) = v["high_s_proof"].as_str() {
                assert!(!key.verify_personal_message(message, proof));
            }

            let mut changed = message.to_vec();
            changed.push(b' ');

            assert!(!key.verify_personal_message(&changed, v["proof"].as_str().unwrap()));
        }
    }

    each_scheme!(check);

    for v in common::fixture()["boundaries"].as_array().unwrap() {
        let message = vec![b'a'; usize::try_from(v["length"].as_u64().unwrap()).unwrap()];

        assert_eq!(
            hex::encode(personal_message_digest(&message).unwrap()),
            v["digest_hex"]
        );
    }
}

#[test]
fn malformed_native_envelopes_and_cross_purpose_proofs_fail() {
    fn check<C: FixtureScheme>() {
        for v in vectors::<C>() {
            let key = key::<C>(&v);
            let proof = v["proof"].as_str().unwrap();
            let original = STANDARD.decode(proof).unwrap();
            let message = v["message"].as_str().unwrap().as_bytes();
            let mut bad = vec![Vec::new(), original[..original.len() - 1].to_vec()];
            let mut longer = original.clone();

            longer.push(0);
            bad.push(longer);

            for flag in 0..=7 {
                if flag != C::FLAG {
                    let mut bytes = original.clone();
                    bytes[0] = flag;
                    bad.push(bytes);
                }
            }

            for index in [1, 32, 64, 65, original.len() - 1] {
                let mut bytes = original.clone();
                bytes[index] ^= 1;
                bad.push(bytes);
            }

            for bytes in bad {
                assert!(!key.verify_personal_message(message, &STANDARD.encode(bytes)));
            }

            assert!(!key.verify_personal_message(message, proof.trim_end_matches('=')));
            assert!(!key.verify_personal_message(message, &format!("{proof}\n")));

            // Every other flag is refused: unsupported schemes and the two other
            // supported ones alike.
            for flag in (0..=7).chain([255]).filter(|&flag| flag != C::FLAG) {
                let mut bytes = key.to_sui_bytes();
                bytes[0] = flag;

                assert!(SuiPublicKey::<C>::from_sui_bytes(&bytes).is_err());
            }

            assert!(!verify(&key, &v, v["transaction_proof"].as_str().unwrap()));
        }

        let raw_len = key::<C>(&vectors::<C>()[0]).raw_bytes().len();

        // Only the flag, a truncated key, an extended key and an invalid key.
        assert!(SuiPublicKey::<C>::from_sui_bytes(&[]).is_err());
        assert!(SuiPublicKey::<C>::from_sui_bytes(&[C::FLAG]).is_err());

        for len in [raw_len - 1, raw_len, raw_len + 1] {
            let bytes = [vec![C::FLAG], vec![0; len]].concat();

            assert!(SuiPublicKey::<C>::from_sui_bytes(&bytes).is_err());
        }
    }

    each_scheme!(check);
}

#[test]
fn malformed_proofs_never_authorize() {
    fn check<C: FixtureScheme>() {
        for v in vectors::<C>() {
            let key = key::<C>(&v);
            let message = v["message"].as_str().unwrap().as_bytes();

            for size in 0..220 {
                assert!(!key.verify_personal_message(message, &STANDARD.encode(vec![0; size])));
            }

            let original = STANDARD.decode(v["proof"].as_str().unwrap()).unwrap();

            for index in 0..original.len() {
                let mut mutated = original.clone();
                mutated[index] ^= 1;

                assert!(!key.verify_personal_message(message, &STANDARD.encode(mutated)));
            }
        }
    }

    each_scheme!(check);
}

#[test]
fn ecdsa_keys_require_native_compressed_sec1_tags() {
    fn check<C: FixtureScheme>() {
        for v in vectors::<C>() {
            let key = key::<C>(&v);

            for tag in 0..=u8::MAX {
                let mut bytes = key.to_sui_bytes();
                bytes[1] = tag;

                if matches!(tag, 2 | 3) {
                    assert!(SuiPublicKey::<C>::from_sui_bytes(&bytes).is_ok());
                } else {
                    assert!(
                        SuiPublicKey::<C>::from_sui_bytes(&bytes).is_err(),
                        "tag {tag}"
                    );
                    assert!(
                        format!("sui:{}", STANDARD.encode(&bytes))
                            .parse::<SuiPublicKey<C>>()
                            .is_err()
                    );

                    // Borsh state can bypass JSON parsing. Verification must still reject it.
                    let stored = stored::<C>(&bytes[1..]);
                    let mut proof = STANDARD.decode(v["proof"].as_str().unwrap()).unwrap();

                    proof[65] = tag;

                    // The proof embeds exactly the stored key, so only its tag rejects it.
                    assert_eq!(proof[65..], bytes[1..]);
                    assert!(!stored.verify_personal_message(
                        v["message"].as_str().unwrap().as_bytes(),
                        &STANDARD.encode(proof)
                    ));
                }
            }
        }
    }

    check::<Secp256k1>();
    check::<P256>();
}
