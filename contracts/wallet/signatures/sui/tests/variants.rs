mod common;
use base64::{Engine, engine::general_purpose::STANDARD};
use common::{FixtureScheme, key, vectors, verify};
use defuse_wallet::State;
use defuse_wallet_sui::{
    SuiPublicKey,
    crypto::{ed25519::Ed25519, p256::P256, secp256k1::Secp256k1},
};
use near_sdk as _;

/// The contract variant of the scheme `C` against the valid keys and proofs of
/// the foreign scheme `F`.
fn check<C: FixtureScheme, F: FixtureScheme>() {
    let own = key::<C>(&vectors::<C>()[0]);

    for v in vectors::<F>() {
        let proof = v["proof"].as_str().unwrap();
        let foreign = key::<F>(&v);

        // A foreign key is not a key of this scheme.
        assert!(
            v["public_key"]
                .as_str()
                .unwrap()
                .parse::<SuiPublicKey<C>>()
                .is_err()
        );
        assert!(SuiPublicKey::<C>::from_sui_bytes(&foreign.to_sui_bytes()).is_err());

        // A foreign proof does not authorize the key of this scheme.
        assert!(!verify(&own, &v, proof));

        // `StateInit` accepts Borsh state directly, bypassing public-key
        // parsing. The state of a foreign key is readable by this variant only
        // if the keys have the same length, as the two ECDSA keys do.
        let state = borsh::to_vec(&State::new(foreign)).unwrap();
        let stored = borsh::from_slice::<State<SuiPublicKey<C>>>(&state);

        assert_eq!(
            stored.is_ok(),
            own.raw_bytes().len() == foreign.raw_bytes().len(),
            "{} in {}",
            F::NAME,
            C::NAME
        );

        let Ok(stored) = stored.map(|state| state.public_key) else {
            continue;
        };

        assert_eq!(stored.raw_bytes(), foreign.raw_bytes());

        // A valid foreign proof still fails for its own key placed in this
        // variant, also with the flag of this variant.
        assert!(!verify(&stored, &v, proof));

        let mut reflagged = STANDARD.decode(proof).unwrap();
        reflagged[0] = C::FLAG;

        assert!(!verify(&stored, &v, &STANDARD.encode(reflagged)));
    }
}

#[test]
fn each_schema_rejects_valid_proofs_and_keys_from_other_sui_schemes() {
    check::<Ed25519, Secp256k1>();
    check::<Ed25519, P256>();
    check::<Secp256k1, Ed25519>();
    check::<Secp256k1, P256>();
    check::<P256, Ed25519>();
    check::<P256, Secp256k1>();
}
