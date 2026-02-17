use crate::crypto::{
    CryptoType, CryptoTypeId, DeriveError, DeriveJunction, Pair as TraitPair, PublicBytes,
    SecretStringError, SignatureBytes,
};
use alloc::vec::Vec;
use codec::Encode;

use qp_rusty_crystals_dilithium::ml_dsa_44;

// Byte lengths based on ml-dsa-44
pub const PUBLIC_KEY_LEN: usize = ml_dsa_44::PUBLICKEYBYTES;
pub const SIGNATURE_LEN: usize = ml_dsa_44::SIGNBYTES;
pub const SEED_LEN: usize = 32;

pub const CRYPTO_ID: CryptoTypeId = CryptoTypeId(*b"dil1");

#[doc(hidden)]
pub struct DilithiumPublicTag;
#[doc(hidden)]
pub struct DilithiumSignatureTag;

pub type Public = PublicBytes<PUBLIC_KEY_LEN, DilithiumPublicTag>;
pub type Signature = SignatureBytes<SIGNATURE_LEN, DilithiumSignatureTag>;

type Seed = [u8; SEED_LEN];

fn derive_hard_junction(secret_seed: &Seed, cc: &[u8; 32]) -> Seed {
    ("DilithiumHDKD", secret_seed, cc).using_encoded(sp_crypto_hashing::blake2_256)
}

/// Runtime-compatible verification (works in no_std).
#[inline]
pub fn verify_signature<M: AsRef<[u8]>>(sig: &Signature, message: M, pubkey: &Public) -> bool {
    // qp 1.0.1 ml_dsa_44: PublicKey is available in no_std; Keypair/SecretKey are not.
    let pk = ml_dsa_44::PublicKey::from_bytes(pubkey.as_ref());
    pk.verify(message.as_ref(), sig.as_ref(), None)
}

/// Stub Pair.
///
/// In qp 1.0.1 with feature `no_std`, `ml_dsa_44::Keypair` is compiled out, so we cannot
/// implement signing/keygen here. This is OK for *runtime block verification*, which only
/// needs `verify_signature` above.
///
/// If you need host-side signing, do it in a std-enabled client crate (e.g. subxt signer).
pub struct Pair {
    seed: Seed,
}

impl Clone for Pair {
    fn clone(&self) -> Self {
        Pair { seed: self.seed }
    }
}

impl TraitPair for Pair {
    type Public = Public;
    type Seed = Seed;
    type Signature = Signature;
    type ProofOfPossession = Signature;

    fn from_seed_slice(seed: &[u8]) -> Result<Pair, SecretStringError> {
        if seed.len() != SEED_LEN {
            return Err(SecretStringError::InvalidSeedLength);
        }

        let mut s = [0u8; SEED_LEN];
        s.copy_from_slice(seed);

        // We cannot derive the public key without Keypair/SecretKey in qp 1.0.1 no_std.
        Ok(Pair { seed: s })
    }

    fn derive<Iter: Iterator<Item = DeriveJunction>>(
        &self,
        path: Iter,
        _seed: Option<Seed>,
    ) -> Result<(Pair, Option<Seed>), DeriveError> {
        let mut acc = self.seed;
        for j in path {
            match j {
                DeriveJunction::Soft(_) => return Err(DeriveError::SoftKeyInPath),
                DeriveJunction::Hard(cc) => acc = derive_hard_junction(&acc, &cc),
            }
        }
        Ok((Pair { seed: acc }, Some(acc)))
    }

    fn public(&self) -> Public {
        // Not usable for real signing in this configuration.
        // Returns a deterministic placeholder so code compiles; runtime verification does not call this.
        Public::from_raw([0u8; PUBLIC_KEY_LEN])
    }

    #[cfg(feature = "full_crypto")]
    fn sign(&self, _message: &[u8]) -> Signature {
        panic!("ml_dsa_44::Keypair is not available in qp 1.0.1 with feature `no_std`; signing must be done host-side with a std-enabled implementation");
    }

    fn verify<M: AsRef<[u8]>>(sig: &Signature, message: M, pubkey: &Public) -> bool {
        verify_signature(sig, message, pubkey)
    }

    fn to_raw_vec(&self) -> Vec<u8> {
        self.seed.to_vec()
    }
}

impl CryptoType for Public {
    type Pair = Pair;
}
impl CryptoType for Signature {
    type Pair = Pair;
}
impl CryptoType for Pair {
    type Pair = Pair;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_signature_compiles() {
        // This just checks the code compiles; actual runtime verification is tested by
        // submitting a Dilithium-signed extrinsic and seeing it included/finalized.
        let _ = (PUBLIC_KEY_LEN, SIGNATURE_LEN);
    }
}
