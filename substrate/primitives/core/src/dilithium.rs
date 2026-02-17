use crate::crypto::{
    CryptoType, CryptoTypeId, DeriveError, DeriveJunction, Pair as TraitPair,
    PublicBytes, SignatureBytes, SecretStringError,
};
use alloc::vec::Vec;
use codec::Encode;

// Using qp_rusty_crystals_dilithium library
use qp_rusty_crystals_dilithium::ml_dsa_87;

/* Byte lengths based on ml-dsa-44
pub const PUBLIC_KEY_LEN: usize = ml_dsa_44::PUBLICKEYBYTES;
pub const SIGNATURE_LEN: usize = ml_dsa_44::SIGNBYTES;
pub const SEED_LEN: usize = 32; */

pub const PUBLIC_KEY_LEN: usize = ml_dsa_87::PUBLICKEYBYTES;
pub const SIGNATURE_LEN: usize = ml_dsa_87::SIGNBYTES;
pub const SEED_LEN: usize = 32;

// Identifier used to match public keys against Dilithium keys
pub const CRYPTO_ID: CryptoTypeId = CryptoTypeId(*b"dil1");

#[doc(hidden)]
pub struct DilithiumPublicTag;
#[doc(hidden)]
pub struct DilithiumSignatureTag;

// Public key type (fixed-length bytes like other crypto modules)
pub type Public = PublicBytes<PUBLIC_KEY_LEN, DilithiumPublicTag>;

// Signature type
pub type Signature = SignatureBytes<SIGNATURE_LEN, DilithiumSignatureTag>;

// The raw secret seed, which can be used to create the `Pair`.
// Seed is fixed-size array of bytes, each element is one byte (u8)
type Seed = [u8; SEED_LEN]; 

// Domain-separated hard-derivation step.
//
// Domain separation ("DilithiumHDKD") prevents cross-algorithm collisions.
// Hard derivation is seed-based, so it works for schemes without public derivation.
fn derive_hard_junction(secret_seed: &Seed, cc: &[u8; 32]) -> Seed {
    ("DilithiumHDKD", secret_seed, cc).using_encoded(sp_crypto_hashing::blake2_256)
}

// Dilithium key pair.
pub struct Pair {
    inner: ml_dsa_87::Keypair,
    seed: Seed,
}

// Implement Clone 
// Cloning a Pair means "same seed -> same keypair".
impl Clone for Pair {
    fn clone(&self) -> Self {
        Pair::from_seed(&self.seed)
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

        // Copy into a fixed-size array so we can retain it.
        let mut s = [0u8; SEED_LEN];
        s.copy_from_slice(seed);

        // The generator expects SensitiveBytes32; conversion may zeroize the source,
        // so feed it a disposable copy.
        let mut entropy = s;

        let inner = ml_dsa_87::Keypair::generate((&mut entropy).into());

        Ok(Pair {
            inner,
            seed: s,
        })
    }

    // Returns a derived key
    //
    // Soft junctions are rejected because Dilithium does not support public derivation.
    // Each hard junction updates the seed deterministically.
    fn derive<Iter: Iterator<Item = DeriveJunction>>(
        &self,
        path: Iter,
        _seed: Option<Seed>,
    ) -> Result<(Pair, Option<Seed>), DeriveError> {
        let mut acc = self.seed;

        for j in path {
            match j {
                DeriveJunction::Soft(_) => {
                    // Matches ed25519 behavior: cannot do soft derivation without scheme support.
                    return Err(DeriveError::SoftKeyInPath);
                }
                DeriveJunction::Hard(cc) => {
                    acc = derive_hard_junction(&acc, &cc);
                }
            }
        }

        Ok((Pair::from_seed(&acc), Some(acc)))
    }

    fn public(&self) -> Public {
        Public::from_raw(self.inner.public.to_bytes())
    }

    #[cfg(feature = "full_crypto")]
    fn sign(&self, message: &[u8]) -> Signature {
        let sig = self
            .inner
            .sign(message, None, None)
            .expect("ml_dsa_87 signing failed");
        Signature::from_raw(sig)

        /* ml_dsa_44
        let sig = self
            .inner
            .sign(message, None, false) // hedged: bool
            .expect("ml_dsa_44 signing returned None");
        Signature::from_raw(sig)
        */
    }

    fn verify<M: AsRef<[u8]>>(sig: &Signature, message: M, pubkey: &Public) -> bool {
        let pk = match ml_dsa_87::PublicKey::from_bytes(pubkey.as_ref()) {
            Ok(pk) => pk,
            Err(_) => return false,
        };
        pk.verify(message.as_ref(), sig.as_ref(), None)
    }

    /*
    fn verify<M: AsRef<[u8]>>(sig: &Signature, message: M, pubkey: &Public) -> bool {
        // pubkey is already fixed-size (PUBLICKEYBYTES) because PublicBytes<N> wraps [u8; N]
        let pk = ml_dsa_44::PublicKey::from_bytes(pubkey.as_ref());
        pk.verify(message.as_ref(), sig.as_ref(), None)
    }*/


    // Return a vec filled with raw data.
    // Substrate convention: export the SEED (re-creatable secret),
    fn to_raw_vec(&self) -> Vec<u8> {
        self.seed.to_vec()
    }
}

// Wire into CryptoType so SignatureBytes/PublicBytes get `verify` helpers etc.
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
    use crate::crypto::Pair as TraitPair;

    #[test]
    fn seed_pair_should_sign_and_verify() {
        let seed: Seed = *b"12345678901234567890123456789012";
        let pair = Pair::from_seed(&seed);
        let public = pair.public();
        let msg = b"Test Dilithium message";

        #[cfg(feature = "full_crypto")]
        {
            let sig = pair.sign(msg);
            // Uses the generic SignatureBytes::verify helper via CryptoType
            assert!(sig.verify(msg.as_slice(), &public));
        }
    }
}
