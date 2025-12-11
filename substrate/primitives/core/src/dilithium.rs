use crate::crypto::{
    CryptoType, CryptoTypeId, DeriveError, DeriveJunction, Pair as TraitPair,
    PublicBytes, SignatureBytes, SecretStringError,
};
use alloc::vec::Vec;
use qp_rusty_crystals_dilithium::ml_dsa_87;

// Constants based on ml-dsa-87
pub const PUBLIC_KEY_LEN: usize = 2592;
pub const SIGNATURE_LEN: usize = 4627;
pub const SEED_LEN: usize = 32;

/// Identifier used to match public keys against Dilithium keys
pub const CRYPTO_ID: CryptoTypeId = CryptoTypeId(*b"dil1");

#[doc(hidden)]
pub struct DilithiumPublicTag;
#[doc(hidden)]
pub struct DilithiumSignatureTag;

/// Public key type (fixed-length bytes like other crypto modules)
pub type Public = PublicBytes<PUBLIC_KEY_LEN, DilithiumPublicTag>;

/// Signature type
pub type Signature = SignatureBytes<SIGNATURE_LEN, DilithiumSignatureTag>;

/// Seed type for keypair generation
type Seed = [u8; SEED_LEN];

/// Keypair wrapper
#[derive(Clone)]
pub struct Pair {
    inner: ml_dsa_87::Keypair,
}

impl TraitPair for Pair {
    type Public = Public;
    type Seed = Seed;
    type Signature = Signature;
    type ProofOfPossession = Signature;

    /// Get the public key.
    fn public(&self) -> Public {
        Public::from_raw(self.inner.public.to_bytes())
    }

    /// Create a keypair from a seed slice.
    fn from_seed_slice(seed: &[u8]) -> Result<Pair, SecretStringError> {
        if seed.len() != SEED_LEN {
            return Err(SecretStringError::InvalidSeedLength);
        }
        Ok(Pair {
            inner: ml_dsa_87::Keypair::generate(seed),
        })
    }

    /// No HD derivation for now — just return self.
    fn derive<Iter: Iterator<Item = DeriveJunction>>(
        &self,
        _path: Iter,
        _seed: Option<Seed>,
    ) -> Result<(Pair, Option<Seed>), DeriveError> {
        Ok((self.clone(), None))
    }

    /// Sign a message.
    #[cfg(feature = "full_crypto")]
    fn sign(&self, message: &[u8]) -> Signature {
        let sig = self.inner.sign(message, None, None); // [u8; SIGNATURE_LEN]
        Signature::from_raw(sig)
    }

    /// Verify a signature.
    fn verify<M: AsRef<[u8]>>(sig: &Signature, message: M, pubkey: &Public) -> bool {
        let pk = match ml_dsa_87::PublicKey::from_bytes(pubkey.as_ref()) {
            Ok(pk) => pk,
            Err(_) => return false,
        };
        pk.verify(message.as_ref(), sig.as_ref(), None)
    }

    /// Export raw secret key bytes.
    fn to_raw_vec(&self) -> Vec<u8> {
        self.inner.secret.to_bytes().to_vec()
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

// Verify a Dilithium signature against a message and public key.
pub fn verify_signature<M: AsRef<[u8]>>(
    sig: &Signature,
    message: M,
    pubkey: &Public,
) -> bool {
    match ml_dsa_87::PublicKey::from_bytes(pubkey.as_ref()) {
        Ok(pk) => pk.verify(message.as_ref(), sig.as_ref(), None),
        Err(_) => false,
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Pair as TraitPair;

    #[test]
    fn dilithium_sign_and_verify() {
        // Deterministic seed → deterministic keypair
        let seed: Seed = *b"12345678901234567890123456789012";
        let pair = Pair::from_seed(&seed);
        let public = pair.public();
        let message = b"Test Dilithium message";

        #[cfg(feature = "full_crypto")]
        {
            // 1) Sign message
            let sig = pair.sign(message);

            // 2) Verify valid signature
            assert!(
                Pair::verify(&sig, message, &public),
                "Dilithium verification must succeed for a valid signature"
            );

            // 3) Tamper signature → must fail
            let mut bad = sig.clone();
            bad.0[0] ^= 0x01;

            assert!(
                !Pair::verify(&bad, message, &public),
                "Dilithium verification must fail for a tampered signature"
            );
        }
    }
}
