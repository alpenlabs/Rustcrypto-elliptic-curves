//! Taproot Schnorr verifying key.

use super::{tagged_hash, Signature, CHALLENGE_TAG};
use crate::{AffinePoint, FieldBytes, ProjectivePoint, PublicKey, Scalar};
use elliptic_curve::{
    bigint::U256,
    group::prime::PrimeCurveAffine,
    ops::{LinearCombination, Reduce},
    point::DecompactPoint,
};
use sha2::{
    digest::{consts::U32, FixedOutput},
    Digest, Sha256,
};
use signature::{hazmat::PrehashVerifier, DigestVerifier, Error, Result, Verifier};

#[cfg(feature = "serde")]
use serdect::serde::{de, ser, Deserialize, Serialize};

/// Taproot Schnorr verifying key.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct VerifyingKey {
    /// Inner public key
    pub(super) inner: PublicKey,
}

impl VerifyingKey {
    /// Borrow the inner [`AffinePoint`] this type wraps.
    pub fn as_affine(&self) -> &AffinePoint {
        self.inner.as_affine()
    }

    /// Serialize as bytes.
    pub fn to_bytes(&self) -> FieldBytes {
        self.as_affine().x.to_bytes()
    }

    /// Compute Schnorr signature.
    ///
    /// # ⚠️ Warning
    ///
    /// This is a low-level interface intended only for unusual use cases
    /// involving verifying pre-hashed messages, or "raw" messages where the
    /// message is not hashed at all prior to being used to generate the
    /// Schnorr signature.
    ///
    /// The preferred interfaces are the [`DigestVerifier`] or [`PrehashVerifier`] traits.
    pub fn verify_raw(
        &self,
        message: &[u8],
        signature: &Signature,
    ) -> core::result::Result<(), Error> {
        let (r, s) = signature.split();

        let e = <Scalar as Reduce<U256>>::reduce_bytes(
            &tagged_hash(CHALLENGE_TAG)
                .chain_update(signature.r.to_bytes())
                .chain_update(self.to_bytes())
                .chain_update(message)
                .finalize(),
        );

        #[cfg(all(target_os = "zkvm", target_vendor = "succinct"))]
        {
            use elliptic_curve::sec1::ToEncodedPoint;
            use sp1_lib::{
                secp256k1::Secp256k1Point as Sp1Secp256k1Point,
                unconstrained,
                utils::{AffinePoint as SP1AffinePoint, WeierstrassAffinePoint},
            };

            let s_bits = be_bytes_to_le_bits(s.to_bytes().as_ref());
            let neg_e_bits = be_bytes_to_le_bits(e.negate().to_bytes().as_ref());

            let encoded_pk = self.inner.to_encoded_point(false);
            let pk =
                <Sp1Secp256k1Point as SP1AffinePoint<16>>::from_le_bytes(encoded_pk.as_bytes());
            let generator = Sp1Secp256k1Point::new(Sp1Secp256k1Point::GENERATOR);

            let R =
                Sp1Secp256k1Point::multi_scalar_multiplication(&s_bits, generator, &neg_e_bits, pk);
            let r_bytes = R.to_le_bytes();

            if R.is_infinity() || r_bytes[32] % 2 == 0 || &r_bytes[0..32] != &r.to_bytes().to_vec()
            {
                return Err(Error::new());
            }

            return Ok(());
        }

        let R = ProjectivePoint::lincomb(
            &ProjectivePoint::GENERATOR,
            s,
            &self.inner.to_projective(),
            &-e,
        )
        .to_affine();

        if R.is_identity().into() || R.y.normalize().is_odd().into() || R.x.normalize() != *r {
            return Err(Error::new());
        }

        Ok(())
    }

    /// Parse verifying key from big endian-encoded x-coordinate.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let maybe_affine_point = AffinePoint::decompact(FieldBytes::from_slice(bytes));
        let affine_point = Option::from(maybe_affine_point).ok_or_else(Error::new)?;
        PublicKey::from_affine(affine_point)
            .map_err(|_| Error::new())?
            .try_into()
    }
}

//
// `*Verifier` trait impls
//

impl<D> DigestVerifier<D, Signature> for VerifyingKey
where
    D: Digest + FixedOutput<OutputSize = U32>,
{
    fn verify_digest(&self, digest: D, signature: &Signature) -> Result<()> {
        self.verify_prehash(digest.finalize_fixed().as_slice(), signature)
    }
}

impl PrehashVerifier<Signature> for VerifyingKey {
    fn verify_prehash(
        &self,
        prehash: &[u8],
        signature: &Signature,
    ) -> core::result::Result<(), Error> {
        self.verify_raw(prehash, signature)
    }
}

impl Verifier<Signature> for VerifyingKey {
    fn verify(&self, msg: &[u8], signature: &Signature) -> Result<()> {
        self.verify_digest(Sha256::new_with_prefix(msg), signature)
    }
}

//
// Other trait impls
//

impl From<VerifyingKey> for AffinePoint {
    fn from(vk: VerifyingKey) -> AffinePoint {
        *vk.as_affine()
    }
}

impl From<&VerifyingKey> for AffinePoint {
    fn from(vk: &VerifyingKey) -> AffinePoint {
        *vk.as_affine()
    }
}

impl From<VerifyingKey> for PublicKey {
    fn from(vk: VerifyingKey) -> PublicKey {
        vk.inner
    }
}

impl From<&VerifyingKey> for PublicKey {
    fn from(vk: &VerifyingKey) -> PublicKey {
        vk.inner
    }
}

impl TryFrom<PublicKey> for VerifyingKey {
    type Error = Error;

    fn try_from(public_key: PublicKey) -> Result<VerifyingKey> {
        if public_key.as_affine().y.normalize().is_even().into() {
            Ok(Self { inner: public_key })
        } else {
            Err(Error::new())
        }
    }
}

impl TryFrom<&PublicKey> for VerifyingKey {
    type Error = Error;

    fn try_from(public_key: &PublicKey) -> Result<VerifyingKey> {
        Self::try_from(*public_key)
    }
}

#[cfg(feature = "serde")]
impl Serialize for VerifyingKey {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        self.inner.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for VerifyingKey {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        VerifyingKey::try_from(PublicKey::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

/// Convert big-endian bytes with the most significant bit first to little-endian bytes with the least significant bit first.
///
/// [Ref](https://github.com/RustCrypto/signatures/compare/master...sp1-patches:signatures:ratan/patch-0.16.9-sp1-4.0.0-rc.3-v2#diff-9ca62a3b6caabf24ac0e8fc2b6e94dade6cd93dda5d0cb95a36f1ba9b7516d41R529-R542)
#[inline]
#[cfg(all(target_os = "zkvm", target_vendor = "succinct"))]
fn be_bytes_to_le_bits(be_bytes: &[u8; 32]) -> [bool; 256] {
    let mut bits = [false; 256];
    // Reverse the byte order to little-endian.
    for (i, &byte) in be_bytes.iter().rev().enumerate() {
        for j in 0..8 {
            // Flip the bit order so the least significant bit is now the first bit of the chunk.
            bits[i * 8 + j] = ((byte >> j) & 1) == 1;
        }
    }
    bits
}
