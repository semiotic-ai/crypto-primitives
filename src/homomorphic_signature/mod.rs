use crate::Error;
use ark_serialize::CanonicalSerialize;
use ark_std::hash::Hash;
use ark_std::rand::Rng;

pub mod ncs1;
pub trait HomomorphicSignatureScheme {
    type Parameters: Clone + Send + Sync;
    type PublicKey: CanonicalSerialize + Hash + Eq + Clone + Default + Send + Sync;
    type SecretKey: CanonicalSerialize + Clone + Default;
    type Signature: Clone + Default + Send + Sync;
    type Message: Clone + Default + Send + Sync;
    type Weight;

    // Create single g2 element and n g1
    fn setup<R: Rng>(rng: &mut R, n: usize) -> Result<Self::Parameters, Error>;

    fn keygen<R: Rng>(
        pp: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), Error>;

    fn sign(
        pp: &Self::Parameters,
        sk: &Self::SecretKey,
        tag: &[u8],
        index: &[u8],
        message: &[Self::Message],
        //rng: &mut R, TODO: Research if this makes sense to have per message randomness in HSS signing
    ) -> Result<Self::Signature, Error>;

    fn verify(
        pp: &Self::Parameters,
        pk: &Self::PublicKey,
        tag: &[u8],
        index: &[u8],
        message: &[Self::Message],
        signature: &Self::Signature,
    ) -> Result<bool, Error>;

    fn verify_aggregate(
        pp: &Self::Parameters,
        pk: &Self::PublicKey,
        tag: &[u8],
        message: &[Self::Message],
        weights: &[Self::Weight],
        signature: &Self::Signature,
    ) -> Result<bool, Error>;

    fn evaluate(
        signature: &[Self::Signature],
        weights: &[Self::Weight]
    ) -> Result<Self::Signature, Error>;
}

#[cfg(test)]
mod test {
    use crate::homomorphic_signature::{ncs1, *};
    use ark_ec::Group;
    use ark_bn254::Bn254 as Curve;
    use ark_std::{test_rng, vec::Vec, UniformRand};
    use blake2::Blake2s;

    fn single_sign_and_verify<S: HomomorphicSignatureScheme>(tag: &[u8], index: &[u8], message: &[S::Message]) {
        let rng = &mut test_rng();
        let n = message.len();
        let parameters = S::setup(rng, n).unwrap();
        let (pk, sk) = S::keygen(&parameters, rng).unwrap();
        let sig = S::sign(&parameters, &sk, tag, index, message).unwrap();

        assert!(S::verify(&parameters, &pk, tag, index, message, &sig).unwrap());
    }


    #[test]
    fn ncs1_signature_test() {
        let rng = &mut test_rng();
        let message = Curve::ScalarField::rand(rng);
        let tag: Vec<u8> = vec![rng.gen()];
        let index: Vec<u8> = vec![rng.gen()];
        single_sign_and_verify::<ncs1::NCS1<Curve, Blake2s>>(&tag, &index, message.as_bytes());
    }
}
