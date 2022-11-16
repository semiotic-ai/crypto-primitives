//NCS1
use crate::Error;
use ark_std::{marker::PhantomData, rand::Rng};
use digest::Digest;
use ark_ec::pairing::Pairing;
use crate::HomomorphicSignatureScheme;
use crate::ark_std::UniformRand;
use std::ops::MulAssign;
use ark_ec::AffineRepr;

pub struct NCS1<P: Pairing, D: Digest> {
    _pairing: PhantomData<P>,
    _hash: PhantomData<D>,
}

#[derive(Clone)]
pub struct NCS1Parameters<P: Pairing> {
    pub g1_generators: Vec<P::G1>,
    pub g2_generator: P::G2,
}

impl<P: Pairing, D: Digest + Send + Sync> HomomorphicSignatureScheme for NCS1<P,D> {
    type Parameters = NCS1Parameters<P>;
    type PublicKey = P::G2;
    type SecretKey = P::ScalarField;
    type Signature= P::G1;
    type Message = P::ScalarField;
    type Weight = P::ScalarField;

    // Create single g2  and n g1
    fn setup<R: Rng>(rng: &mut R, n: usize) -> Result<Self::Parameters, Error>{
        let g1_gens: Vec<P::G1> = (0..n).map(|_| P::G1::rand(rng)).collect();
        let g2_gen: P::G2 = P::G2::rand(rng);
        Ok(
            NCS1Parameters{
                g1_generators: g1_gens,
                g2_generator: g2_gen
            }
        )
    }

    fn keygen<R: Rng>(
        pp: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), Error>{
        let secret_key = P::ScalarField::rand(rng);
        let mut public_key = pp.g2_generator.clone();
        public_key.mul_assign(secret_key);

        Ok((
            public_key,
            secret_key
        ))
    }

    fn sign(
        pp: &Self::Parameters,
        sk: &Self::SecretKey,
        tag: &[u8],
        index: &[u8],
        message: &[Self::Message]
    ) -> Result<Self::Signature, Error>{
        assert!(pp.g1_generators.len() == message.len());
        let mut lane_data = tag.to_vec();
        lane_data.append(&mut index.to_vec());
        let lane_point = hash_to_g1::<P,D>(lane_data);

        let value_point: P::G1 =
            pp.g1_generators
            .iter()
            .zip(message.iter())
            .map(|(g1_gen, msg)| *g1_gen*msg)
            .sum();

        let message_point: P::G1 = lane_point + value_point;
        let signature = message_point.clone() * sk;
        Ok(signature)
    }

    //TODO: Need to define endianess of index to ensure verify aggregate uses same endianness
    fn verify(
        pp: &Self::Parameters,
        pk: &Self::PublicKey,
        tag: &[u8],
        index: &[u8],
        message: &[Self::Message],
        signature: &Self::Signature
    ) -> Result<bool, Error>{
        let lane_point = hash_to_g1::<P,D>([tag, index].concat());

        let message_point : P::G1 =
            pp.g1_generators
            .iter()
            .zip(message.iter())
            .map(|(g1_gen, msg)| *g1_gen*msg)
            .sum();

        let rhs_pairing = P::pairing(lane_point + message_point, pk);
        let lhs_pairing = P::pairing(signature, pp.g2_generator);
        Ok(lhs_pairing == rhs_pairing)

    }

    fn verify_aggregate(
        pp: &Self::Parameters,
        pk: &Self::PublicKey,
        tag: &[u8],
        message: &[Self::Message],
        weights: &[Self::Weight],
        signature: &Self::Signature,
    ) -> Result<bool, Error>{
        let aggregate_lane_point: P::G1 =
            weights
            .iter()
            .enumerate()
            .map(|(index, weight)| hash_to_g1::<P,D>([tag, &index.to_be_bytes()].concat()) * weight)
            .sum();

        let message_point : P::G1 =
            pp.g1_generators
            .iter()
            .zip(message.iter())
            .map(|(g1_gen, msg)| *g1_gen * msg)
            .sum();

        let rhs_pairing = P::pairing(aggregate_lane_point + message_point, pk);
        let lhs_pairing = P::pairing(signature, pp.g2_generator);
        Ok(lhs_pairing == rhs_pairing)
    }

    fn evaluate(
        signatures: &[Self::Signature],
        weights: &[Self::Weight]
    ) -> Result<Self::Signature, Error>{

        Ok( signatures
            .iter()
            .zip(weights.iter())
            .map(|(sig, weight)|*sig * weight)
            .sum()
        )
    }
}

fn hash_to_g1<P: Pairing, D: Digest> (message_data: Vec<u8>) -> P::G1Affine {
    let mut g1_point:Option<P::G1Affine> = None;
    let mut counter = 0;
    while g1_point.is_some() == false {
        let mut tmp_message = message_data.clone();
        tmp_message.push(counter);
        let hash_out = D::digest(&tmp_message);
        g1_point = P::G1Affine::from_random_bytes(&hash_out);
        counter += 1;
    }
    g1_point.unwrap()
}