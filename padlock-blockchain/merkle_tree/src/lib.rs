extern crate sha2;

#[cfg(feature = "serde_support")]
extern crate serde;

mod merkle_proof;

use std::convert::TryInto;

use blake2::{VarBlake2b, digest::{Update, VariableOutput}};

#[cfg(feature = "serde_support")]
use serde::{Deserialize, Serialize};

pub use merkle_proof::MerkleProof;

/// Creates a merkle tree based on some data represented as bytes in a Vec<u8> form.
///
/// It uses Sha256 truncated to 224 bits for it's hash function.
///
/// If a layer in the merkle tree has an uneven amount of nodes, the last node in the layer will be
/// cloned into the next layer. For example:
///
/// ```text
///     fde7a5c     567hb34
///     /     \        |
///    /       \       |
/// a64bh38 a2bd78f 567hb31
/// ```
///
/// The two leftmost hashes are hashed together, but the rightmost one doesn't have anything to be
/// hashed with, and so it is just carried over to the next layer.
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct MerkleTree {
    pub root: [u8; 28],
    layers: Vec<Layer>,
}

impl MerkleTree {
    pub fn new<T>(leafs: &[T]) -> Self 
    where
        Vec<u8>: From<T>,
        T: Clone,
    {
        let leafs: Vec<Vec<u8>> = convert_vec_type(leafs);

        let mut layers: Vec<Layer> = Vec::new();
        let first_layer = Layer::from_leafs(&leafs);
        layers.push(first_layer);

        for i in 0.. {
            let last_layer = &layers.last().unwrap().0;
            if last_layer.len() == 1 {
                break;
            }
            let layer = Layer::from_layer(&mut layers[i]);
            layers.push(layer);
        }

        MerkleTree {
            root: layers.last().unwrap().0[0].hash,
            layers,
        }
    }

    #[allow(unused_variables)]
    pub fn get_proof(&self, hash: [u8; 28]) -> Option<MerkleProof> {
        MerkleProof::new(hash, self)
    }
}

#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
struct Layer(Vec<Node>);

impl Layer {
    fn from_layer(layer: &mut Layer) -> Self {
        let mut nodes: Vec<Node> = Vec::new();

        for i in (0..layer.0.len()).step_by(2) {
            // If the last node doesn't have another node to be hashed with, it just carries the
            // node over to the next layer.
            if i + 1 >= layer.0.len() {
                let node_index = nodes.len();
                let node = Node::from_node(&layer.0[i], node_index);
                nodes.push(node);
                break;
            }

            let node =
                Node::from_nodes(&layer.0[i], &layer.0[i + 1], nodes.len());

            layer.0[i].set_parent_index(nodes.len());
            layer.0[i + 1].set_parent_index(nodes.len());

            nodes.push(node)
        }

        Layer(nodes)
    }

    fn from_leafs(leafs: &[Vec<u8>]) -> Self {
        let mut nodes: Vec<Node> = Vec::new();

        for (i, leaf) in leafs.iter().enumerate() {
            let hash = hash(leaf);
            let node = Node::from_hash(hash, i);
            nodes.push(node);
        }

        Layer(nodes)
    }
}

#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
struct Node {
    hash: [u8; 28],
    index: usize,
    left_child_index: usize,
    right_child_index: Option<usize>,
    parent_index: Option<usize>,
}

impl Node {
    fn from_node(node: &Node, index: usize) -> Self {
        Node {
            hash: node.hash,
            index,
            left_child_index: node.index,
            right_child_index: None,
            parent_index: None,
        }
    }

    fn from_hash(hash: [u8; 28], hash_index: usize) -> Self {
        Node {
            hash,
            index: hash_index,
            left_child_index: hash_index,
            right_child_index: None,
            parent_index: None,
        }
    }

    fn from_nodes(left_node: &Node, right_node: &Node, index: usize) -> Self {
        let to_hash = [left_node.hash, right_node.hash].concat();
        let hash = hash(&to_hash);

        Node {
            hash,
            index,
            left_child_index: left_node.index,
            right_child_index: Some(right_node.index),
            parent_index: None,
        }
    }

    fn set_parent_index(&mut self, index: usize) {
        self.parent_index = Some(index);
    }
}

fn convert_vec_type<T: Clone, A: From<T>>(
    vec: &[T],
) -> Vec<A> {
    let mut end_vec: Vec<A> = Vec::with_capacity(vec.len());

    for item in vec {
        let end_item: A = A::from(item.clone());
        end_vec.push(end_item);
    }
    end_vec
}

pub fn hash(data: &[u8]) -> [u8; 28] {
    let mut hasher = VarBlake2b::new(28).unwrap();
    hasher.update(data);
    hasher.finalize_boxed()[..].try_into().unwrap()
}
