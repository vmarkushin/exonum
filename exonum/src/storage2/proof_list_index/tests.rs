use ::crypto::{Hash, hash};
use super::super::{Database, MemoryDB, StorageValue, pair_hash};
use super::{ProofListIndex, ListProof};

use self::ListProof::*;

// const KEY_SIZE: usize = 10;

// #[derive(Serialize)]
// struct ProofInfo<V: Serialize> {
//     root_hash: Hash,
//     list_length: usize,
//     proof: ListProof<V>,
//     range_st: usize,
//     range_end: usize,
// }

// fn random_values(len: usize) -> Vec<Vec<u8>> {
//     let mut rng = thread_rng();

//     let mut exists_keys = HashSet::new();

//     let kv_generator = |_| {
//         let mut new_val: Vec<u8> = vec![0; KEY_SIZE];
//         rng.fill_bytes(&mut new_val);

//         while exists_keys.contains(&new_val) {
//             rng.fill_bytes(&mut new_val);
//         }
//         exists_keys.insert(new_val.clone());
//         new_val
//     };

//     (0..len)
//         .map(kv_generator)
//         .collect::<Vec<_>>()
// }

#[test]
fn test_list_methods() {
    let mut fork = MemoryDB::new().fork();
    let mut index = ProofListIndex::new(vec![255], &mut fork);

    assert!(index.is_empty());
    assert_eq!(index.len(), 0);
    index.push(vec![1]);
    assert!(!index.is_empty());
    assert_eq!(index.len(), 1);

    index.push(vec![2]);
    assert_eq!(index.len(), 2);

    index.push(vec![3]);
    assert_eq!(index.len(), 3);

    assert_eq!(index.get(0), Some(vec![1]));
    assert_eq!(index.get(1), Some(vec![2]));
    assert_eq!(index.get(2), Some(vec![3]));
}

#[test]
fn test_height() {
    let mut fork = MemoryDB::new().fork();
    let mut index = ProofListIndex::new(vec![255], &mut fork);

    index.push(vec![1]);
    assert_eq!(index.height(), 1);

    index.push(vec![2]);
    assert_eq!(index.height(), 2);

    index.push(vec![3]);
    assert_eq!(index.height(), 3);

    index.push(vec![4]);
    assert_eq!(index.height(), 3);

    assert_eq!(index.len(), 4);
    assert_eq!(index.get(0), Some(vec![1]));
    assert_eq!(index.get(1), Some(vec![2]));
    assert_eq!(index.get(2), Some(vec![3]));
    assert_eq!(index.get(3), Some(vec![4]));

    index.set(1, vec![10]);
    assert_eq!(index.get(1), Some(vec![10]));
}

#[test]
fn test_list_index_proof() {
    let mut fork = MemoryDB::new().fork();
    let mut index = ProofListIndex::new(vec![255], &mut fork);

    let h0 = 2u64.hash();
    let h1 = 4u64.hash();
    let h2 = 6u64.hash();
    let h01 = pair_hash(&h0, &h1);
    let h22 = hash(h2.as_ref());
    let h012 = pair_hash(&h01, &h22);

    assert_eq!(index.root_hash(), Hash::default());

    index.push(2u64);

    assert_eq!(index.root_hash(), h0);
    assert_eq!(index.get_proof(0), Leaf(2));
    assert_eq!(index.get_proof(0).validate(index.root_hash(), index.len()).unwrap(), [(0, &2)]);

    index.push(4u64);
    assert_eq!(index.root_hash(), h01);
    assert_eq!(index.get_proof(0), Left(Box::new(Leaf(2)), Some(h1)));
    assert_eq!(index.get_proof(0).validate(index.root_hash(), index.len()).unwrap(), [(0, &2)]);
    assert_eq!(index.get_proof(1), Right(h0, Box::new(Leaf(4))));
    assert_eq!(index.get_proof(1).validate(index.root_hash(), index.len()).unwrap(), [(1, &4)]);

    assert_eq!(index.get_range_proof(0, 2), Full(Box::new(Leaf(2)), Box::new(Leaf(4))));
    assert_eq!(index.get_range_proof(0, 2).validate(index.root_hash(), index.len()).unwrap(), [(0, &2), (1, &4)]);

    index.push(6u64);
    assert_eq!(index.root_hash(), h012);
    assert_eq!(index.get_proof(0), Left(Box::new(Left(Box::new(Leaf(2)), Some(h1))), Some(h22)));
    assert_eq!(index.get_proof(0).validate(index.root_hash(), index.len()).unwrap(), [(0, &2)]);
    assert_eq!(index.get_proof(1), Left(Box::new(Right(h0, Box::new(Leaf(4)))), Some(h22)));
    assert_eq!(index.get_proof(1).validate(index.root_hash(), index.len()).unwrap(), [(1, &4)]);
    assert_eq!(index.get_proof(2), Right(h01, Box::new(Left(Box::new(Leaf(6)), None))));
    assert_eq!(index.get_proof(2).validate(index.root_hash(), index.len()).unwrap(), [(2, &6)]);


    assert_eq!(index.get_range_proof(0, 2), Left(Box::new(Full(Box::new(Leaf(2)), Box::new(Leaf(4)))), Some(h22)));
    assert_eq!(index.get_range_proof(0, 2).validate(index.root_hash(), index.len()).unwrap(), [(0, &2), (1, &4)]);

    assert_eq!(index.get_range_proof(1, 3), Full(Box::new(Right(h0, Box::new(Leaf(4)))),
                                                 Box::new(Left(Box::new(Leaf(6)), None))));
    assert_eq!(index.get_range_proof(1, 3).validate(index.root_hash(), index.len()).unwrap(), [(1, &4), (2, &6)]);

    assert_eq!(index.get_range_proof(0, 3), Full(Box::new(Full(Box::new(Leaf(2)), Box::new(Leaf(4)))),
                                                 Box::new(Left(Box::new(Leaf(6)), None))));
    assert_eq!(index.get_range_proof(0, 3).validate(index.root_hash(), index.len()).unwrap(), [(0, &2), (1, &4), (2, &6)]);
}

// #[test]
// fn generate_proof_in_index_containing_hashes() {
//     let mut fork = MemoryDB::new().fork();
//     let mut index = ProofListIndex::new(vec![255], &mut fork);
//     let num_vals = 10u32;
//     let values = random_values(num_vals as usize);
//     let hash_vals = values.into_iter().map(|el| hash(&el)).collect::<Vec<Hash>>();
//     for value in &hash_vals {
//         index.push(*value);
//     }
//     let mut index_root_hash = index.root_hash();
//     let mut index_len = index.len() as usize;
//     let st_r = 0;
//     let end_r = 5;
//     let range_proof = index.get_range_proof(st_r, end_r);
//     {
//         let (inds, actual_vals): (Vec<_>, Vec<&Hash>) =
//             proof_indices_values(&range_proof).into_iter().unzip();
//         assert_eq!(inds, (st_r as usize..end_r as usize).collect::<Vec<_>>());
//         let expect_vals = &hash_vals[st_r as usize..end_r as usize];
//         let paired = expect_vals.iter().zip(actual_vals);
//         for pair in paired {
//             assert_eq!(*pair.0, *pair.1);
//         }
//     }
// }

// #[test]
// fn randomly_generate_proofs() {
//     let mut fork = MemoryDB::new().fork();
//     let mut index = ProofListIndex::new(vec![255], &mut fork);
//     let num_vals = 100;
//     let values = random_values(num_vals as usize);
//     let mut rng = thread_rng();
//     for value in &values {
//         index.push(value.clone());
//     }
//     index.get(0);
//     let mut index_root_hash = index.root_hash();
//     let mut index_len = index.len() as usize;

//     for _ in 0..50 {
//         let start_range = rng.gen_range(0, num_vals);
//         let end_range = rng.gen_range(start_range + 1, num_vals + 1);
//         let range_proof = index.get_range_proof(start_range, end_range);
//         assert_eq!(range_proof.compute_proof_root(), index_root_hash);

//         {
//             let (inds, actual_vals): (Vec<_>, Vec<_>) =
//                 proof_indices_values(&range_proof).into_iter().unzip();
//             assert_eq!(inds,
//                        (start_range as usize..end_range as usize).collect::<Vec<_>>());
//             let expect_vals = &values[start_range as usize..end_range as usize];
//             let paired = expect_vals.iter().zip(actual_vals);
//             for pair in paired {
//                 assert_eq!(*pair.0, *pair.1);
//             }
//         }

//         let json_repre = serde_json::to_string(&range_proof);
//         let proof_info = ProofInfo {
//             root_hash: index_root_hash,
//             list_length: index_len,
//             proof: range_proof,
//             range_st: start_range as usize,
//             range_end: end_range as usize,
//         };
//         println!("{}", serde_json::to_string(&proof_info));

//         // println!("{}", json_repre);
//         let deser_proof: ListProof<Vec<u8>> = serde_json::from_str(&json_repre);
//         assert_eq!(proof_indices_values(&deser_proof).len(),
//                    (end_range - start_range) as usize);
//         assert_eq!(deser_proof.compute_proof_root(), index_root_hash);
//         // println!("{:?}", deser_proof);
//     }
// }

// #[test]
// fn test_index_and_proof_roots() {
//     let mut fork = MemoryDB::new().fork();
//     let mut index = ProofListIndex::new(vec![255], &mut fork);
//     assert_eq!(index.root_hash(), Hash::zero());

//     let h1 = hash(&[1, 2]);
//     let h2 = hash(&[2, 3]);
//     let h3 = hash(&[3, 4]);
//     let h4 = hash(&[4, 5]);
//     let h5 = hash(&[5, 6]);
//     let h6 = hash(&[6, 7]);
//     let h7 = hash(&[7, 8]);
//     let h8 = hash(&[8, 9]);

//     let h12 = hash(&[h1.as_ref(), h2.as_ref()].concat());
//     let h3up = hash(h3.as_ref());
//     let h123 = hash(&[h12.as_ref(), h3up.as_ref()].concat());

//     let h34 = hash(&[h3.as_ref(), h4.as_ref()].concat());
//     let h1234 = hash(&[h12.as_ref(), h34.as_ref()].concat());

//     let h5up = hash(h5.as_ref());
//     let h5upup = hash(h5up.as_ref());
//     let h12345 = hash(&[h1234.as_ref(), h5upup.as_ref()].concat());

//     let h56 = hash(&[h5.as_ref(), h6.as_ref()].concat());
//     let h56up = hash(h56.as_ref());
//     let h123456 = hash(&[h1234.as_ref(), h56up.as_ref()].concat());

//     let h7up = hash(h7.as_ref());
//     let h567 = hash(&[h56.as_ref(), h7up.as_ref()].concat());
//     let h1234567 = hash(&[h1234.as_ref(), h567.as_ref()].concat());

//     let h78 = hash(&[h7.as_ref(), h8.as_ref()].concat());
//     let h5678 = hash(&[h56.as_ref(), h78.as_ref()].concat());
//     let h12345678 = hash(&[h1234.as_ref(), h5678.as_ref()].concat());

//     let expected_hash_comb: Vec<(Vec<u8>, Hash, )> = vec![(vec![1, 2], h1, 0),
//                                                              (vec![2, 3], h12, 1),
//                                                              (vec![3, 4], h123, 2),
//                                                              (vec![4, 5], h1234, 3),
//                                                              (vec![5, 6], h12345, 4),
//                                                              (vec![6, 7], h123456, 5),
//                                                              (vec![7, 8], h1234567, 6),
//                                                              (vec![8, 9], h12345678, 7)];

//     for (inserted, exp_root, proof_ind) in expected_hash_comb {
//         index.push(inserted);
//         let mut index_len = index.len() as usize;

//         assert_eq!(index.root_hash(), exp_root);
//         let range_proof = index.get_range_proof(proof_ind, proof_ind + 1).validate(index.root_hash(), index.len()).unwrap();
//         assert_eq!(range_proof.len(), 1);

//         let json_repre = serde_json::to_string(&range_proof);
//         let deser_proof: ListProof<Vec<u8>> = serde_json::from_str(&json_repre);
//         assert_eq!(deser_proof.len(), 1);

//         let proof_info = ProofInfo {
//             root_hash: exp_root,
//             list_length: index_len,
//             proof: range_proof,
//             range_st: proof_ind as usize,
//             range_end: (proof_ind + 1) as usize,
//         };
//         println!("{}", serde_json::to_string(&proof_info));

//         let range_proof = index.get_range_proof(0, proof_ind + 1).validate(index.root_hash(), index.len()).unwrap();
//         assert_eq!(range_proof.len(),
//                    (proof_ind + 1) as usize);

//         let json_repre = serde_json::to_string(&range_proof);
//         let deser_proof: ListProof<Vec<u8>> = serde_json::from_str(&json_repre);
//         assert_eq!(deser_proof.len(),
//                    (proof_ind + 1) as usize);
//         let proof_info = ProofInfo {
//             root_hash: exp_root,
//             list_length: index_len,
//             proof: range_proof,
//             range_st: 0,
//             range_end: (proof_ind + 1) as usize,
//         };
//         println!("{}", serde_json::to_string(&proof_info));
//         let range_proof = index.get_range_proof(0, 1).validate(index.root_hash(), index.len()).unwrap();
//         assert_eq!(range_proof.len(), 1);

//         let json_repre = serde_json::to_string(&range_proof);
//         let deser_proof: ListProof<Vec<u8>> = serde_json::from_str(&json_repre);
//         assert_eq!(deser_proof.len(), 1);

//         let proof_info = ProofInfo {
//             root_hash: exp_root,
//             list_length: index_len,
//             proof: range_proof,
//             range_st: 0,
//             range_end: 1,
//         };
//         println!("{}", serde_json::to_string(&proof_info));
//     }

//     let range_proof = index.get_range_proof(0, 8).validate(index.root_hash(), index.len()).unwrap();
//     let (inds, val_refs): (Vec<_>, Vec<_>) =
//         range_proof.into_iter().unzip();
//     assert_eq!(inds, (0usize..8).collect::<Vec<_>>());
//     let expect_vals = vec![vec![1, 2], vec![2, 3], vec![3, 4], vec![4, 5], vec![5, 6],
//                            vec![6, 7], vec![7, 8], vec![8, 9]];
//     let paired = expect_vals.into_iter().zip(val_refs);
//     for pair in paired {
//         assert_eq!(pair.0, *pair.1);
//     }

//     let mut range_proof = index.get_range_proof(3, 5).validate(index.root_hash(), index.len()).unwrap();
//     assert_eq!(range_proof.len(), 2);
//     range_proof = index.get_range_proof(2, 6).validate(index.root_hash(), index.len()).unwrap();
//     assert_eq!(range_proof.len(), 4);
//     assert_eq!(index.get(0), Some(vec![1, 2]));
// }

#[test]
#[should_panic]
fn test_proof_illegal_lower_bound() {
    let mut fork = MemoryDB::new().fork();
    let mut index = ProofListIndex::new(vec![255], &mut fork);
    index.get_range_proof(0, 1);
    index.push(vec![1]);
}

#[test]
#[should_panic]
fn test_proof_illegal_bound_empty() {
    let mut fork = MemoryDB::new().fork();
    let mut index = ProofListIndex::new(vec![255], &mut fork);
    for i in 0u8..8 {
        index.push(vec![i]);
    }
    index.get_range_proof(8, 9);
}

#[test]
#[should_panic]
fn test_proof_illegal_range() {
    let mut fork = MemoryDB::new().fork();
    let mut index = ProofListIndex::new(vec![255], &mut fork);
    for i in 0u8..4 {
        index.push(vec![i]);
    }
    index.get_range_proof(2, 2);
}

// #[test]
// fn test_proof_structure() {
//     let mut fork = MemoryDB::new().fork();
//     let mut index = ProofListIndex::new(vec![255], &mut fork);
//     assert_eq!(index.root_hash(), Hash::zero());

//     let h1 = hash(&vec![0, 1, 2]);
//     let h2 = hash(&vec![1, 2, 3]);
//     let h3 = hash(&vec![2, 3, 4]);
//     let h4 = hash(&vec![3, 4, 5]);
//     let h5 = hash(&vec![4, 5, 6]);
//     let h12 = hash(&[h1.as_ref(), h2.as_ref()].concat());
//     let h34 = hash(&[h3.as_ref(), h4.as_ref()].concat());
//     let h1234 = hash(&[h12.as_ref(), h34.as_ref()].concat());
//     let h5up = hash(h5.as_ref());
//     let h5upup = hash(h5up.as_ref());
//     let h12345 = hash(&[h1234.as_ref(), h5upup.as_ref()].concat());

//     for i in 0u8...4 {
//         index.push(vec![i, i + 1, i + 2]);
//     }

//     assert_eq!(index.root_hash(), h12345);
//     let range_proof = index.get_range_proof(4, 5);
//     assert_eq!(range_proof.compute_proof_root(), h12345);

//     assert_eq!(vec![4, 5, 6], *(proof_indices_values(&range_proof)[0].1));
//     if let ListProof::Right(left_hash1, right_proof1) = range_proof {
//         assert_eq!(left_hash1, h1234);
//         let unboxed_proof = *right_proof1;
//         if let ListProof::Left(left_proof2, right_hash2) = unboxed_proof {
//             assert!(right_hash2.is_none());
//             let unboxed_proof = *left_proof2;
//             if let ListProof::Left(_, right_hash3) = unboxed_proof {
//                 assert!(right_hash3.is_none());
//             } else {
//                 assert!(false);
//             }
//         } else {
//             assert!(false);
//         }

//     } else {
//         assert!(false);
//     }
//     index.push(vec![5, 6, 7]);
// }

#[test]
fn test_simple_root_hash() {
    let h1 = hash(&[1]);
    let h2 = hash(&[2]);

    let mut fork = MemoryDB::new().fork();
    let mut index = ProofListIndex::new(vec![255], &mut fork);
    assert_eq!(index.get(0), None);
    index.push(vec![1]);
    assert_eq!(index.root_hash(), h1);

    index.set(0, vec![2]);
    assert_eq!(index.root_hash(), h2);
}

#[test]
fn test_same_root_hash() {
    let mut fork = MemoryDB::new().fork();
    let mut i1 = ProofListIndex::new(vec![255], &mut fork);
    i1.push(vec![1]);
    i1.push(vec![2]);
    i1.push(vec![3]);
    i1.push(vec![4]);

    i1.set(0, vec![4]);
    i1.set(1, vec![7]);
    i1.set(2, vec![5]);
    i1.set(3, vec![1]);

    let mut fork = MemoryDB::new().fork();
    let mut i2 = ProofListIndex::new(vec![255], &mut fork);
    i2.push(vec![4]);
    i2.push(vec![7]);
    i2.push(vec![5]);
    i2.push(vec![1]);

    assert_eq!(i1.root_hash(), i2.root_hash());
}
