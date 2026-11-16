use orvpass_core::sss::{recover_secret, split_secret};

#[test]
fn test_sss_split_and_reconstruct_threshold() {
    let secret = b"ORVPASS-ENTERPRISE-MASTER-KEY-2026";
    let k = 3;
    let n = 5;

    let shards = split_secret(secret, k, n);
    assert_eq!(shards.len(), n);

    // Any subset of k shards must recover the exact secret
    let subset1 = vec![shards[0].clone(), shards[1].clone(), shards[2].clone()];
    assert_eq!(recover_secret(&subset1).unwrap(), secret);

    let subset2 = vec![shards[1].clone(), shards[3].clone(), shards[4].clone()];
    assert_eq!(recover_secret(&subset2).unwrap(), secret);

    let subset3 = vec![shards[0].clone(), shards[2].clone(), shards[4].clone()];
    assert_eq!(recover_secret(&subset3).unwrap(), secret);

    // Fewer than k shards must fail
    let insufficient = vec![shards[0].clone(), shards[1].clone()];
    assert!(recover_secret(&insufficient).is_err());

    // Duplicate shards must not count as distinct
    let duplicates = vec![shards[0].clone(), shards[0].clone(), shards[1].clone()];
    assert!(recover_secret(&duplicates).is_err());
}
