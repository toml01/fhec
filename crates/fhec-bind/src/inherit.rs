//! C3 linearization of contract inheritance, as Solidity performs it.
//!
//! Solidity linearizes with the C3 algorithm over the *reversed* base list: for
//! `contract C is A, B` the merge input is `[lin(B), lin(A), [B, A]]`, so `B` (the last
//! written base) is the most derived. See the Solidity docs on multiple inheritance.

use crate::ids::ContractId;
use solar_data_structures::map::FxHashMap;

/// Computes the C3 linearization for `id`, most-derived-first.
///
/// `bases` gives the *declared* (source-order) in-unit base list per contract.
/// Returns `None` on cycles or an inconsistent hierarchy.
pub(crate) fn c3_linearize(
    id: ContractId,
    bases: &FxHashMap<ContractId, Vec<ContractId>>,
) -> Option<Vec<ContractId>> {
    let mut memo: FxHashMap<ContractId, Option<Vec<ContractId>>> = FxHashMap::default();
    let mut in_progress: Vec<ContractId> = Vec::new();
    lin(id, bases, &mut memo, &mut in_progress)
}

fn lin(
    id: ContractId,
    bases: &FxHashMap<ContractId, Vec<ContractId>>,
    memo: &mut FxHashMap<ContractId, Option<Vec<ContractId>>>,
    in_progress: &mut Vec<ContractId>,
) -> Option<Vec<ContractId>> {
    if let Some(cached) = memo.get(&id) {
        return cached.clone();
    }
    if in_progress.contains(&id) {
        return None; // inheritance cycle
    }
    in_progress.push(id);

    let declared = bases.get(&id).cloned().unwrap_or_default();
    // Reverse: last written base is most derived.
    let reversed: Vec<ContractId> = declared.iter().rev().copied().collect();

    let mut sequences: Vec<Vec<ContractId>> = Vec::with_capacity(reversed.len() + 1);
    for &base in &reversed {
        sequences.push(lin(base, bases, memo, in_progress)?);
    }
    sequences.push(reversed);

    let merged = merge(sequences)?;
    let mut result = Vec::with_capacity(merged.len() + 1);
    result.push(id);
    result.extend(merged);

    in_progress.pop();
    memo.insert(id, Some(result.clone()));
    Some(result)
}

/// C3 merge: repeatedly take the first head that appears in no sequence tail.
fn merge(mut sequences: Vec<Vec<ContractId>>) -> Option<Vec<ContractId>> {
    let mut result = Vec::new();
    loop {
        sequences.retain(|s| !s.is_empty());
        if sequences.is_empty() {
            return Some(result);
        }
        let mut candidate = None;
        'outer: for seq in &sequences {
            let head = seq[0];
            for other in &sequences {
                if other.iter().skip(1).any(|&c| c == head) {
                    continue 'outer; // head is in a tail; not a valid candidate
                }
            }
            candidate = Some(head);
            break;
        }
        let head = candidate?; // no valid head: inconsistent hierarchy
        result.push(head);
        for seq in &mut sequences {
            seq.retain(|&c| c != head);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: usize) -> ContractId {
        ContractId::new(n)
    }

    #[test]
    fn diamond() {
        // A; B is A; C is A; D is B, C  =>  [D, C, B, A]
        let mut bases = FxHashMap::default();
        bases.insert(id(0), vec![]); // A
        bases.insert(id(1), vec![id(0)]); // B
        bases.insert(id(2), vec![id(0)]); // C
        bases.insert(id(3), vec![id(1), id(2)]); // D is B, C
        let lin = c3_linearize(id(3), &bases).unwrap();
        assert_eq!(lin, vec![id(3), id(2), id(1), id(0)]);
    }

    #[test]
    fn cycle_fails() {
        let mut bases = FxHashMap::default();
        bases.insert(id(0), vec![id(1)]);
        bases.insert(id(1), vec![id(0)]);
        assert!(c3_linearize(id(0), &bases).is_none());
    }

    #[test]
    fn inconsistent_fails() {
        // A; B; C is A, B; D is B, A; E is C, D  => inconsistent
        let mut bases = FxHashMap::default();
        bases.insert(id(0), vec![]); // A
        bases.insert(id(1), vec![]); // B
        bases.insert(id(2), vec![id(0), id(1)]); // C is A, B
        bases.insert(id(3), vec![id(1), id(0)]); // D is B, A
        bases.insert(id(4), vec![id(2), id(3)]); // E is C, D
        assert!(c3_linearize(id(4), &bases).is_none());
    }
}
