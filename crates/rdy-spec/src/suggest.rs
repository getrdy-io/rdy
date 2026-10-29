//! Did-you-mean: the nearest known name for a mistyped one.
//!
//! One implementation serves the spec lint (a mistyped key or check id) and the command line (a mistyped
//! flag, `rdy-cli`), so both give the same advice for the same typo.

/// The candidate closest to `input`, when it is close enough to be a typo.
///
/// The distance counts one edit for an insert, a delete, a change or a swap of two neighbours (optimal
/// string alignment, counted in characters). The limit is one third of the length of `input`, at least 1
/// and at most 2 (07 section 1). An exact match is not a suggestion. On a tie the first candidate wins,
/// so the result does not depend on hashing.
///
/// Not part of the stable API; `rdy-cli` and the lint use it.
#[doc(hidden)]
#[must_use]
pub fn did_you_mean<'a>(input: &str, candidates: &[&'a str]) -> Option<&'a str> {
    let limit = (input.chars().count() / 3).clamp(1, 2);
    candidates
        .iter()
        .filter(|c| **c != input)
        .map(|c| (distance(input, c), *c))
        .filter(|(d, _)| *d <= limit)
        .min_by_key(|(d, _)| *d)
        .map(|(_, c)| c)
}

/// The optimal string alignment distance of two strings, counted in characters.
fn distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut rows = vec![vec![0usize; b.len() + 1]; a.len() + 1];
    for (i, row) in rows.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in rows[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=a.len() {
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let mut best = (rows[i - 1][j] + 1)
                .min(rows[i][j - 1] + 1)
                .min(rows[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                best = best.min(rows[i - 2][j - 2] + 1);
            }
            rows[i][j] = best;
        }
    }
    rows[a.len()][b.len()]
}

#[cfg(test)]
mod tests {
    use super::did_you_mean;

    #[test]
    fn finds_typos_and_ignores_the_rest() {
        let fields = ["min", "max", "path"];
        assert_eq!(did_you_mean("mn", &fields), Some("min"));
        let ids = ["host.memory", "host.disk", "net.dns"];
        assert_eq!(did_you_mean("host.memroy", &ids), Some("host.memory"));
        assert_eq!(did_you_mean("upload.now", &ids), None);
        assert_eq!(did_you_mean("host.memory", &ids), None);
        assert_eq!(did_you_mean("", &ids), None);
    }

    #[test]
    fn a_swap_of_neighbours_is_one_edit_and_the_limit_is_two() {
        assert_eq!(did_you_mean("metdata", &["metadata"]), Some("metadata"));
        assert_eq!(did_you_mean("prodcut", &["product"]), Some("product"));
        // Three edits away is not a typo.
        assert_eq!(did_you_mean("abcdefghi", &["abcdefxyz"]), None);
        assert_eq!(did_you_mean("abcdefghi", &["abcdefgxy"]), Some("abcdefgxy"));
    }

    #[test]
    fn a_tie_goes_to_the_first_candidate() {
        assert_eq!(did_you_mean("mix", &["max", "min"]), Some("max"));
    }
}
