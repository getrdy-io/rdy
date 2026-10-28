//! Spans and the union merge (04 section 3.1, point 2).
//!
//! Every rule reports spans against the original text. This module merges overlapping or touching spans
//! into their union, so the output can be written once, no rule ever sees a placeholder, and no byte of a
//! partly overlapped span is left behind.

/// A byte range of the original text that one rule wants removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Span {
    /// First byte, inclusive.
    pub start: usize,
    /// One past the last byte.
    pub end: usize,
    /// The rule that found it. Rule names are `[a-z0-9_.]`.
    pub rule: &'static str,
    /// Higher wins when spans merge. See [`super::rules::priority`].
    pub priority: u8,
}

/// Merges overlapping or touching spans into one span covering their union.
///
/// The merged span is named after the highest priority rule in it. On a priority tie the span that starts
/// first (then the one that ends last, then the smaller rule name) wins, so the result does not depend on
/// the order the rules ran in. Empty spans are dropped. The caller rejects inverted ranges before this. The output is sorted and
/// disjoint, with a gap of at
/// least one byte between spans.
pub(crate) fn merge(mut spans: Vec<Span>) -> Vec<Span> {
    spans.retain(|s| s.start < s.end);
    spans.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then(b.end.cmp(&a.end))
            .then(b.priority.cmp(&a.priority))
            .then(a.rule.cmp(b.rule))
    });
    let mut out: Vec<Span> = Vec::with_capacity(spans.len());
    for next in spans {
        match out.last_mut() {
            Some(cur) if next.start <= cur.end => {
                cur.end = cur.end.max(next.end);
                if next.priority > cur.priority {
                    cur.priority = next.priority;
                    cur.rule = next.rule;
                }
            }
            _ => out.push(next),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn span(start: usize, end: usize, rule: &'static str, priority: u8) -> Span {
        Span {
            start,
            end,
            rule,
            priority,
        }
    }

    #[test]
    fn overlapping_spans_become_their_union() {
        let merged = merge(vec![span(2, 8, "low", 1), span(5, 12, "high", 9)]);
        assert_eq!(merged, vec![span(2, 12, "high", 9)]);
    }

    #[test]
    fn touching_spans_merge() {
        let merged = merge(vec![span(0, 4, "a", 1), span(4, 9, "b", 1)]);
        assert_eq!(merged.len(), 1);
        assert_eq!((merged[0].start, merged[0].end), (0, 9));
    }

    #[test]
    fn spans_with_a_gap_stay_apart() {
        let merged = merge(vec![span(5, 8, "b", 1), span(0, 4, "a", 1)]);
        assert_eq!(merged, vec![span(0, 4, "a", 1), span(5, 8, "b", 1)]);
    }

    #[test]
    fn a_contained_span_is_absorbed() {
        let merged = merge(vec![span(0, 20, "outer", 1), span(5, 8, "inner", 9)]);
        assert_eq!(merged, vec![span(0, 20, "inner", 9)]);
    }

    #[test]
    fn a_chain_of_overlaps_is_one_span() {
        let merged = merge(vec![
            span(0, 5, "a", 1),
            span(4, 9, "b", 2),
            span(8, 14, "c", 3),
        ]);
        assert_eq!(merged, vec![span(0, 14, "c", 3)]);
    }

    #[test]
    fn empty_spans_are_dropped() {
        assert!(merge(vec![span(3, 3, "a", 1)]).is_empty());
    }

    #[test]
    fn a_priority_tie_does_not_depend_on_input_order() {
        let one = merge(vec![span(0, 6, "zeta", 5), span(3, 9, "alpha", 5)]);
        let two = merge(vec![span(3, 9, "alpha", 5), span(0, 6, "zeta", 5)]);
        assert_eq!(one, two);
        assert_eq!(one[0].rule, "zeta");
    }
}
