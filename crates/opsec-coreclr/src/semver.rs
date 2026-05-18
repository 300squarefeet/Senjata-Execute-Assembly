//! Semver comparison helper — platform-independent.

/// Compare two semver strings ("8.0.4" vs "8.0.10") numerically per-segment.
pub fn semver_cmp(a: &str, b: &str) -> core::cmp::Ordering {
    let mut ai = a.split('.');
    let mut bi = b.split('.');
    loop {
        let (ax, bx) = (ai.next(), bi.next());
        match (ax, bx) {
            (None, None) => return core::cmp::Ordering::Equal,
            (None, Some(_)) => return core::cmp::Ordering::Less,
            (Some(_), None) => return core::cmp::Ordering::Greater,
            (Some(x), Some(y)) => {
                let ax: u32 = x.parse().unwrap_or(0);
                let by: u32 = y.parse().unwrap_or(0);
                match ax.cmp(&by) {
                    core::cmp::Ordering::Equal => continue,
                    other => return other,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::semver_cmp;
    use core::cmp::Ordering;

    #[test]
    fn major_dominates() {
        assert_eq!(semver_cmp("8.0.0", "7.99.99"), Ordering::Greater);
    }

    #[test]
    fn patch_numeric_not_lexical() {
        // The whole point: "8.0.10" must beat "8.0.4" despite being shorter lex.
        assert_eq!(semver_cmp("8.0.10", "8.0.4"), Ordering::Greater);
    }

    #[test]
    fn equal_strings() {
        assert_eq!(semver_cmp("6.0.27", "6.0.27"), Ordering::Equal);
    }

    #[test]
    fn missing_segment_is_zero() {
        assert_eq!(semver_cmp("8.0", "8.0.0"), Ordering::Less);
    }
}
