//! Port ranges for port hopping. Port of `extras/utils/portunion.go`.
//!
//! Parses the link's port spec — `"443"`, `"1000-2000"`, `"1000,2000-3000"`,
//! `"all"`/`"*"` — into a normalized set of inclusive ranges, and expands it to
//! the concrete port list the hopping socket rotates through. Invalid input
//! yields `None` (Go returns `nil`).

/// An inclusive port range `[start, end]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

/// A normalized collection of port ranges (sorted, non-overlapping).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortUnion(Vec<PortRange>);

/// Parse comma-separated ports/ranges into a normalized [`PortUnion`], or `None`
/// if the input is invalid.
#[must_use]
pub fn parse_port_union(s: &str) -> Option<PortUnion> {
    if s == "all" || s == "*" {
        // Wildcard special case.
        return Some(PortUnion(vec![PortRange {
            start: 0,
            end: 65535,
        }]));
    }
    let mut result = Vec::new();
    for part in s.split(',') {
        if part.contains('-') {
            // Port range: exactly two endpoints.
            let mut bounds = part.split('-');
            let (Some(a), Some(b), None) = (bounds.next(), bounds.next(), bounds.next()) else {
                return None;
            };
            let mut start: u16 = a.parse().ok()?;
            let mut end: u16 = b.parse().ok()?;
            if start > end {
                std::mem::swap(&mut start, &mut end);
            }
            result.push(PortRange { start, end });
        } else {
            // Single port.
            let port: u16 = part.parse().ok()?;
            result.push(PortRange {
                start: port,
                end: port,
            });
        }
    }
    if result.is_empty() {
        return None;
    }
    Some(normalize(result))
}

/// Sort and merge overlapping/adjacent ranges (low to high).
fn normalize(mut ranges: Vec<PortRange>) -> PortUnion {
    ranges.sort_by_key(|r| (r.start, r.end));
    let mut normalized: Vec<PortRange> = Vec::with_capacity(ranges.len());
    for current in ranges {
        match normalized.last_mut() {
            // +1 in u32 so a range ending at 65535 doesn't overflow.
            Some(last) if u32::from(current.start) <= u32::from(last.end) + 1 => {
                if current.end > last.end {
                    last.end = current.end;
                }
            },
            _ => normalized.push(current),
        }
    }
    PortUnion(normalized)
}

impl PortUnion {
    /// The concrete list of ports, in range order.
    #[must_use]
    pub fn ports(&self) -> Vec<u16> {
        let mut ports = Vec::new();
        for range in &self.0 {
            // RangeInclusive<u16> terminates correctly even at 65535.
            for port in range.start..=range.end {
                ports.push(port);
            }
        }
        ports
    }

    /// Whether `port` falls in any range.
    #[must_use]
    pub fn contains(&self, port: u16) -> bool {
        self.0.iter().any(|r| r.start <= port && port <= r.end)
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    fn union(ranges: &[(u16, u16)]) -> PortUnion {
        PortUnion(
            ranges
                .iter()
                .map(|&(start, end)| PortRange { start, end })
                .collect(),
        )
    }

    // (input, expected ranges) — aliased for clippy's type_complexity threshold.
    type ParseCase = (&'static str, &'static [(u16, u16)]);

    // Port of TestParsePortUnion.
    #[test]
    fn parse_cases() {
        let valid: &[ParseCase] = &[
            ("all", &[(0, 65535)]),
            ("*", &[(0, 65535)]),
            ("1234", &[(1234, 1234)]),
            (
                "5678,1234,9012",
                &[(1234, 1234), (5678, 5678), (9012, 9012)],
            ),
            ("1234-1240", &[(1234, 1240)]),
            ("1240-1234", &[(1234, 1240)]),
            (
                "5678,1200-1236,9100-9012,1234-1240",
                &[(1200, 1240), (5678, 5678), (9012, 9100)],
            ),
            (
                "5678,1200-1236,65531-65535,65532-65534,9100-9012,1234-1240",
                &[(1200, 1240), (5678, 5678), (9012, 9100), (65531, 65535)],
            ),
            (
                "5678,1200-1236,65532-65535,65531-65534,9100-9012,1234-1240",
                &[(1200, 1240), (5678, 5678), (9012, 9100), (65531, 65535)],
            ),
        ];
        for (input, want) in valid {
            assert_eq!(parse_port_union(input), Some(union(want)), "parse {input}");
        }

        let invalid = [
            "",
            "1234-",
            "1234-ggez",
            "233,",
            "1234-1240-1250",
            "-,,",
            "http",
        ];
        for input in invalid {
            assert_eq!(parse_port_union(input), None, "reject {input}");
        }
    }

    // Port of TestPortUnion_Ports.
    #[test]
    fn ports_expansion() {
        assert_eq!(union(&[(1234, 1234)]).ports(), vec![1234], "single port");
        assert_eq!(
            union(&[(1234, 1236)]).ports(),
            vec![1234, 1235, 1236],
            "small range"
        );
        assert_eq!(
            union(&[(1234, 1236), (5678, 5680), (9000, 9002)]).ports(),
            vec![1234, 1235, 1236, 5678, 5679, 5680, 9000, 9001, 9002],
            "multiple ranges",
        );
        assert_eq!(
            union(&[(65535, 65535)]).ports(),
            vec![65535],
            "single 65535"
        );
        assert_eq!(
            union(&[(65530, 65535)]).ports(),
            vec![65530, 65531, 65532, 65533, 65534, 65535],
            "range up to 65535 terminates",
        );
        assert_eq!(
            union(&[(65530, 65535), (1234, 1236)]).ports(),
            vec![65530, 65531, 65532, 65533, 65534, 65535, 1234, 1235, 1236],
            "multiple ranges incl. 65535 expand in given order",
        );
    }

    #[test]
    fn contains_checks_ranges() {
        let u = union(&[(1000, 2000), (3000, 3000)]);
        assert!(u.contains(1500), "in range");
        assert!(u.contains(3000), "single port in union");
        assert!(!u.contains(2500), "gap is excluded");
    }
}
