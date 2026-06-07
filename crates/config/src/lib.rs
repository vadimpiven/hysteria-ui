//! `hysteria2://` share-link parsing and generation.
//!
//! Port of `app/cmd/client.go`'s `parseURI`/`URI`: it turns an untrusted link
//! into a [`profile::Profile`] and back. The structural split is
//! hand-rolled (the reference forks Go's `net/url` because a standard parser
//! rejects the port-range host used for port hopping, e.g.
//! `host:7000-10000,20000`); percent-encoding and query (de)serialization are
//! delegated to `percent-encoding` and `form_urlencoded`.
//!
//! Beyond the Go port: the link's `#fragment` carries a human-readable display
//! name (the convention used by the Hysteria mobile apps / sing-box, which the
//! Go reference ignores). [`name_from_uri`] reads it on import and
//! [`to_uri_with_name`] emits it on share; the name is non-secret metadata, not
//! connection data, so it is kept out of [`profile::Profile`] (it lives in the
//! `store` crate's metadata).

use std::collections::HashMap;

use form_urlencoded::Serializer;
use percent_encoding::AsciiSet;
use percent_encoding::NON_ALPHANUMERIC;
use percent_encoding::percent_decode_str;
use percent_encoding::utf8_percent_encode;
use profile::Obfs;
use profile::Profile;

/// Characters kept unescaped in userinfo: the RFC 3986 unreserved set. Anything
/// else is percent-encoded; the `user:pass` separator is added outside this set.
const USERINFO: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// Parse a `hysteria2://` (or `hy2://`) link into a [`Profile`]. Returns `None`
/// if `s` is not such a link (a non-matching scheme, or no host), mirroring the
/// reference's "is this a URI?" boolean.
#[must_use]
pub fn parse_uri(s: &str) -> Option<Profile> {
    let (scheme, after) = s.split_once("://")?;
    if !scheme.eq_ignore_ascii_case("hysteria2") && !scheme.eq_ignore_ascii_case("hy2") {
        return None;
    }
    // Drop the fragment, then split the query off the authority(+path).
    let after = after.split('#').next().unwrap_or("");
    let (authority_path, query) = match after.split_once('?') {
        Some((ap, q)) => (ap, Some(q)),
        None => (after, None),
    };
    // The authority precedes the first '/'; the path is ignored.
    let authority = authority_path.split('/').next().unwrap_or("");
    // Userinfo precedes the last '@'; the remainder is host[:port-spec].
    let (auth, host) = match authority.rsplit_once('@') {
        Some((user, host)) => (percent_decode(user)?, host),
        None => (String::new(), authority),
    };
    if host.is_empty() {
        return None;
    }

    let mut profile = Profile {
        server: host.to_string(),
        auth,
        ..Profile::default()
    };
    if let Some(query) = query {
        let params = parse_query(query);
        // The reference reads `q.Get(...) != ""`, so an empty value is "absent".
        // obfs-password is only meaningful alongside an obfs type, as in Go.
        if let Some(obfs_type) = params.get("obfs").filter(|s| !s.is_empty()) {
            profile.obfs = Some(Obfs {
                obfs_type: obfs_type.clone(),
                password: params.get("obfs-password").cloned().unwrap_or_default(),
            });
        }
        if let Some(sni) = params.get("sni").filter(|s| !s.is_empty()) {
            profile.tls.sni.clone_from(sni);
        }
    }
    Some(profile)
}

/// Generate the shareable `hysteria2://` link for a [`Profile`] (port of the
/// reference `URI`): only the connect-relevant fields, query keys sorted, the
/// cert pin normalized. The connection-only canonical link, with no name
/// fragment; use [`to_uri_with_name`] for the share view.
#[must_use]
pub fn to_uri(p: &Profile) -> String {
    to_uri_with_name(p, None)
}

/// Like [`to_uri`], but appends the profile's display name as the link's
/// `#fragment` (percent-encoded) when `name` is non-empty, so a shared link
/// carries its name for re-import (see [`name_from_uri`]). The Go reference's
/// `URI` emits no fragment; the name is this client's convention, kept out of
/// [`Profile`] (it is non-secret metadata, not connection data).
#[must_use]
pub fn to_uri_with_name(p: &Profile, name: Option<&str>) -> String {
    // Keys appended alphabetically to match the reference (`url.Values.Encode`
    // sorts): obfs, obfs-password, sni.
    let mut q = Serializer::new(String::new());
    if let Some(obfs) = &p.obfs {
        q.append_pair("obfs", &obfs.obfs_type);
        q.append_pair("obfs-password", &obfs.password);
    }
    if !p.tls.sni.is_empty() {
        q.append_pair("sni", &p.tls.sni);
    }
    let query = q.finish();

    let userinfo = if p.auth.is_empty() {
        String::new()
    } else {
        format!("{}@", encode_userinfo(&p.auth))
    };
    let query = if query.is_empty() {
        String::new()
    } else {
        format!("?{query}")
    };
    let base = format!("hysteria2://{userinfo}{server}/{query}", server = p.server);
    match name.map(str::trim).filter(|n| !n.is_empty()) {
        Some(n) => format!("{base}#{}", encode_component(n)),
        None => base,
    }
}

/// Extract the display name from a `hysteria2://` link's `#fragment`
/// (percent-decoded), or `None` when the link is not a hysteria2 URI, has no
/// fragment, or the fragment is empty. The fragment-as-name is this client's
/// convention (as in the Hysteria mobile apps / sing-box); the Go reference's
/// `parseURI` ignores it. Trimming/host-fallback is the caller's policy (see
/// `store`), so this returns the fragment verbatim.
#[must_use]
pub fn name_from_uri(s: &str) -> Option<String> {
    let (scheme, after) = s.split_once("://")?;
    if !scheme.eq_ignore_ascii_case("hysteria2") && !scheme.eq_ignore_ascii_case("hy2") {
        return None;
    }
    let (_, fragment) = after.split_once('#')?;
    if fragment.is_empty() {
        return None;
    }
    percent_decode(fragment)
}

/// Percent-decode a userinfo component (Go's `QueryUnescape`).
fn percent_decode(s: &str) -> Option<String> {
    percent_decode_str(s)
        .decode_utf8()
        .ok()
        .map(std::borrow::Cow::into_owned)
}

/// Percent-encode userinfo, preserving the `user:pass` separator (Go splits on
/// the first colon and encodes each half).
fn encode_userinfo(auth: &str) -> String {
    match auth.split_once(':') {
        Some((user, pass)) => format!("{}:{}", encode_component(user), encode_component(pass)),
        None => encode_component(auth),
    }
}

fn encode_component(s: &str) -> String {
    utf8_percent_encode(s, USERINFO).to_string()
}

/// Parse a query string into a first-wins map (Go's `url.Values.Get` returns the
/// first value for a key).
fn parse_query(query: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for (k, v) in form_urlencoded::parse(query.as_bytes()) {
        map.entry(k.into_owned()).or_insert_with(|| v.into_owned());
    }
    map
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use anyhow::anyhow;
    use pretty_assertions::assert_eq;
    use profile::Tls;

    use super::*;

    fn tls(sni: &str) -> Tls {
        Tls { sni: sni.into() }
    }

    fn obfs(obfs_type: &str, password: &str) -> Option<Obfs> {
        Some(Obfs {
            obfs_type: obfs_type.into(),
            password: password.into(),
        })
    }

    /// Port of `TestClientConfigURI`: parse, and round-trip the link back.
    #[test]
    fn parse_and_generate_golden_corpus() -> Result<()> {
        let cases: &[(&str, Profile)] = &[
            (
                "hysteria2://god@zilla.jp/",
                Profile {
                    server: "zilla.jp".into(),
                    auth: "god".into(),
                    ..Profile::default()
                },
            ),
            (
                "hysteria2://john:wick@continental.org:4443/",
                Profile {
                    server: "continental.org:4443".into(),
                    auth: "john:wick".into(),
                    ..Profile::default()
                },
            ),
            (
                "hysteria2://saul@better.call:7000-10000,20000/",
                Profile {
                    server: "better.call:7000-10000,20000".into(),
                    auth: "saul".into(),
                    ..Profile::default()
                },
            ),
            (
                "hysteria2://noauth.com/?obfs=salamander&obfs-password=66ccff&sni=crap.cc",
                Profile {
                    server: "noauth.com".into(),
                    auth: String::new(),
                    tls: tls("crap.cc"),
                    obfs: obfs("salamander", "66ccff"),
                    fast_open: false,
                },
            ),
            (
                "hysteria2://pw@geckotown.com:8443/?obfs=gecko&obfs-password=hidden",
                Profile {
                    server: "geckotown.com:8443".into(),
                    auth: "pw".into(),
                    obfs: obfs("gecko", "hidden"),
                    ..Profile::default()
                },
            ),
        ];
        for (uri, want) in cases {
            let got = parse_uri(uri).ok_or_else(|| anyhow!("parse_uri returned None for {uri}"))?;
            assert_eq!(&got, want, "parse_uri({uri})");
            assert_eq!(&to_uri(want), uri, "to_uri round-trips {uri}");
        }
        Ok(())
    }

    #[test]
    fn non_hysteria_uris_are_rejected() {
        assert!(parse_uri("invalid.bs").is_none(), "bare string rejected");
        assert!(
            parse_uri("https://www.google.com/search?q=test").is_none(),
            "http(s) scheme rejected",
        );
        assert!(parse_uri("hysteria2://").is_none(), "empty host rejected");
    }

    #[test]
    fn hy2_alias_and_scheme_case_are_accepted() -> Result<()> {
        let a = parse_uri("hy2://god@zilla.jp/").ok_or_else(|| anyhow!("hy2 alias rejected"))?;
        let b = parse_uri("HYSTERIA2://god@zilla.jp/").ok_or_else(|| anyhow!("upper rejected"))?;
        assert_eq!(a.server, "zilla.jp", "hy2 alias parses host");
        assert_eq!(b.auth, "god", "uppercase scheme parses auth");
        Ok(())
    }

    #[test]
    fn empty_query_values_are_treated_as_absent() -> Result<()> {
        // The reference uses `q.Get(...) != ""`, so an empty value is "absent".
        let p = parse_uri("hysteria2://host:443/?obfs=&obfs-password=x&sni=")
            .ok_or_else(|| anyhow!("None"))?;
        assert!(p.obfs.is_none(), "empty obfs ignored");
        assert_eq!(p.tls.sni, "", "empty sni ignored");
        Ok(())
    }

    #[test]
    fn fragment_is_read_as_the_display_name() -> Result<()> {
        assert_eq!(
            name_from_uri("hysteria2://god@zilla.jp/#Home"),
            Some("Home".to_string()),
            "plain fragment is the name",
        );
        assert_eq!(
            name_from_uri("hysteria2://host:443/?sni=a#My%20VPN%20%F0%9F%9A%80"),
            Some("My VPN 🚀".to_string()),
            "fragment is percent-decoded (spaces + UTF-8) and survives a query",
        );
        assert_eq!(
            name_from_uri("hy2://god@zilla.jp/#JP"),
            Some("JP".to_string()),
            "hy2 alias carries a fragment too",
        );
        assert!(
            name_from_uri("hysteria2://god@zilla.jp/").is_none(),
            "no fragment means no name",
        );
        assert!(
            name_from_uri("hysteria2://god@zilla.jp/#").is_none(),
            "an empty fragment is not a name",
        );
        assert!(
            name_from_uri("https://example.com/#frag").is_none(),
            "a non-hysteria link yields no name",
        );

        // The connection parse still ignores the fragment.
        let p = parse_uri("hysteria2://god@zilla.jp/#Home").ok_or_else(|| anyhow!("None"))?;
        assert_eq!(p.server, "zilla.jp", "fragment does not leak into the host");
        assert_eq!(p.auth, "god", "fragment does not disturb auth");
        Ok(())
    }

    #[test]
    fn name_round_trips_through_a_share_link() -> Result<()> {
        let profile = Profile {
            server: "example.com:443".into(),
            auth: "tok".into(),
            ..Profile::default()
        };
        let link = to_uri_with_name(&profile, Some("My VPN 🚀"));
        assert!(
            link.ends_with("#My%20VPN%20%F0%9F%9A%80"),
            "share link appends the percent-encoded name fragment: {link}",
        );
        assert_eq!(
            name_from_uri(&link),
            Some("My VPN 🚀".to_string()),
            "the name round-trips back out of the shared link",
        );
        assert_eq!(
            parse_uri(&link).map(|p| p.server),
            Some("example.com:443".to_string()),
            "and the profile still parses from the same link",
        );

        // An empty/whitespace name emits no fragment (matches `to_uri`).
        assert_eq!(
            to_uri_with_name(&profile, Some("  ")),
            to_uri(&profile),
            "a blank name adds no fragment",
        );
        assert_eq!(
            to_uri_with_name(&profile, None),
            to_uri(&profile),
            "to_uri is to_uri_with_name(_, None)",
        );
        Ok(())
    }

    #[test]
    fn percent_encoded_auth_round_trips() -> Result<()> {
        // A space in the auth token must survive parse → generate.
        let p = parse_uri("hysteria2://a%20b@host:443/").ok_or_else(|| anyhow!("None"))?;
        assert_eq!(p.auth, "a b", "userinfo is percent-decoded");
        assert_eq!(to_uri(&p), "hysteria2://a%20b@host:443/", "auth re-encodes");
        Ok(())
    }
}
