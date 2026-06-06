//! `hysteria2://` share-link parsing and generation (PLAN §5 `config/`).
//!
//! Port of `app/cmd/client.go`'s `parseURI`/`URI`. App-side only: it turns an
//! untrusted link into a [`profile::Profile`] and back. The structural split is
//! hand-rolled (the reference forks Go's `net/url` because a standard parser
//! rejects the port-range host used for port hopping, e.g.
//! `host:7000-10000,20000`); percent-encoding and query (de)serialization are
//! delegated to `percent-encoding` and `form_urlencoded`.

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
        // obfs-password is only meaningful alongside an obfs type, as in Go.
        if let Some(obfs_type) = params.get("obfs") {
            profile.obfs = Some(Obfs {
                obfs_type: obfs_type.clone(),
                password: params.get("obfs-password").cloned().unwrap_or_default(),
            });
        }
        if let Some(sni) = params.get("sni") {
            profile.tls.sni.clone_from(sni);
        }
        if let Some(insecure) = params.get("insecure").and_then(|s| parse_bool(s)) {
            profile.tls.insecure = insecure;
        }
        if let Some(pin) = params.get("pinSHA256") {
            profile.tls.pin_sha256 = Some(pin.clone());
        }
    }
    Some(profile)
}

/// Generate the shareable `hysteria2://` link for a [`Profile`] (port of the
/// reference `URI`): only the connect-relevant fields, query keys sorted, the
/// cert pin normalized.
#[must_use]
pub fn to_uri(p: &Profile) -> String {
    // Keys appended alphabetically to match the reference (`url.Values.Encode`
    // sorts): insecure, obfs, obfs-password, pinSHA256, sni.
    let mut q = Serializer::new(String::new());
    if p.tls.insecure {
        q.append_pair("insecure", "1");
    }
    if let Some(obfs) = &p.obfs {
        q.append_pair("obfs", &obfs.obfs_type);
        q.append_pair("obfs-password", &obfs.password);
    }
    if let Some(pin) = &p.tls.pin_sha256 {
        q.append_pair("pinSHA256", &normalize_cert_hash(pin));
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
    format!("hysteria2://{userinfo}{server}/{query}", server = p.server)
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

/// Go's `strconv.ParseBool`: `None` on an unrecognized value (the reference
/// leaves `insecure` unchanged when parsing fails).
fn parse_bool(s: &str) -> Option<bool> {
    match s {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}

/// Lowercase and strip `:`/`-` separators (port of `normalizeCertHash`).
fn normalize_cert_hash(hash: &str) -> String {
    hash.to_lowercase().replace([':', '-'], "")
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use anyhow::anyhow;
    use pretty_assertions::assert_eq;
    use profile::Tls;

    use super::*;

    fn tls(sni: &str, insecure: bool, pin: Option<&str>) -> Tls {
        Tls {
            sni: sni.into(),
            insecure,
            pin_sha256: pin.map(Into::into),
            ca: None,
        }
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
                "hysteria2://noauth.com/?insecure=1&obfs=salamander&obfs-password=66ccff&pinSHA256=deadbeef&sni=crap.cc",
                Profile {
                    server: "noauth.com".into(),
                    auth: String::new(),
                    tls: tls("crap.cc", true, Some("deadbeef")),
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
    fn percent_encoded_auth_round_trips() -> Result<()> {
        // A space in the auth token must survive parse → generate.
        let p = parse_uri("hysteria2://a%20b@host:443/").ok_or_else(|| anyhow!("None"))?;
        assert_eq!(p.auth, "a b", "userinfo is percent-decoded");
        assert_eq!(to_uri(&p), "hysteria2://a%20b@host:443/", "auth re-encodes");
        Ok(())
    }
}
