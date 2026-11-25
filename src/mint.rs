//! One web login and one JNLP download, never retried automatically.
use crate::Result;
use quick_xml::{Reader, events::Event};
use reqwest::{Client, Url, header};
use std::time::Duration;

pub struct Tokens {
    pub user: String,
    pub pass: String,
    pub port: u16,
}

pub fn base_url(host: &str) -> Result<Url> {
    // Validate raw syntax before URL normalization can erase a port or path.
    let raw = if host.starts_with('[') && host.ends_with(']') {
        &host[1..host.len() - 1]
    } else {
        host
    };
    let ip = raw.parse::<std::net::IpAddr>().is_ok();
    let dns = !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    if !ip && !dns {
        return Err("--host must be a hostname or IP address, without URL/port/path".into());
    }
    let authority = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    let url = Url::parse(&format!("https://{authority}/"))?;
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || url.port().is_some()
    {
        return Err("--host must be a hostname or IP address, without URL/port/path".into());
    }
    Ok(url)
}

pub async fn mint(host: &str, user: &str, pass: &str) -> Result<Tokens> {
    let base = base_url(host)?;
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .user_agent("Mozilla/5.0 aten-vm/0.1")
        .build()?;
    let login = client
        .post(base.join("cgi/login.cgi")?)
        .header(header::COOKIE, "langSetFlag=0; language=English")
        .header(header::REFERER, base.as_str())
        .form(&[("name", user), ("pwd", pass)])
        .send()
        .await?;
    let sid = extract_sid(login.headers())?;
    let response = client
        .get(base.join("cgi/url_redirect.cgi?url_name=ikvm&url_type=jwsk")?)
        .header(
            header::COOKIE,
            format!("langSetFlag=0; language=English; SID={sid}"),
        )
        .send()
        .await?
        .error_for_status()?;
    // Bound untrusted XML rather than buffering arbitrary controller output.
    let mut response = response;
    let mut data = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if data.len() + chunk.len() > 256 * 1024 {
            return Err("JNLP response exceeds 256 KiB".into());
        }
        data.extend_from_slice(&chunk);
    }
    parse_jnlp(std::str::from_utf8(&data)?)
}

fn extract_sid(headers: &header::HeaderMap) -> Result<String> {
    // The BMC always emits two SID Set-Cookie headers on success: first a
    // clearing one ("SID=; expires=1970..."), then the real session SID.
    // Keep scanning: only fail if no non-empty SID was found at all.
    let mut found = None;
    for value in headers.get_all(header::SET_COOKIE) {
        let cookie = value.to_str()?.split(';').next().unwrap_or("").trim();
        if let Some(sid) = cookie.strip_prefix("SID=")
            && sid.len() == 15
            && sid
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        {
            found = Some(sid.to_owned());
        }
    }
    found.ok_or_else(|| "web login rejected: SID cleared/invalid (bad credentials or session rejection); not retrying".into())
}

fn parse_jnlp(xml: &str) -> Result<Tokens> {
    let mut reader = Reader::from_str(xml);
    let mut args = Vec::new();
    let mut is_jnlp = false;
    loop {
        match reader.read_event().map_err(|_| "malformed JNLP XML")? {
            Event::Start(e) if e.local_name().as_ref() == b"jnlp" => is_jnlp = true,
            Event::Start(e) if e.local_name().as_ref() == b"argument" => {
                let text = reader
                    .read_text(e.name())
                    .map_err(|_| "malformed JNLP argument")?;
                args.push(
                    quick_xml::escape::unescape(&text)
                        .map_err(|_| "invalid XML entity in JNLP argument")?
                        .into_owned(),
                );
            }
            Event::DocType(_) => return Err("unexpected DOCTYPE in JNLP".into()),
            Event::Eof => break,
            _ => {}
        }
    }
    if !is_jnlp || args.len() < 6 {
        return Err("mint failed: expected JNLP with at least six arguments".into());
    }
    crate::auth::validate_tokens(&args[1], &args[2])?;
    let port = args[5].parse::<u16>()?;
    if port == 0 {
        return Err("invalid zero vUSB port in JNLP".into());
    }
    Ok(Tokens {
        user: args[1].clone(),
        pass: args[2].clone(),
        port,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn literal_tokens_and_xml_entities() {
        let t = parse_jnlp("<jnlp><application-desc><argument>host</argument><argument>a/b+</argument><argument>tok==&amp;</argument><argument>x</argument><argument>5900</argument><argument>623</argument></application-desc></jnlp>").unwrap();
        assert_eq!(t.user, "a/b+");
        assert_eq!(t.pass, "tok==&");
        assert_eq!(t.port, 623);
        assert!(parse_jnlp("<html>login</html>").is_err());
    }
    #[test]
    fn malformed_xml_does_not_log_secrets() {
        let error = parse_jnlp("<jnlp><argument>&SECRET_TOKEN;</argument></jnlp>")
            .err()
            .unwrap();
        assert!(!error.to_string().contains("SECRET_TOKEN"));
        assert_eq!(error.to_string(), "invalid XML entity in JNLP argument");
    }
    #[test]
    fn login_cookie_validation() {
        let mut h = header::HeaderMap::new();
        assert!(extract_sid(&h).is_err());
        h.insert(header::SET_COOKIE, "SID=; path=/".parse().unwrap());
        assert!(extract_sid(&h).is_err());
        h.insert(
            header::SET_COOKIE,
            "SID=abc123def456ghi; path=/".parse().unwrap(),
        );
        assert_eq!(extract_sid(&h).unwrap(), "abc123def456ghi");
    }
    #[test]
    fn host_is_not_a_url() {
        assert!(base_url("172.31.224.254").is_ok());
        assert!(base_url("::1").is_ok());
        assert!(base_url("https://example.com").is_err());
        assert!(base_url("a@b").is_err());
        assert!(base_url("example.com/path").is_err());
        assert!(base_url("example.com/..").is_err());
        assert!(base_url("[::1]:443").is_err());
        assert!(base_url("[::1]").is_ok());
    }
}

#[cfg(test)]
mod regression {
    use super::*;

    #[test]
    fn cleared_then_real_sid_pair_from_bmc_is_accepted() {
        // Exact response shape observed from the BMC on successful login:
        // first a clearing Set-Cookie, then the real session SID.
        let mut h = header::HeaderMap::new();
        h.insert(
            header::SET_COOKIE,
            "SID=; expires=Thursday,01-Jan-1970 00:00:00 GMT; ;Secure; HttpOnly"
                .parse()
                .unwrap(),
        );
        h.append(
            header::SET_COOKIE,
            "SID=dyzivwbcoyfvuty; path=/ ; ;Secure; HttpOnly"
                .parse()
                .unwrap(),
        );
        assert_eq!(extract_sid(&h).unwrap(), "dyzivwbcoyfvuty");
    }

    #[test]
    fn only_cleared_sid_still_rejects() {
        let mut h = header::HeaderMap::new();
        h.insert(
            header::SET_COOKIE,
            "SID=; expires=Thursday,01-Jan-1970 00:00:00 GMT; ;Secure; HttpOnly"
                .parse()
                .unwrap(),
        );
        assert!(extract_sid(&h).is_err());
    }
}
