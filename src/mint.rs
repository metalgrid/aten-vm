//! One web login and one JNLP download, never retried automatically.
//! `mint_html5` is the Insyde HTML5 fallback: login, the iKVM/HTML5 page, then
//! the bootstrap page's entry_value ticket (first 15 bytes = user token, the
//! rest = password token; live-captured from firmware 01.73.11).
use crate::Result;
use quick_xml::{Reader, events::Event};
use reqwest::{Client, Url, header};
use std::time::Duration;

pub struct Tokens {
    pub user: String,
    pub pass: String,
    pub port: u16,
    pub sid: String,
    /// Serve over the Insyde HTML5 WebSocket (`wss://host:port/vm`) instead of
    /// raw legacy vUSB TCP.
    pub html5: bool,
}

impl Tokens {
    pub fn legacy(user: String, pass: String, port: u16) -> Self {
        Self {
            user,
            pass,
            port,
            sid: String::new(),
            html5: false,
        }
    }
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

fn client(proxy: Option<&(String, u16)>) -> Result<Client> {
    let mut builder = Client::builder()
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .user_agent("Mozilla/5.0 aten-vm/0.1");
    if let Some((proxy_host, proxy_port)) = proxy {
        builder = builder.proxy(reqwest::Proxy::all(format!(
            "socks5://{proxy_host}:{proxy_port}"
        ))?);
    }
    Ok(builder.build()?)
}

/// Mint through the legacy Java/JNLP flow. Fails on firmwares with the Java
/// viewer disabled; callers fall back to `mint_html5`.
pub async fn mint(
    host: &str,
    user: &str,
    pass: &str,
    proxy: Option<&(String, u16)>,
) -> Result<Tokens> {
    let base = base_url(host)?;
    let client = client(proxy)?;
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
    parse_jnlp(std::str::from_utf8(&data)?, sid)
}

/// Try the legacy JNLP flow first, then the HTML5 flow once. Each flow makes
/// exactly one login+fetch pass; neither retries on failure.
pub async fn mint_auto(
    host: &str,
    user: &str,
    pass: &str,
    proxy: Option<&(String, u16)>,
    force_html5: bool,
) -> Result<Tokens> {
    if force_html5 {
        return mint_html5(host, user, pass, proxy).await;
    }
    match mint(host, user, pass, proxy).await {
        Ok(tokens) => Ok(tokens),
        Err(legacy_error) => {
            eprintln!("Legacy JNLP mint failed: {legacy_error}; trying the HTML5 path once");
            mint_html5(host, user, pass, proxy)
                .await
                .map_err(|html5_error| {
                    format!("both mint paths failed: legacy: {legacy_error}; html5: {html5_error}")
                        .into()
                })
        }
    }
}

/// Mint through the Insyde HTML5 flow for firmwares with the Java viewer
/// disabled: login, then visit the iKVM/HTML5 page and its bootstrap page,
/// and split the bootstrap `entry_value` ticket into vUSB tokens.
pub async fn mint_html5(
    host: &str,
    user: &str,
    pass: &str,
    proxy: Option<&(String, u16)>,
) -> Result<Tokens> {
    const LIMIT: usize = 256 * 1024;
    let base = base_url(host)?;
    let client = client(proxy)?;
    let login = client
        .post(base.join("cgi/login.cgi")?)
        .header(header::COOKIE, "langSetFlag=0; language=English")
        .header(header::REFERER, base.as_str())
        .form(&[("name", user), ("pwd", pass)])
        .send()
        .await?;
    let sid = extract_sid(login.headers())?;
    let cookie = format!("langSetFlag=0; language=English; SID={sid}");
    let ikvm = base.join("cgi/url_redirect.cgi?url_name=man_ikvm_html5")?;
    let page = client
        .get(ikvm.clone())
        .header(header::COOKIE, &cookie)
        .header(
            header::REFERER,
            base.join("cgi/url_redirect.cgi?url_name=topmenu")?.as_str(),
        )
        .send()
        .await?
        .error_for_status()?;
    let page = bounded_body(page, LIMIT).await?;
    let _csrf = extract_csrf(&page)?;
    let bootstrap = base.join("cgi/url_redirect.cgi?url_name=man_ikvm_html5_bootstrap")?;
    let page = client
        .get(bootstrap)
        .header(header::COOKIE, &cookie)
        .header(header::REFERER, ikvm.as_str())
        .send()
        .await?
        .error_for_status()?;
    let page = bounded_body(page, LIMIT).await?;
    let ticket = extract_entry_value(&page)?;
    // StoreVMInfoFromGUI: username is the first 15 ticket bytes and the
    // password token is the remainder (9 bytes on firmware 01.73.11).
    if ticket.len() < 16 || !ticket.is_ascii() {
        return Err("HTML5 entry_value ticket is too short or not ASCII".into());
    }
    let (user_token, pass_token) = ticket.split_at(15);
    crate::auth::validate_tokens(user_token, pass_token)?;
    Ok(Tokens {
        user: user_token.to_owned(),
        pass: pass_token.to_owned(),
        // The WebSocket rides the HTTPS port (bmc PORT_INFO VM_SERVICE path).
        port: 443,
        sid,
        html5: true,
    })
}

async fn bounded_body(response: reqwest::Response, limit: usize) -> Result<String> {
    let mut response = response;
    let mut data = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if data.len() + chunk.len() > limit {
            return Err("BMC page response exceeds 256 KiB".into());
        }
        data.extend_from_slice(&chunk);
    }
    Ok(String::from_utf8_lossy(&data).into_owned())
}

/// The bootstrap page embeds `SmcCsrfInsert("CSRF_TOKEN", "...")`; the value
/// is only needed for firmware pages that require it, so keep parsing strict.
fn extract_csrf(page: &str) -> Result<String> {
    // The bootstrap page embeds SmcCsrfInsert("CSRF_TOKEN", "<value>");
    // spacing varies, so locate the key literal and take the next string.
    let marker = "SmcCsrfInsert";
    let at = page.find(marker).ok_or("HTML5 page has no CSRF token")?;
    let rest = &page[at..];
    let key = rest
        .find("\"CSRF_TOKEN\"")
        .ok_or("HTML5 CSRF insert is malformed")?;
    let rest = &rest[key..];
    let comma = rest.find(',').ok_or("HTML5 CSRF insert is malformed")?;
    let rest = &rest[comma..];
    let start = rest.find('"').ok_or("HTML5 CSRF token is missing")? + 1;
    let rest = &rest[start..];
    let end = rest.find('"').ok_or("HTML5 CSRF token is unterminated")?;
    if end == 0 {
        return Err("HTML5 CSRF token is empty".into());
    }
    Ok(rest[..end].to_owned())
}

fn extract_entry_value(page: &str) -> Result<String> {
    let marker = "id=\"entry_value\"";
    let at = page
        .find(marker)
        .ok_or("HTML5 bootstrap page has no entry_value ticket")?;
    let rest = &page[at..];
    let at = rest
        .find("value=\"")
        .ok_or("HTML5 entry_value has no value")?
        + 7;
    let end = rest[at..]
        .find('"')
        .ok_or("HTML5 entry_value is unterminated")?
        + at;
    Ok(rest[at..end].to_owned())
}

fn extract_sid(headers: &header::HeaderMap) -> Result<String> {
    // The BMC always emits two SID Set-Cookie headers on success: first a
    // clearing one ("SID=; expires=1970..."), then the real session SID.
    // Keep scanning: only fail if no non-empty SID was found at all. Older
    // firmware issues 15 lowercase digits; newer (01.73.11) mixes in uppercase.
    let mut found = None;
    for value in headers.get_all(header::SET_COOKIE) {
        let cookie = value.to_str()?.split(';').next().unwrap_or("").trim();
        if let Some(sid) = cookie.strip_prefix("SID=")
            && sid.len() == 15
            && sid.bytes().all(|b| b.is_ascii_alphanumeric())
        {
            found = Some(sid.to_owned());
        }
    }
    found.ok_or_else(|| "web login rejected: SID cleared/invalid (bad credentials or session rejection); not retrying".into())
}

fn parse_jnlp(xml: &str, sid: String) -> Result<Tokens> {
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
        sid,
        html5: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn literal_tokens_and_xml_entities() {
        let t = parse_jnlp("<jnlp><application-desc><argument>host</argument><argument>a/b+</argument><argument>tok==&amp;</argument><argument>x</argument><argument>5900</argument><argument>623</argument></application-desc></jnlp>", "sid".into()).unwrap();
        assert_eq!(t.user, "a/b+");
        assert_eq!(t.pass, "tok==&");
        assert_eq!(t.port, 623);
        assert!(parse_jnlp("<html>login</html>", "sid".into()).is_err());
    }
    #[test]
    fn malformed_xml_does_not_log_secrets() {
        let error = parse_jnlp(
            "<jnlp><argument>&SECRET_TOKEN;</argument></jnlp>",
            "sid".into(),
        )
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
        // Firmware 01.73.11 mixes uppercase into the 15-character SID.
        h.insert(
            header::SET_COOKIE,
            "SID=Xg4vt0ZQ0zFn0er; path=/".parse().unwrap(),
        );
        assert_eq!(extract_sid(&h).unwrap(), "Xg4vt0ZQ0zFn0er");
        h.insert(
            header::SET_COOKIE,
            "SID=Xg4vt0ZQ0zFn0e; path=/".parse().unwrap(),
        );
        assert!(extract_sid(&h).is_err());
        h.insert(
            header::SET_COOKIE,
            "SID=Xg4_t0ZQ0zFn0er; path=/".parse().unwrap(),
        );
        assert!(extract_sid(&h).is_err());
    }
    #[test]
    fn html5_page_markers_extract() {
        let csrf = extract_csrf(
            "<script>SmcCsrfInsert (\"CSRF_TOKEN\", \"fJzHgi96adyoXLowV+Ok2cg8/C008QY6fhV07L2n9mE\");</script>",
        )
        .unwrap();
        assert_eq!(csrf, "fJzHgi96adyoXLowV+Ok2cg8/C008QY6fhV07L2n9mE");
        assert!(extract_csrf("<html>session gone</html>").is_err());
        let ticket = extract_entry_value(
            "<input type=\"hidden\" id=\"entry_value\" value=\"fwhXSuKINlBYFEvGagTTXA==\">",
        )
        .unwrap();
        assert_eq!(ticket, "fwhXSuKINlBYFEvGagTTXA==");
        assert_eq!(ticket.len(), 24);
        assert!(extract_entry_value("<html>404</html>").is_err());
    }
    #[test]
    fn html5_ticket_splits_at_fifteen_bytes() {
        let ticket = "fwhXSuKINlBYFEvGagTTXA==";
        assert!(ticket.len() >= 16);
        let (user, pass) = ticket.split_at(15);
        assert_eq!(user, "fwhXSuKINlBYFEv");
        assert_eq!(pass, "GagTTXA==");
        assert!(crate::auth::validate_tokens(user, pass).is_ok());
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
