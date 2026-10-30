//! Tests for the proxy URL, the `CONNECT` request and the reply parser (M1-091).
//!
//! Every credential here is a synthetic canary.

use super::*;

fn url(text: &str) -> ProxyUrl {
    ProxyUrl::parse(text).expect("a valid proxy url")
}

#[test]
fn a_proxy_url_has_a_host_and_a_port() {
    let p = url("http://proxy.acme.test:3128");
    assert_eq!(p.host().to_string(), "proxy.acme.test");
    assert_eq!(p.port(), 3128);
    assert!(!p.has_credentials());
    assert_eq!(p.origin(), "http://proxy.acme.test:3128");
    // A trailing slash is fine, a scheme is optional and the default port is 80.
    assert_eq!(url("http://proxy.acme.test:3128/").port(), 3128);
    assert_eq!(
        url("proxy.acme.test:8080").origin(),
        "http://proxy.acme.test:8080"
    );
    assert_eq!(url("http://proxy.acme.test").port(), DEFAULT_PROXY_PORT);
    assert_eq!(
        url("  http://10.1.2.3:3128 ").origin(),
        "http://10.1.2.3:3128"
    );
    assert_eq!(
        url("http://[2001:db8::7]:3128").origin(),
        "http://[2001:db8::7]:3128"
    );
    assert_eq!(
        url("http://[2001:db8::7]").origin(),
        "http://[2001:db8::7]:80"
    );
}

#[test]
fn what_is_not_a_plain_http_proxy_is_refused_with_a_hint_and_no_echo() {
    let cases: [(&str, ProxyUrlError); 11] = [
        ("", ProxyUrlError::Size),
        ("   ", ProxyUrlError::Size),
        ("https://proxy.acme.test:3128", ProxyUrlError::Scheme),
        (
            "socks5://u:Canary-pw-1@proxy.acme.test:1080",
            ProxyUrlError::Scheme,
        ),
        ("http://proxy.acme.test:3128/pac.js", ProxyUrlError::Extra),
        (
            "http://proxy.acme.test:3128?x=Canary-q-1",
            ProxyUrlError::Extra,
        ),
        ("http://proxy.acme.test:0", ProxyUrlError::Address),
        ("http://proxy.acme.test:99999", ProxyUrlError::Address),
        ("http://:3128", ProxyUrlError::Address),
        ("http://bad host:3128", ProxyUrlError::Address),
        ("http://127.1:3128", ProxyUrlError::Address),
    ];
    for (text, want) in cases {
        let error = ProxyUrl::parse(text).expect_err(text);
        assert_eq!(error, want, "{text}");
        let shown = error.to_string();
        assert!(shown.contains("Fix:"), "{shown}");
        assert!(
            !shown.contains("Canary"),
            "an error echoed the text: {shown}"
        );
    }
    let too_long = format!("http://{}.acme.test:3128", "a".repeat(2100));
    assert_eq!(ProxyUrl::parse(&too_long), Err(ProxyUrlError::Size));
}

#[test]
fn userinfo_is_percent_decoded_and_both_forms_are_secrets() {
    let p = url("http://svc:Pa55%2Dcanary%40x@proxy.acme.test:3128");
    assert!(p.has_credentials());
    // The base64 of `svc:Pa55-canary@x`: the password is decoded before it is encoded.
    assert_eq!(
        p.authorization().as_deref(),
        Some("Basic c3ZjOlBhNTUtY2FuYXJ5QHg=")
    );
    let secrets = p.secrets();
    assert_eq!(
        secrets,
        [
            "Pa55-canary@x",
            "Pa55%2Dcanary%40x",
            "c3ZjOlBhNTUtY2FuYXJ5QHg="
        ]
    );
    // A password with nothing to decode is one form plus the pair.
    let plain = url("http://user:pass-word-1@proxy.acme.test:3128");
    assert_eq!(plain.secrets().len(), 2);
    assert_eq!(plain.secrets()[0], "pass-word-1");
}

#[test]
fn a_user_without_a_password_sends_an_empty_one_and_the_user_is_the_secret() {
    let p = url("http://svc@proxy.acme.test:3128");
    assert!(p.has_credentials());
    assert_eq!(p.authorization().as_deref(), Some("Basic c3ZjOg=="));
    // The token-as-user pattern: the user name and the base64 of `user:` both reach output.
    assert_eq!(p.secrets(), ["svc", "c3ZjOg=="]);
    let empty = url("http://svc:@proxy.acme.test:3128");
    assert_eq!(empty.secrets(), ["svc", "c3ZjOg=="]);
    // A URL with no user has nothing to hide.
    assert!(url("http://proxy.acme.test:3128").secrets().is_empty());
}

#[test]
fn bad_userinfo_is_refused() {
    for text in [
        "http://sv%zzc:Canary-pw-1@proxy.acme.test:3128",
        "http://svc:Canary%2@proxy.acme.test:3128",
        "http://svc:Canary-%ff%fe@proxy.acme.test:3128",
        "http://:Canary-pw-1@proxy.acme.test:3128",
        "http://a%3Ab:Canary-pw-1@proxy.acme.test:3128",
    ] {
        let error = ProxyUrl::parse(text).expect_err(text);
        assert_eq!(error, ProxyUrlError::Userinfo, "{text}");
        assert!(!error.to_string().contains("Canary"));
    }
    // An at sign in the password splits at the last one.
    assert_eq!(
        url("http://svc:p@ss-canary@proxy.acme.test:3128")
            .host()
            .to_string(),
        "proxy.acme.test"
    );
}

#[test]
fn debug_and_display_mask_the_userinfo() {
    let p = url("http://svc:Pa55%2Dcanary%40x@proxy.acme.test:3128");
    for text in [format!("{p}"), format!("{p:?}"), format!("{p:#?}")] {
        assert!(text.contains("proxy.acme.test:3128"), "{text}");
        assert!(text.contains("***"), "{text}");
        for leaked in ["svc", "Pa55", "canary", "c3ZjOl"] {
            assert!(!text.contains(leaked), "{leaked} leaked: {text}");
        }
    }
    assert_eq!(
        url("http://proxy.acme.test:3128").to_string(),
        "http://proxy.acme.test:3128"
    );
    assert!(!p.origin().contains('@'));
}

#[test]
fn the_connect_request_carries_basic_auth_only_when_the_url_has_a_user() {
    let with = url("http://svc:Pa55%2Dcanary%40x@proxy.acme.test:3128")
        .connect_request("registry.acme.test:443");
    assert_eq!(
        String::from_utf8(with).expect("ascii"),
        "CONNECT registry.acme.test:443 HTTP/1.1\r\nHost: registry.acme.test:443\r\n\
         Proxy-Authorization: Basic c3ZjOlBhNTUtY2FuYXJ5QHg=\r\n\r\n"
    );
    let without = url("http://proxy.acme.test:3128").connect_request("[2001:db8::1]:443");
    assert_eq!(
        String::from_utf8(without).expect("ascii"),
        "CONNECT [2001:db8::1]:443 HTTP/1.1\r\nHost: [2001:db8::1]:443\r\n\r\n"
    );
}

#[test]
fn base64_follows_rfc_4648() {
    for (bytes, text) in [
        (&b""[..], ""),
        (b"f", "Zg=="),
        (b"fo", "Zm8="),
        (b"foo", "Zm9v"),
        (b"foob", "Zm9vYg=="),
        (b"fooba", "Zm9vYmE="),
        (b"foobar", "Zm9vYmFy"),
        (&[0xfb, 0xff], "+/8="),
    ] {
        assert_eq!(base64(bytes), text);
    }
    assert_eq!(base64(b"user:pass"), "dXNlcjpwYXNz");
}

#[test]
fn a_connect_reply_is_read_for_its_status_and_challenge_only() {
    let head = |text: &str| parse_connect_head(text.as_bytes());
    let reply = head("HTTP/1.1 200 Connection Established\r\n\r\n").expect("200");
    assert_eq!((reply.status, reply.challenge), (200, ProxyChallenge::None));
    assert_eq!(head("HTTP/1.0 200 OK\r\n\r\n").expect("1.0").status, 200);
    assert_eq!(head("HTTP/1.1 403\r\n\r\n").expect("no reason").status, 403);
    for (header, want) in [
        (
            "Proxy-Authenticate: Basic realm=\"x\"",
            ProxyChallenge::Basic,
        ),
        ("proxy-authenticate: BASIC", ProxyChallenge::Basic),
        ("Proxy-Authenticate: Negotiate", ProxyChallenge::Negotiate),
        ("Proxy-Authenticate:   NTLM", ProxyChallenge::Ntlm),
        (
            "Proxy-Authenticate: Digest realm=\"x\"",
            ProxyChallenge::Other,
        ),
        ("Proxy-Authenticate:", ProxyChallenge::Other),
    ] {
        let reply = head(&format!(
            "HTTP/1.1 407 Proxy Authentication Required\r\n{header}\r\nContent-Length: 0\r\n\r\n"
        ))
        .expect("407");
        assert_eq!((reply.status, reply.challenge), (407, want), "{header}");
    }
}

#[test]
fn every_challenge_is_read_and_basic_wins_when_offered() {
    let challenge = |headers: &str| {
        parse_connect_head(format!("HTTP/1.1 407 x\r\n{headers}\r\n\r\n").as_bytes())
            .expect("407")
            .challenge
    };
    // Negotiate first and Basic second: the hint must not say "integrated sign-in".
    assert_eq!(
        challenge("Proxy-Authenticate: Negotiate\r\nProxy-Authenticate: Basic realm=\"x\""),
        ProxyChallenge::Basic
    );
    assert_eq!(
        challenge("Proxy-Authenticate: Basic\r\nProxy-Authenticate: Negotiate"),
        ProxyChallenge::Basic
    );
    // Two challenges in one header.
    assert_eq!(
        challenge("Proxy-Authenticate: Negotiate, Basic realm=\"x\", charset=\"UTF-8\""),
        ProxyChallenge::Basic
    );
    // Without Basic, the first known scheme stays, and a known scheme beats an unknown one.
    assert_eq!(
        challenge("Proxy-Authenticate: NTLM\r\nProxy-Authenticate: Negotiate"),
        ProxyChallenge::Ntlm
    );
    assert_eq!(
        challenge(
            "Proxy-Authenticate: Digest realm=\"x\", nonce=\"y\"\r\nProxy-Authenticate: Negotiate"
        ),
        ProxyChallenge::Negotiate
    );
    assert_eq!(
        challenge("Proxy-Authenticate: Digest realm=\"x\", nonce=\"y\""),
        ProxyChallenge::Other
    );
    // The advice follows: Basic with no credentials asks for them, and does not name sign-in.
    let basic = NetFailure::ProxyAuthRequired {
        target: "a.acme.test:443".to_owned(),
        challenge: challenge("Proxy-Authenticate: Negotiate\r\nProxy-Authenticate: Basic"),
        sent_credentials: false,
    };
    assert!(
        basic.to_string().contains("user name and password"),
        "{basic}"
    );
    assert!(!basic.to_string().contains("integrated sign-in"), "{basic}");
}

#[test]
fn a_reply_that_is_not_http_is_refused() {
    for text in [
        "",
        "SSH-2.0-OpenSSH_9.6\r\n\r\n",
        "\x16\x03\x01\x02\x00\x01\x00\r\n\r\n",
        "HTTP/2 200\r\n\r\n",
        "HTTP/1.1 20\r\n\r\n",
        "HTTP/1.1 2000 x\r\n\r\n",
        "HTTP/1.1 abc x\r\n\r\n",
        "HTTP/1.1 99 x\r\n\r\n",
        "HTTP/1.1 600 x\r\n\r\n",
        "http/1.1 200 x\r\n\r\n",
    ] {
        assert!(parse_connect_head(text.as_bytes()).is_err(), "{text:?}");
    }
}

#[test]
fn statuses_map_to_typed_failures() {
    let reply = |status, challenge| ConnectReply { status, challenge };
    let target = "registry.acme.test:443";
    for ok in [200, 204, 299] {
        assert_eq!(
            reply(ok, ProxyChallenge::None).into_result(target, false),
            Ok(())
        );
    }
    assert_eq!(
        reply(403, ProxyChallenge::None).into_result(target, true),
        Err(NetFailure::ProxyForbidden {
            target: target.to_owned()
        })
    );
    assert_eq!(
        reply(407, ProxyChallenge::Basic).into_result(target, true),
        Err(NetFailure::ProxyAuthRequired {
            target: target.to_owned(),
            challenge: ProxyChallenge::Basic,
            sent_credentials: true,
        })
    );
    for status in [100, 301, 400, 502, 504] {
        assert_eq!(
            reply(status, ProxyChallenge::None).into_result(target, false),
            Err(NetFailure::ProxyRefused {
                target: target.to_owned(),
                status
            })
        );
    }
}

#[test]
fn every_failure_ends_with_a_fix_and_names_no_peer_text() {
    let target = "registry.acme.test:443".to_owned();
    let failures = [
        NetFailure::Dns {
            host: "registry.acme.test".to_owned(),
        },
        NetFailure::ProxyForbidden {
            target: target.clone(),
        },
        NetFailure::ProxyAuthRequired {
            target: target.clone(),
            challenge: ProxyChallenge::Basic,
            sent_credentials: false,
        },
        NetFailure::ProxyAuthRequired {
            target: target.clone(),
            challenge: ProxyChallenge::Basic,
            sent_credentials: true,
        },
        NetFailure::ProxyAuthRequired {
            target: target.clone(),
            challenge: ProxyChallenge::Negotiate,
            sent_credentials: true,
        },
        NetFailure::ProxyAuthRequired {
            target: target.clone(),
            challenge: ProxyChallenge::Ntlm,
            sent_credentials: false,
        },
        NetFailure::ProxyRefused {
            target,
            status: 502,
        },
        NetFailure::ProxyBadReply {
            reason: "no HTTP status line",
        },
        NetFailure::NoProxy,
    ];
    for failure in failures {
        let text = failure.to_string();
        assert!(text.contains("Fix:"), "{text}");
        assert!(!text.contains("Proxy-Authorization"), "{text}");
    }
    let basic = NetFailure::ProxyAuthRequired {
        target: "a:1".to_owned(),
        challenge: ProxyChallenge::Basic,
        sent_credentials: false,
    };
    assert!(basic.to_string().contains("http://user:password@host:port"));
    let negotiate = NetFailure::ProxyAuthRequired {
        target: "a:1".to_owned(),
        challenge: ProxyChallenge::Negotiate,
        sent_credentials: true,
    };
    assert!(negotiate.to_string().contains("does not attempt"));
}
