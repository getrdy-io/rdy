//! A reader for the few things `k8s.dns` wants from a CoreDNS `Corefile`.
//!
//! A Corefile is a list of server blocks, each a header line that ends with `{`, directives (one per line,
//! some with a nested `{ ... }` block of their own) and a closing `}` on its own line. This reader is
//! line based, as the files CoreDNS ships are. It is not a full parser: a block written on one line
//! (`a { b }`) is not understood, and the result then says nothing rather than something wrong. It keeps:
//!
//! - whether a server block for the root zone (`.:53`) forwards `.` to `/etc/resolv.conf`;
//! - whether any block has the `loop` plugin (CoreDNS stops itself when it sees a forward loop);
//! - the zones of the `kubernetes` plugin (the cluster domain), without the reverse zones.
//!
//! Comments (`#` to the end of the line, outside quotes) are dropped first. At most [`MAX_LINES`] lines are
//! read and at most [`MAX_WORDS`] words per line. Nothing of the text is kept except the few words above.

/// The most lines read.
const MAX_LINES: usize = 2000;
/// The most words read from one line.
const MAX_WORDS: usize = 64;

/// What the check keeps of a Corefile.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Corefile {
    /// True when a root-zone block has `forward . /etc/resolv.conf` (or the older `proxy`).
    pub(super) forwards_to_resolv_conf: bool,
    /// The upstreams of the root-zone forward, as written: an address, a host or a file path. Empty when
    /// the root zone does not forward.
    pub(super) upstreams: Vec<String>,
    /// True when any block has the `loop` plugin.
    pub(super) loop_plugin: bool,
    /// The zones of the `kubernetes` plugin, lower case, no trailing dot, reverse zones left out.
    pub(super) cluster_zones: Vec<String>,
}

/// The words of a line, with `#` comments dropped and double quotes honoured.
fn words(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut word = String::new();
    let mut quoted = false;
    let mut has_word = false;
    for ch in line.chars() {
        match ch {
            '"' => {
                quoted = !quoted;
                has_word = true;
            }
            '#' if !quoted => break,
            c if c.is_whitespace() && !quoted => {
                if has_word {
                    out.push(std::mem::take(&mut word));
                    has_word = false;
                    if out.len() >= MAX_WORDS {
                        return out;
                    }
                }
            }
            c => {
                word.push(c);
                has_word = true;
            }
        }
    }
    if has_word {
        out.push(word);
    }
    out
}

/// True when a block header names the root zone: a word `.`, `.:53`, `:53` or a list of them.
fn is_root_header(header: &[String]) -> bool {
    header.iter().any(|word| {
        word.trim_end_matches(',')
            .rsplit_once("://")
            .map_or(word.trim_end_matches(','), |(_, rest)| rest)
            .split(':')
            .next()
            .is_some_and(|zone| zone == "." || zone.is_empty())
    })
}

/// Reads `text`.
pub(super) fn parse(text: &str) -> Corefile {
    let mut found = Corefile::default();
    let mut depth = 0_usize;
    let mut root = false;
    for line in text.lines().take(MAX_LINES) {
        let mut line_words = words(line);
        if line_words.is_empty() {
            continue;
        }
        if line_words == ["}"] {
            depth = depth.saturating_sub(1);
            continue;
        }
        let opens = line_words.last().is_some_and(|last| last == "{");
        if opens {
            line_words.pop();
        }
        match depth {
            0 => {
                if opens {
                    root = is_root_header(&line_words);
                    depth = 1;
                }
            }
            1 => {
                directive(&line_words, root, &mut found);
                if opens {
                    depth = 2;
                }
            }
            _ => {
                if opens {
                    depth += 1;
                }
            }
        }
    }
    found
}

/// One directive of a server block.
fn directive(words: &[String], root: bool, found: &mut Corefile) {
    let Some((name, args)) = words.split_first() else {
        return;
    };
    match name.as_str() {
        "loop" => found.loop_plugin = true,
        "forward" | "proxy" if root => {
            // `forward FROM TO...`: only the root zone matters, and the first upstream decides.
            if let Some((from, to)) = args.split_first()
                && from == "."
                && !to.is_empty()
                && found.upstreams.is_empty()
            {
                found.upstreams = to.to_vec();
                found.forwards_to_resolv_conf = to.iter().any(|up| up == "/etc/resolv.conf");
            }
        }
        "kubernetes" => {
            for zone in args {
                let zone = zone.trim_end_matches('.').to_ascii_lowercase();
                if !zone.is_empty()
                    && !zone.ends_with(".arpa")
                    && !found.cluster_zones.contains(&zone)
                {
                    found.cluster_zones.push(zone);
                }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KUBEADM: &str = "\
.:53 {
    errors
    health {
       lameduck 5s
    }
    ready
    kubernetes cluster.local in-addr.arpa ip6.arpa {
       pods insecure
       fallthrough in-addr.arpa ip6.arpa
       ttl 30
    }
    prometheus :9153
    forward . /etc/resolv.conf {
       max_concurrent 1000
    }
    cache 30
    loop
    reload
    loadbalance
}
";

    #[test]
    fn the_kubeadm_corefile_forwards_to_resolv_conf_and_has_the_loop_plugin() {
        let file = parse(KUBEADM);
        assert!(file.forwards_to_resolv_conf);
        assert_eq!(file.upstreams, ["/etc/resolv.conf"]);
        assert!(file.loop_plugin);
        assert_eq!(file.cluster_zones, ["cluster.local"]);
    }

    #[test]
    fn explicit_upstreams_are_not_resolv_conf() {
        let file = parse(".:53 {\n  forward . 10.0.0.2 10.0.0.3\n  loop\n}\n");
        assert!(!file.forwards_to_resolv_conf);
        assert_eq!(file.upstreams, ["10.0.0.2", "10.0.0.3"]);
    }

    #[test]
    fn a_resolv_conf_file_that_is_not_the_node_default_is_not_flagged() {
        let file = parse(".:53 {\n  forward . /run/systemd/resolve/resolv.conf\n}\n");
        assert!(!file.forwards_to_resolv_conf);
        assert_eq!(file.upstreams, ["/run/systemd/resolve/resolv.conf"]);
    }

    #[test]
    fn a_stub_zone_that_forwards_to_resolv_conf_is_not_the_root_forward() {
        let text =
            "consul.local:53 {\n  forward . /etc/resolv.conf\n}\n.:53 {\n  forward . 10.0.0.2\n}\n";
        let file = parse(text);
        assert!(!file.forwards_to_resolv_conf);
        assert_eq!(file.upstreams, ["10.0.0.2"]);
    }

    #[test]
    fn comments_and_nested_blocks_do_not_leak_into_the_result() {
        let text = "\
# forward . /etc/resolv.conf
.:53 {
    kubernetes cluster.example. in-addr.arpa {
        loop
        forward . /etc/resolv.conf
    }
    forward . 1.1.1.1 # /etc/resolv.conf
}
";
        let file = parse(text);
        assert!(!file.forwards_to_resolv_conf);
        assert!(!file.loop_plugin);
        assert_eq!(file.cluster_zones, ["cluster.example"]);
        assert_eq!(file.upstreams, ["1.1.1.1"]);
    }

    #[test]
    fn the_old_proxy_plugin_counts_and_a_second_root_forward_does_not_override_the_first() {
        let file = parse(".:53 {\n  proxy . /etc/resolv.conf\n  forward . 9.9.9.9\n}\n");
        assert!(file.forwards_to_resolv_conf);
    }

    #[test]
    fn a_quoted_word_keeps_its_hash() {
        let file = parse(".:53 {\n  forward . \"/etc/#x\"\n}\n");
        assert_eq!(file.upstreams, ["/etc/#x"]);
    }

    #[test]
    fn garbage_gives_an_empty_result_and_never_panics() {
        for text in [
            "",
            "}",
            "}}}{{{",
            "{",
            ". {",
            "forward . /etc/resolv.conf",
            "\u{0}\u{1}",
            "a { b }",
        ] {
            let file = parse(text);
            assert!(!file.forwards_to_resolv_conf, "{text:?}");
        }
        let long = format!(".:53 {{\n{}\n}}\n", "x ".repeat(10_000));
        let _ = parse(&long);
        let many = "a {\n".repeat(100_000);
        let _ = parse(&many);
    }

    #[test]
    fn only_the_first_lines_are_read() {
        let mut text = ".:53 {\n".to_owned();
        text.push_str(&"  cache 30\n".repeat(MAX_LINES));
        text.push_str("  forward . /etc/resolv.conf\n}\n");
        assert!(!parse(&text).forwards_to_resolv_conf);
    }
}
