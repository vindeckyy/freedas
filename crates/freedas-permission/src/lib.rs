//! Permission rule engine: allow/ask/deny with whole-string globs, last match wins.

use freedas_core::FreedasError;
use freedas_core::config::{Config, PermissionRule};

/// Whole-string glob with `*` and `?`.
pub fn glob_match(pattern: &str, value: &str) -> bool {
    fn inner(p: &[char], v: &[char]) -> bool {
        if p.is_empty() {
            return v.is_empty();
        }
        match p[0] {
            '*' => {
                // Match zero or more chars.
                for i in 0..=v.len() {
                    if inner(&p[1..], &v[i..]) {
                        return true;
                    }
                }
                false
            }
            '?' => !v.is_empty() && inner(&p[1..], &v[1..]),
            c => {
                if v.is_empty() {
                    return false;
                }
                // Case-fold on Windows only; elsewhere matching stays byte-exact.
                #[cfg(windows)]
                let eq = v[0].to_ascii_lowercase() == c.to_ascii_lowercase();
                #[cfg(not(windows))]
                let eq = v[0] == c;
                eq && inner(&p[1..], &v[1..])
            }
        }
    }
    let p: Vec<char> = pattern.chars().collect();
    let v: Vec<char> = value.chars().collect();
    inner(&p, &v)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    Allow,
    Ask,
    Deny,
}

impl Effect {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "allow" => Some(Effect::Allow),
            "ask" => Some(Effect::Ask),
            "deny" => Some(Effect::Deny),
            _ => None,
        }
    }
}

pub fn resolve(
    config: &Config,
    action: &str,
    resource: &str,
    agent_rules: &[PermissionRule],
) -> Effect {
    let mut effect = Effect::Ask; // default: ask
    let mut all: Vec<&PermissionRule> = config.permission.rules.iter().collect();
    all.extend(agent_rules.iter());
    for r in all {
        if r.action != "*" && r.action != action {
            continue;
        }
        let mut pat = r.resource.as_str();
        if glob_match(pat, resource) {
            if let Some(e) = Effect::parse(&r.effect) {
                effect = e;
            }
            continue;
        }
        // Shell patterns ending in " *" also match without arguments.
        if pat.ends_with(" *") {
            pat = &pat[..pat.len() - 2];
            if glob_match(pat, resource)
                && let Some(e) = Effect::parse(&r.effect)
            {
                effect = e;
            }
        }
    }
    effect
}

pub fn combine(
    resources: &[(String, String)],
    config: &Config,
    agent_rules: &[PermissionRule],
) -> Effect {
    let mut has_ask = false;
    for (action, resource) in resources {
        match resolve(config, action, resource, agent_rules) {
            Effect::Deny => return Effect::Deny,
            Effect::Ask => has_ask = true,
            Effect::Allow => {}
        }
    }
    if has_ask { Effect::Ask } else { Effect::Allow }
}

/// Shell scanner: extract subcommands and write-paths. Fails closed on dynamic
/// constructs: they return `needs_ask = true`.
#[derive(Debug, Default)]
pub struct ShellScan {
    pub commands: Vec<String>,
    pub writes: Vec<String>,
    pub reads: Vec<String>,
    pub needs_ask: bool,
    pub dynamic: Vec<String>,
}

const DYNAMIC_MARKERS: &[&str] = &[
    "$(",
    "`",
    "$[",
    "<(",
    ">(",
    "<<<",
    " <<<",
    "eval ",
    "sh -c",
    "bash -c",
    "env ",
    "xargs",
    "find -exec",
    "git -c",
    "rg --pre",
    "sed -e",
    "python -c",
    "node -e",
    "perl -e",
    "ruby -e",
];

const WRITE_WORDS: &[&str] = &[
    "tee", "cp", "mv", "rm", "mkdir", "touch", "chmod", "chown", "dd", "ln",
];

/// Commands whose non-flag arguments are read targets.
const READ_WORDS: &[&str] = &[
    "cat", "bat", "grep", "egrep", "fgrep", "rg", "head", "tail", "less", "more", "source", ".",
    "wc", "sort", "uniq", "cut", "strings", "file", "diff", "cmp", "nl", "od", "xxd", "tac",
];

/// Read commands whose first positional argument is a pattern, not a file.
const PATTERN_FIRST: &[&str] = &["grep", "egrep", "fgrep", "rg"];

/// Expand `~` and `$VAR`/`${VAR}` in a path operand. `None` means the path
/// could not be resolved statically, which the caller must treat as `ask`.
fn expand_vars(s: &str) -> Option<String> {
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '~' && out.is_empty() && matches!(chars.peek(), None | Some('/') | Some('\\')) {
            out.push_str(&std::env::var("HOME").ok()?);
            continue;
        }
        if c != '$' {
            out.push(c);
            continue;
        }
        let braced = chars.peek() == Some(&'{');
        if braced {
            chars.next();
        }
        let mut name = String::new();
        while let Some(&n) = chars.peek() {
            if n.is_ascii_alphanumeric() || n == '_' {
                name.push(n);
                chars.next();
            } else {
                break;
            }
        }
        if braced {
            if chars.peek() == Some(&'}') {
                chars.next();
            } else {
                return None;
            }
        }
        if name.is_empty() {
            return None;
        }
        out.push_str(&std::env::var(&name).ok()?);
    }
    Some(out)
}

/// Strip quotes/escapes, then expand variables. Empty or still-dynamic
/// results are unresolvable.
fn resolve_target(raw: &str) -> Option<String> {
    let mut s = String::new();
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\'' | '"' => {}
            '\\' => {
                if let Some(n) = chars.next() {
                    s.push(n);
                }
            }
            _ => s.push(c),
        }
    }
    let expanded = expand_vars(&s)?;
    if expanded.is_empty() {
        None
    } else {
        Some(expanded)
    }
}

fn push_target(scan: &mut ShellScan, raw: &str, into_writes: bool) {
    match resolve_target(raw) {
        Some(t) if into_writes => scan.writes.push(t),
        Some(t) => scan.reads.push(t),
        None => {
            scan.needs_ask = true;
            scan.dynamic.push(format!("unresolved path {raw}"));
        }
    }
}
/// Length in chars of an unquoted `$IFS`/`${IFS...}`/`$*`/`$@` word-split
/// marker at `s[pos..]` (`s[pos] == '$'`). `None` when absent. `$IFS` must not
/// be a prefix of a longer name (`$IFSX` is a different variable).
fn ifs_split_len(s: &[char], pos: usize) -> Option<usize> {
    if s.get(pos) != Some(&'$') {
        return None;
    }
    match s.get(pos + 1) {
        Some('*') | Some('@') => Some(2),
        Some('{') => {
            if s.get(pos + 2..pos + 5) != Some(&['I', 'F', 'S'][..]) {
                return None;
            }
            let mut j = pos + 5;
            while j < s.len() && s[j] != '}' {
                j += 1;
            }
            if j < s.len() {
                Some(j - pos + 1)
            } else {
                Some(5)
            }
        }
        Some('I') => {
            if s.get(pos + 1..pos + 4) != Some(&['I', 'F', 'S'][..]) {
                return None;
            }
            match s.get(pos + 4) {
                None => Some(4),
                Some(c) if !c.is_ascii_alphanumeric() && *c != '_' => Some(4),
                _ => None,
            }
        }
        _ => None,
    }
}

/// True when an unquoted `{...}` brace group appears outside `${...}`.
/// Covers `{a,b}`, `/{,}`, and `c{a}at`-style obfuscation; `${VAR}` is
/// excluded so ordinary variable expansion keeps resolving.
fn has_brace_group(command: &str) -> bool {
    let v: Vec<char> = command.chars().collect();
    let mut in_single = false;
    let mut in_double = false;
    let mut i = 0;
    while i < v.len() {
        let c = v[i];
        if c == '\'' && !in_double {
            in_single = !in_single;
            i += 1;
            continue;
        }
        if c == '"' && !in_single {
            in_double = !in_double;
            i += 1;
            continue;
        }
        if c == '\\' && !in_single {
            i += 2;
            continue;
        }
        if !in_single && !in_double && c == '{' {
            if i > 0 && v[i - 1] == '$' {
                i += 1;
                continue;
            }
            let mut j = i + 1;
            while j < v.len() && v[j] != '}' {
                if v[j].is_whitespace() || matches!(v[j], ';' | '|' | '&' | '(' | ')') {
                    break;
                }
                j += 1;
            }
            if j < v.len() && v[j] == '}' && j > i + 1 {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Inner command strings of `<(...)` / `>(...)` process substitutions,
/// respecting quotes and nesting. Callers recurse into each inner string
/// and skip the span in the outer scan so `|`/`>` inside cannot mis-parse.
fn extract_process_inners(command: &str) -> Vec<String> {
    let v: Vec<char> = command.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    let mut in_single = false;
    let mut in_double = false;
    while i < v.len() {
        let c = v[i];
        if c == '\'' && !in_double {
            in_single = !in_single;
            i += 1;
            continue;
        }
        if c == '"' && !in_single {
            in_double = !in_double;
            i += 1;
            continue;
        }
        if c == '\\' && !in_single {
            i += 2;
            continue;
        }
        if !in_single && !in_double && (c == '<' || c == '>') && v.get(i + 1) == Some(&'(') {
            let mut depth = 1usize;
            let mut j = i + 2;
            let mut js = false;
            let mut jd = false;
            while j < v.len() {
                let d = v[j];
                if d == '\'' && !jd {
                    js = !js;
                } else if d == '"' && !js {
                    jd = !jd;
                } else if d == '\\' && !js {
                    j += 1;
                } else if !js && !jd {
                    if d == '(' {
                        depth += 1;
                    } else if d == ')' {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                }
                j += 1;
            }
            if j < v.len() {
                out.push(v[i + 2..j].iter().collect());
                i = j + 1;
                continue;
            }
        }
        i += 1;
    }
    out
}

pub fn scan_shell(command: &str) -> ShellScan {
    let mut scan = ShellScan::default();
    for marker in DYNAMIC_MARKERS {
        if command.contains(marker) {
            scan.needs_ask = true;
            scan.dynamic.push(marker.trim().to_string());
        }
    }
    // Process substitution bodies run as commands; recurse so their reads,
    // writes, and dynamic markers are visible even though the outer text
    // only shows `<(...)` / `>(...)`.
    for inner in extract_process_inners(command) {
        let sub = scan_shell(&inner);
        scan.commands.extend(sub.commands);
        scan.writes.extend(sub.writes);
        scan.reads.extend(sub.reads);
        if sub.needs_ask {
            scan.needs_ask = true;
        }
        scan.dynamic.extend(sub.dynamic);
    }
    if has_brace_group(command) {
        scan.needs_ask = true;
        scan.dynamic.push("brace expansion".to_string());
    }
    // Split on top-level separators (approximation; sufficient for prefix checks).
    // `$IFS`/`${IFS...}`/`$*`/`$@` act as word separators like whitespace.
    let v: Vec<char> = command.chars().collect();
    let mut current = String::new();
    let mut words: Vec<String> = Vec::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut i = 0;
    let flush_word = |w: &mut String, words: &mut Vec<String>| {
        if !w.is_empty() {
            words.push(std::mem::take(w));
        }
    };
    let skip_proc = |v: &[char], start: usize| -> usize {
        let mut depth = 1usize;
        let mut j = start + 2;
        let mut js = false;
        let mut jd = false;
        while j < v.len() {
            let d = v[j];
            if d == '\'' && !jd {
                js = !js;
            } else if d == '"' && !js {
                jd = !jd;
            } else if d == '\\' && !js {
                j += 1;
            } else if !js && !jd {
                if d == '(' {
                    depth += 1;
                } else if d == ')' {
                    depth -= 1;
                    if depth == 0 {
                        return j + 1;
                    }
                }
            }
            j += 1;
        }
        v.len()
    };
    while i < v.len() {
        let c = v[i];
        match c {
            '\'' if !in_double => {
                in_single = !in_single;
                i += 1;
            }
            '"' if !in_single => {
                in_double = !in_double;
                i += 1;
            }
            '\\' if !in_single => {
                if i + 1 < v.len() {
                    current.push(v[i + 1]);
                    i += 2;
                } else {
                    i += 1;
                }
            }
            '$' if !in_single => {
                if let Some(len) = ifs_split_len(&v, i) {
                    flush_word(&mut current, &mut words);
                    i += len;
                } else {
                    current.push(c);
                    i += 1;
                }
            }
            '<' if !in_single && !in_double && v.get(i + 1) == Some(&'(') => {
                flush_word(&mut current, &mut words);
                i = skip_proc(&v, i);
            }
            ';' | '|' | '&' if !in_single && !in_double => {
                flush_word(&mut current, &mut words);
                if !words.is_empty() {
                    scan.commands.push(words.join(" "));
                    words.clear();
                }
                i += 1;
            }
            ' ' | '\t' if !in_single && !in_double => {
                flush_word(&mut current, &mut words);
                i += 1;
            }
            '>' if !in_single && !in_double => {
                if v.get(i + 1) == Some(&'(') {
                    flush_word(&mut current, &mut words);
                    i = skip_proc(&v, i);
                    continue;
                }
                flush_word(&mut current, &mut words);
                i += 1;
                // skip `>>`, `>&`, `>|`
                while i < v.len() && matches!(v[i], '>' | '&' | '|') {
                    i += 1;
                }
                while i < v.len() && v[i] == ' ' {
                    i += 1;
                }
                let mut target = String::new();
                while i < v.len() {
                    let n = v[i];
                    if n.is_whitespace() || matches!(n, ';' | '|' | '&' | ')') {
                        break;
                    }
                    target.push(n);
                    i += 1;
                }
                if !target.is_empty() {
                    push_target(&mut scan, &target, true);
                }
            }
            _ => {
                current.push(c);
                i += 1;
            }
        }
    }
    flush_word(&mut current, &mut words);
    if !words.is_empty() {
        scan.commands.push(words.join(" "));
    }
    let commands = scan.commands.clone();
    for (idx, cmd) in commands.iter().enumerate() {
        // `echo payload | sh` / `| bash` executes its stdin; fail closed even
        // when the payload itself looks benign.
        if idx > 0 {
            let toks = shell_tokens(cmd);
            let (stripped, nested) = strip_wrappers(toks);
            let piped_shell = nested.is_some()
                || stripped
                    .first()
                    .map(|s| matches!(base_name(s), "sh" | "bash" | "dash" | "zsh" | "ksh"))
                    .unwrap_or(false);
            if piped_shell {
                scan.needs_ask = true;
                if !scan.dynamic.iter().any(|d| d == "piped shell") {
                    scan.dynamic.push("piped shell".to_string());
                }
            }
        }
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        let Some(first) = parts.first() else { continue };
        if WRITE_WORDS.contains(first) {
            for w in &parts[1..] {
                if !w.starts_with('-') {
                    push_target(&mut scan, w, true);
                }
            }
        }
        if READ_WORDS.contains(first) {
            let mut seen_pattern = false;
            let mut skip_next = false;
            for w in &parts[1..] {
                if skip_next {
                    skip_next = false;
                    continue;
                }
                if w.starts_with('-') {
                    if matches!(*first, "head" | "tail") && matches!(*w, "-n" | "-c") {
                        skip_next = true;
                    }
                    continue;
                }
                if matches!(*first, "head" | "tail") && w.parse::<u64>().is_ok() {
                    continue;
                }
                if PATTERN_FIRST.contains(first) && !seen_pattern {
                    seen_pattern = true;
                    continue;
                }
                push_target(&mut scan, w, false);
            }
        }
        if *first == "cd"
            && let Some(target) = parts.get(1)
        {
            scan.commands.push(format!("cd {target}"));
        }
    }
    scan
}
/// Split a command line on top-level `;`, `&&`, `||`, `|`, `&`, and newlines,
/// respecting quotes.
fn split_simple_commands(command: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut chars = command.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\'' if !in_double => {
                in_single = !in_single;
                cur.push(c);
            }
            '"' if !in_single => {
                in_double = !in_double;
                cur.push(c);
            }
            '\\' if !in_single => {
                cur.push(c);
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            ';' | '|' | '&' | '\n' if !in_single && !in_double => {
                if !cur.trim().is_empty() {
                    out.push(std::mem::take(&mut cur));
                } else {
                    cur.clear();
                }
            }
            _ => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}
/// Tokenize one simple command, removing quotes and escapes.
fn shell_tokens(command: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let v: Vec<char> = command.chars().collect();
    let mut i = 0;
    let flush = |cur: &mut String, out: &mut Vec<String>| {
        if !cur.is_empty() {
            out.push(std::mem::take(cur));
        }
    };
    while i < v.len() {
        let c = v[i];
        match c {
            '\'' if !in_double => {
                in_single = !in_single;
                i += 1;
            }
            '"' if !in_single => {
                in_double = !in_double;
                i += 1;
            }
            '\\' if !in_single => {
                if i + 1 < v.len() {
                    cur.push(v[i + 1]);
                    i += 2;
                } else {
                    i += 1;
                }
            }
            '$' if !in_single => {
                if let Some(len) = ifs_split_len(&v, i) {
                    flush(&mut cur, &mut out);
                    i += len;
                } else {
                    cur.push(c);
                    i += 1;
                }
            }
            c if c.is_whitespace() && !in_single && !in_double => {
                flush(&mut cur, &mut out);
                i += 1;
            }
            _ => {
                cur.push(c);
                i += 1;
            }
        }
    }
    flush(&mut cur, &mut out);
    out
}

fn base_name(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

/// Strip command wrappers and resolve `bash -c`/`eval` payloads.
/// Returns the remaining argv and, when nested, the inner command string.
fn strip_wrappers(mut t: Vec<String>) -> (Vec<String>, Option<String>) {
    loop {
        while t
            .first()
            .map(|a| a.contains('=') && !a.starts_with('-'))
            .unwrap_or(false)
        {
            t.remove(0);
        }
        let Some(first) = t.first() else { break };
        let prog = base_name(first);
        match prog {
            "sudo" | "doas" => {
                t.remove(0);
                while t.first().map(|a| a.starts_with('-')).unwrap_or(false) {
                    let opt = t.remove(0);
                    if matches!(opt.as_str(), "-u" | "-g" | "-C" | "-h" | "-p" | "-r" | "-t")
                        && !t.is_empty()
                    {
                        t.remove(0);
                    }
                }
            }
            "env" => {
                t.remove(0);
                while t
                    .first()
                    .map(|a| a.starts_with('-') || a.contains('='))
                    .unwrap_or(false)
                {
                    t.remove(0);
                }
            }
            "nice" | "ionice" | "timeout" => {
                t.remove(0);
                while t.first().map(|a| a.starts_with('-')).unwrap_or(false) {
                    t.remove(0);
                }
                if let Some(arg) = t.first()
                    && arg
                        .chars()
                        .all(|c| c.is_ascii_digit() || matches!(c, '.' | 's' | 'm' | 'h'))
                {
                    t.remove(0);
                }
            }
            "nohup" | "command" | "exec" | "builtin" | "setsid" | "stdbuf" => {
                t.remove(0);
                while t.first().map(|a| a.starts_with('-')).unwrap_or(false) {
                    t.remove(0);
                }
            }
            "bash" | "sh" | "zsh" | "dash" | "ksh" => {
                let script = t.iter().position(|a| {
                    a == "-c" || (a.starts_with('-') && !a.starts_with("--") && a.contains('c'))
                });
                if let Some(i) = script
                    && let Some(inner) = t.get(i + 1)
                {
                    return (Vec::new(), Some(inner.clone()));
                }
                break;
            }
            "eval" => return (Vec::new(), Some(t[1..].join(" "))),
            _ => break,
        }
        if t.is_empty() {
            break;
        }
    }
    (t, None)
}

fn has_short_flag(args: &[String], flag: char) -> bool {
    args.iter()
        .any(|a| a.starts_with('-') && !a.starts_with("--") && a[1..].chars().any(|c| c == flag))
}

fn check_tokens(t: &[String]) -> Option<&'static str> {
    let prog = t.first().map(|s| base_name(s))?;
    let args = &t[1..];
    let recursive = args.iter().any(|a| a == "--recursive")
        || has_short_flag(args, 'r')
        || has_short_flag(args, 'R');
    let target_root = args.iter().any(|a| a == "/" || a == "/*");
    match prog {
        "rm" => {
            let force = args.iter().any(|a| a == "--force") || has_short_flag(args, 'f');
            let no_preserve = args.iter().any(|a| a == "--no-preserve-root");
            if recursive && force && target_root {
                Some("rm -rf /")
            } else if recursive && force && no_preserve {
                Some("rm -rf --no-preserve-root /")
            } else {
                None
            }
        }
        p if p.starts_with("mkfs") => Some("mkfs"),
        "dd" => args
            .iter()
            .find(|a| a.starts_with("of=/dev/"))
            .map(|_| "dd of=/dev/"),
        "wipefs" => Some("wipefs"),
        "shred" => args
            .iter()
            .find(|a| a.starts_with("/dev/"))
            .map(|_| "shred /dev/"),
        "chmod" => {
            let mode_777 = args
                .iter()
                .any(|a| !a.starts_with('-') && a.contains("777"));
            if recursive && mode_777 && target_root {
                Some("chmod -R 777 /")
            } else {
                None
            }
        }
        "chown" => {
            if recursive && target_root {
                Some("chown -R /")
            } else {
                None
            }
        }
        "shutdown" => Some("shutdown"),
        "reboot" => Some("reboot"),
        "halt" => Some("halt"),
        "poweroff" => Some("poweroff"),
        "kill" => {
            let signal = args.iter().any(|a| a == "-9" || a == "-KILL");
            let root = args.iter().any(|a| a == "1" || a == "-1");
            if signal && root {
                Some("kill -9 1")
            } else {
                None
            }
        }
        "killall" => Some("killall"),
        _ => None,
    }
}

fn catastrophic_inner(command: &str, depth: u8) -> Option<String> {
    // Depth-exceeded used to silently allow; fail closed instead. The cap is
    // raised (was 4) so legitimate nesting still resolves.
    if depth > 10 {
        return Some("deeply-nested shell invocation".into());
    }
    // Fork bombs survive tokenization; match the compacted text.
    let compact: String = command.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.contains(":(){:|:&};:") {
        return Some(":(){ :|:& };:".into());
    }
    // Process substitution bodies execute; check them as nested commands.
    for inner in extract_process_inners(command) {
        if let Some(hit) = catastrophic_inner(&inner, depth + 1) {
            return Some(hit);
        }
    }
    for cmd in split_simple_commands(command) {
        let (tokens, nested) = strip_wrappers(shell_tokens(&cmd));
        if let Some(inner) = nested
            && let Some(hit) = catastrophic_inner(&inner, depth + 1)
        {
            return Some(hit);
        }
        if let Some(hit) = check_tokens(&tokens) {
            return Some(hit.to_string());
        }
    }
    None
}

/// Public entry point for catastrophic-command detection.
pub fn catastrophic_match(command: &str) -> Option<String> {
    catastrophic_inner(command, 0)
}

/// True when a non-`*` rule with action `bash` and effect `allow` matches the
/// command — the only override for a catastrophic hit.
pub fn explicit_bash_allow(config: &Config, command: &str, agent_rules: &[PermissionRule]) -> bool {
    let all: Vec<&PermissionRule> = config
        .permission
        .rules
        .iter()
        .chain(agent_rules.iter())
        .collect();
    all.iter().any(|r| {
        r.action == "bash"
            && r.resource != "*"
            && r.effect == "allow"
            && glob_match(&r.resource, command)
    })
}

pub fn permission_for_shell(
    config: &Config,
    command: &str,
    agent_rules: &[PermissionRule],
) -> Result<Effect, FreedasError> {
    let scan = scan_shell(command);
    let mut resources: Vec<(String, String)> = scan
        .commands
        .iter()
        .map(|c| ("bash".into(), c.clone()))
        .collect();
    // File operands of read commands follow the `read` rules, so `cat .env`
    // asks exactly like the `read` tool does.
    resources.extend(scan.reads.iter().map(|r| ("read".into(), r.clone())));
    if scan.needs_ask {
        // Check if an explicit rule allows the dynamic command; otherwise ask.
        let effect = combine(&resources, config, agent_rules);
        return Ok(match effect {
            Effect::Deny => Effect::Deny,
            _ => Effect::Ask,
        });
    }
    Ok(combine(&resources, config, agent_rules))
}

#[cfg(test)]
mod tests {
    use super::*;
    use freedas_core::config::Config;

    #[test]
    fn glob_basics() {
        assert!(glob_match("*", "anything/at/all"));
        assert!(glob_match("*.env", ".env"));
        assert!(!glob_match("*.env", "file.txt"));
        assert!(glob_match("git status *", "git status --short"));
        assert!(glob_match("src/*.rs", "src/main.rs"));
    }

    #[test]
    fn defaults() {
        let cfg = Config::default();
        assert_eq!(resolve(&cfg, "read", ".env", &[]), Effect::Ask);
        assert_eq!(resolve(&cfg, "read", ".env.example", &[]), Effect::Allow);
        assert_eq!(resolve(&cfg, "read", "src/main.rs", &[]), Effect::Allow);
        assert_eq!(
            resolve(&cfg, "external_directory", "/etc/passwd", &[]),
            Effect::Ask
        );
    }

    #[test]
    fn scanner_detects_dynamic() {
        let s = scan_shell("echo $(whoami)");
        assert!(s.needs_ask);
        let s2 = scan_shell("git status --short");
        assert_eq!(s2.commands, vec!["git status --short"]);
    }

    #[test]
    fn catastrophic_matches_wrapped_and_quoted_forms() {
        for cmd in [
            "rm -rf /",
            "sudo rm -rf /",
            "env FOO=1 rm -rf /",
            "nice -n 5 rm -fr /",
            "bash -c \"rm -rf /\"",
            "bash -lc \"rm -rf /\"",
            "sh -c 'rm -rf /'",
            "/bin/rm -rf /",
            "echo hi && rm -rf /",
            "mkfs.ext4 /dev/sda1",
            "dd if=/dev/zero of=/dev/sda",
            "sudo reboot",
            ":(){ :|:& };:",
        ] {
            assert!(catastrophic_match(cmd).is_some(), "{cmd}");
        }
        for cmd in [
            "rm -rf target",
            "rm file",
            "git status",
            "dd if=/dev/zero of=out.img count=1",
            "chown -R user dir",
            "rm -rf /tmp/build",
        ] {
            assert!(catastrophic_match(cmd).is_none(), "{cmd}");
        }
    }

    #[test]
    fn scanner_extracts_read_targets() {
        let s = scan_shell("cat .env && grep -n TODO src/main.rs");
        assert!(s.reads.contains(&".env".to_string()));
        assert!(s.reads.contains(&"src/main.rs".to_string()));
        assert!(!s.reads.iter().any(|r| r == "TODO"));

        let s = scan_shell("cat \"$HOME/.env\" > \"$HOME/out.txt\"");
        let home = std::env::var("HOME").unwrap();
        assert!(s.reads.contains(&format!("{home}/.env")));
        assert!(s.writes.contains(&format!("{home}/out.txt")));
    }

    #[test]
    fn scanner_marks_unresolved_paths_ask() {
        let s = scan_shell("cat \"$UNSET_VAR_XYZ/file\"");
        assert!(s.needs_ask);
    }

    #[test]
    fn permission_for_shell_checks_read_targets() {
        let cfg = Config::default();
        assert_eq!(
            permission_for_shell(&cfg, "cat .env", &[]).unwrap(),
            Effect::Ask
        );
        assert_eq!(
            permission_for_shell(&cfg, "cat .env.example", &[]).unwrap(),
            Effect::Allow
        );
        assert_eq!(
            permission_for_shell(&cfg, "cat src/main.rs", &[]).unwrap(),
            Effect::Allow
        );
    }
}

#[cfg(test)]
mod parity_tests {
    use super::*;
    use freedas_core::config::Config;

    #[test]
    fn env_reads_ask_by_default() {
        let config = Config::default();
        assert_eq!(resolve(&config, "read", ".env", &[]), Effect::Ask);
        assert_eq!(resolve(&config, "read", ".env.example", &[]), Effect::Allow);
        assert_eq!(resolve(&config, "read", "src/main.rs", &[]), Effect::Allow);
    }
}
