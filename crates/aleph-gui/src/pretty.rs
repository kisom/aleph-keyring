//! Showing a JSON secret readably: re-indented, two spaces a level. Only
//! the layout changes (keys keep their order, numbers and escapes their
//! spelling), and the text is never parsed into values, whose copies of
//! the secret would not be zeroized: it is walked once into a zeroized
//! string. Anything that is not an object or array with balanced
//! brackets and closed strings is left as it is.

use zeroize::Zeroizing;

/// `text` re-indented if it is JSON (an object or array), else `None`.
pub fn json(text: &str) -> Option<Zeroizing<String>> {
    let t = text.trim();
    if !(t.starts_with('{') && t.ends_with('}') || t.starts_with('[') && t.ends_with(']')) {
        return None;
    }
    // (Measured first: a string that grows leaves its old buffer behind.)
    let mut len = 0;
    walk(t, &mut len)?;
    let mut out = Zeroizing::new(String::with_capacity(len));
    walk(t, &mut *out)?;
    Some(out)
}

/// Where the walk writes: the text itself, or just its length.
trait Sink {
    fn put(&mut self, s: &str);
}

impl Sink for String {
    fn put(&mut self, s: &str) {
        self.push_str(s);
    }
}

impl Sink for usize {
    fn put(&mut self, s: &str) {
        *self += s.len();
    }
}

fn walk(t: &str, out: &mut impl Sink) -> Option<()> {
    let mut open: Vec<char> = Vec::new();
    let (mut in_string, mut escaped, mut just_opened) = (false, false, false);
    let mut chars = t.chars().peekable();
    let mut buf = [0u8; 4];
    let newline = |out: &mut dyn FnMut(&str), depth: usize| {
        out("\n");
        for _ in 0..depth {
            out("  ");
        }
    };
    while let Some(c) = chars.next() {
        let mut put = |s: &str| out.put(s);
        let ch = c.encode_utf8(&mut buf);
        if in_string {
            put(ch);
            match (escaped, c) {
                (true, _) => escaped = false,
                (false, '\\') => escaped = true,
                (false, '"') => in_string = false,
                _ => {}
            }
            continue;
        }
        let opened_now = matches!(c, '{' | '[');
        match c {
            '"' => {
                in_string = true;
                put(ch);
            }
            '{' | '[' => {
                open.push(c);
                put(ch);
                // (An empty one stays on its line: `{}`, `[]`.)
                while chars.peek().is_some_and(|c| c.is_whitespace()) {
                    chars.next();
                }
                if !matches!(chars.peek(), Some('}' | ']')) {
                    newline(&mut put, open.len());
                }
            }
            '}' | ']' => {
                let opened = open.pop()?;
                if (opened, c) != ('{', '}') && (opened, c) != ('[', ']') {
                    return None;
                }
                if !just_opened {
                    newline(&mut put, open.len());
                }
                put(ch);
            }
            ',' => {
                put(ch);
                newline(&mut put, open.len());
            }
            ':' => put(": "),
            c if c.is_whitespace() => continue,
            _ => put(ch),
        }
        just_opened = opened_now;
        if open.is_empty() && chars.peek().is_some() {
            // (Something after the outermost value closed.)
            return None;
        }
    }
    (open.is_empty() && !in_string).then_some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pretty(s: &str) -> Option<String> {
        json(s).map(|p| p.to_string())
    }

    #[test]
    fn an_object_is_indented_in_its_own_order() {
        assert_eq!(
            pretty(r#"{"z":1,"a":{"b":[1,2.50,true]},"e":{},"f":[]}"#).unwrap(),
            "{\n  \"z\": 1,\n  \"a\": {\n    \"b\": [\n      1,\n      2.50,\n      true\n    ]\n  },\n  \"e\": {},\n  \"f\": []\n}"
        );
    }

    #[test]
    fn strings_are_kept_as_written() {
        assert_eq!(
            pretty(r#"[ "a, b: {c}", "q\"[x", "\\" ]"#).unwrap(),
            "[\n  \"a, b: {c}\",\n  \"q\\\"[x\",\n  \"\\\\\"\n]"
        );
    }

    #[test]
    fn already_indented_json_comes_out_the_same() {
        let once = pretty(r#"{"k": [1, {"x": null}]}"#).unwrap();
        assert_eq!(pretty(&once).unwrap(), once);
    }

    /// Room for all of it from the start: a string that grows leaves
    /// its old, unzeroized buffer behind.
    #[test]
    fn deep_nesting_never_regrows_the_string() {
        let deep = format!("{}{}", "[".repeat(40), "]".repeat(40));
        let p = json(&deep).unwrap();
        assert_eq!(p.capacity(), p.len());
    }

    #[test]
    fn what_is_not_an_object_or_array_is_left_alone() {
        for s in [
            "ghp_s3cret",
            "\"just a string\"",
            "42",
            "{unclosed",
            "{\"a\":1}}",
            "{\"a\":[1}",
            "{\"a\":\"open}",
            "{\"a\":1} {\"b\":2}",
            "[1] trailing]",
        ] {
            assert_eq!(pretty(s), None, "{s}");
        }
    }
}
