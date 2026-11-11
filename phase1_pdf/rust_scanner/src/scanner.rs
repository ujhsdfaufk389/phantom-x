// =============================================================================
// PHANTOM-X :: Phase 1 -- PDF scanner (Rust)
// =============================================================================
// scanner.rs -- An independent PDF structure and action scanner, written to
// cross-validate the Python inspector.
//
// WHY A SECOND IMPLEMENTATION
//     The lab's ground rule #6 is "cross-validate before trusting: every
//     analyzer is checked against an independent implementation." The Python
//     inspector is the reference. This Rust scanner is the independent
//     implementation, written from the PDF specification rather than from
//     the Python source, so that a shared misreading of the format does
//     not hide in both.
//
//     A disagreement between the two is a bug in one of them. That is the
//     entire point.
//
// WHY RUST SPECIFICALLY
//     The scanner has to run on the research VM, where a Python
//     interpreter is not always present and where a native binary is
//     easier to trust than a script that has been modified. Rust gives a
//     single static binary with no runtime, and no memory-safety class of
//     bug in a parser that reads hostile input.
//
// SCOPE OF THIS FILE
//     Read-only. It parses the PDF, decodes streams, and reports what it
//     finds. It never writes to the PDF and never executes anything it
//     finds. Embedded files are reported, not launched.
// =============================================================================

use std::collections::BTreeMap;

/// A PDF object reference: `N G R` -> generation R, object number N.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ObjRef {
    pub num: u32,
    pub gen: u16,
}

impl ObjRef {
    pub fn new(num: u32, gen: u16) -> Self {
        ObjRef { num, gen }
    }
}

/// A parsed PDF object.
#[derive(Debug, Clone)]
pub enum Object {
    Null,
    Bool(bool),
    Int(i64),
    Real(f64),
    Str(Vec<u8>),
    Name(String),
    Array(Vec<Object>),
    Dict(BTreeMap<String, Object>),
    Stream {
        dict: BTreeMap<String, Object>,
        raw: Vec<u8>,
    },
    /// A reference to another object.
    Ref(ObjRef),
}

impl Object {
    pub fn as_dict(&self) -> Option<&BTreeMap<String, Object>> {
        match self {
            Object::Dict(d) => Some(d),
            Object::Stream { dict, .. } => Some(dict),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&Vec<Object>> {
        match self {
            Object::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_name(&self) -> Option<&str> {
        match self {
            Object::Name(n) => Some(n),
            _ => None,
        }
    }

    /// Resolve a value that may be a direct object or a reference.
    pub fn resolve<'a>(&'a self, doc: &'a Document) -> Option<&'a Object> {
        match self {
            Object::Ref(r) => doc.objects.get(&r.num),
            other => Some(other),
        }
    }
}

/// A parsed PDF document.
pub struct Document {
    pub objects: BTreeMap<u32, Object>,
    pub version: String,
    pub encrypted: bool,
    pub xref_type: String,
    pub trailer_root: Option<ObjRef>,
    /// Object number -> file offset, for diagnostics.
    pub offsets: BTreeMap<u32, u64>,
}

/// A PDF parse error.
#[derive(Debug)]
pub struct PdfError(pub String);

impl std::fmt::Display for PdfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PDF error: {}", self.0)
    }
}

impl std::error::Error for PdfError {}

/// The result type used throughout the parser.
pub type Result<T> = std::result::Result<T, PdfError>;

// ---------------------------------------------------------------------------
// Lexer
// ---------------------------------------------------------------------------

/// A token from the PDF byte stream.
#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    Obj(u32),
    Gen(u16),
    Keyword(String),
    /// A literal string, still escaped.
    Str(Vec<u8>),
    /// A hex string, still escaped.
    HexStr(Vec<u8>),
    Name(String),
    Int(i64),
    Real(f64),
    ArrayOpen,
    ArrayClose,
    DictOpen,
    DictClose,
    BraceOpen,
    BraceClose,
    Eof,
}

pub struct Lexer<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Lexer<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Lexer { data, pos: 0 }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn seek(&mut self, pos: usize) {
        self.pos = pos;
    }

    fn is_ws(b: u8) -> bool {
        matches!(b, b' ' | b'\t' | b'\r' | b'\n' | 0x00)
    }

    fn is_delim(b: u8) -> bool {
        matches!(
            b,
            b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
        )
    }

    /// Skip whitespace and comments.
    pub fn skip_ws(&mut self) {
        loop {
            while self.pos < self.data.len() && Self::is_ws(self.data[self.pos]) {
                self.pos += 1;
            }
            if self.pos < self.data.len() && self.data[self.pos] == b'%' {
                while self.pos < self.data.len()
                    && self.data[self.pos] != b'\n'
                    && self.data[self.pos] != b'\r'
                {
                    self.pos += 1;
                }
                continue;
            }
            break;
        }
    }

    /// Read the next token.
    pub fn next_token(&mut self) -> Result<Token> {
        self.skip_ws();
        if self.pos >= self.data.len() {
            return Ok(Token::Eof);
        }
        let b = self.data[self.pos];

        match b {
            b'[' => {
                self.pos += 1;
                Ok(Token::ArrayOpen)
            }
            b']' => {
                self.pos += 1;
                Ok(Token::ArrayClose)
            }
            b'{' => {
                self.pos += 1;
                Ok(Token::BraceOpen)
            }
            b'}' => {
                self.pos += 1;
                Ok(Token::BraceClose)
            }
            b'<' => {
                if self.pos + 1 < self.data.len() && self.data[self.pos + 1] == b'<' {
                    self.pos += 2;
                    Ok(Token::DictOpen)
                } else {
                    self.pos += 1;
                    Ok(Token::HexStr(self.read_hex_string()?))
                }
            }
            b'>' => {
                if self.pos + 1 < self.data.len() && self.data[self.pos + 1] == b'>' {
                    self.pos += 2;
                    Ok(Token::DictClose)
                } else {
                    self.pos += 1;
                    Ok(Token::Keyword(">".into()))
                }
            }
            b'(' => {
                self.pos += 1;
                Ok(Token::Str(self.read_literal_string()?))
            }
            b')' => {
                self.pos += 1;
                Ok(Token::Keyword(")".into()))
            }
            b'/' => {
                self.pos += 1;
                Ok(Token::Name(self.read_name()))
            }
            b'+' | b'-' | b'.' | b'0'..=b'9' => self.read_number(),
            _ => {
                let start = self.pos;
                while self.pos < self.data.len()
                    && !Self::is_ws(self.data[self.pos])
                    && !Self::is_delim(self.data[self.pos])
                {
                    self.pos += 1;
                }
                if self.pos == start {
                    self.pos += 1;
                }
                Ok(Token::Keyword(
                    String::from_utf8_lossy(&self.data[start..self.pos]).into_owned(),
                ))
            }
        }
    }

    fn read_number(&mut self) -> Result<Token> {
        let start = self.pos;
        let mut is_real = false;
        if self.pos < self.data.len() && (self.data[self.pos] == b'+' || self.data[self.pos] == b'-')
        {
            self.pos += 1;
        }
        while self.pos < self.data.len() {
            let c = self.data[self.pos];
            if c.is_ascii_digit() {
                self.pos += 1;
            } else if c == b'.' {
                is_real = true;
                self.pos += 1;
            } else if c == b'-' || c == b'+' {
                // Only allowed in exponents; treat as part of the number.
                is_real = true;
                self.pos += 1;
            } else {
                break;
            }
        }
        let text = String::from_utf8_lossy(&self.data[start..self.pos]).into_owned();
        if is_real {
            Ok(Token::Real(text.parse::<f64>().unwrap_or(0.0)))
        } else {
            match text.parse::<i64>() {
                Ok(v) => Ok(Token::Int(v)),
                Err(_) => Ok(Token::Real(text.parse::<f64>().unwrap_or(0.0))),
            }
        }
    }

    /// Read a name, decoding #xx escapes.
    fn read_name(&mut self) -> String {
        let mut out = Vec::new();
        while self.pos < self.data.len() {
            let c = self.data[self.pos];
            if Self::is_ws(c) || Self::is_delim(c) {
                break;
            }
            if c == b'#' && self.pos + 2 < self.data.len() {
                let h = (self.data[self.pos + 1], self.data[self.pos + 2]);
                if let (Some(a), Some(b)) = (hex_val(h.0), hex_val(h.1)) {
                    out.push(a * 16 + b);
                    self.pos += 3;
                    continue;
                }
            }
            out.push(c);
            self.pos += 1;
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    fn read_literal_string(&mut self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut depth = 1usize;
        while self.pos < self.data.len() {
            let c = self.data[self.pos];
            self.pos += 1;
            match c {
                b'\\' => {
                    if self.pos >= self.data.len() {
                        break;
                    }
                    let e = self.data[self.pos];
                    self.pos += 1;
                    match e {
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'b' => out.push(0x08),
                        b'f' => out.push(0x0c),
                        b'(' => out.push(b'('),
                        b')' => out.push(b')'),
                        b'\\' => out.push(b'\\'),
                        b'\r' => {
                            // line continuation
                            if self.pos < self.data.len() && self.data[self.pos] == b'\n' {
                                self.pos += 1;
                            }
                        }
                        b'\n' => {}
                        b'0'..=b'7' => {
                            let mut v = (e - b'0') as u32;
                            for _ in 0..2 {
                                if self.pos < self.data.len()
                                    && (b'0'..=b'7').contains(&self.data[self.pos])
                                {
                                    v = v * 8 + (self.data[self.pos] - b'0') as u32;
                                    self.pos += 1;
                                }
                            }
                            out.push((v & 0xff) as u8);
                        }
                        other => out.push(other),
                    }
                }
                b'(' => {
                    depth += 1;
                    out.push(c);
                }
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                    out.push(c);
                }
                other => out.push(other),
            }
        }
        Ok(out)
    }

    fn read_hex_string(&mut self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut hi: Option<u8> = None;
        while self.pos < self.data.len() {
            let c = self.data[self.pos];
            self.pos += 1;
            if c == b'>' {
                break;
            }
            if let Some(v) = hex_val(c) {
                match hi {
                    None => hi = Some(v),
                    Some(h) => {
                        out.push(h * 16 + v);
                        hi = None;
                    }
                }
            }
        }
        if let Some(h) = hi {
            out.push(h * 16);
        }
        Ok(out)
    }
}

/// Decode a single hex digit.
pub fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}
