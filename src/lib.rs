//! WinBox CDB decoder. No network, no firmware execution, no credential logging.
use serde::Serialize;
use serde_json::{Value, json};
use sha1::{Digest, Sha1};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Path,
};
use zeroize::{Zeroize, Zeroizing};

pub const PLAIN: u32 = 0xc01df00d;
pub const ENCRYPTED: u32 = 0x4011f00d;
pub const MAX_FILE: usize = 64 * 1024 * 1024;
const MAX_RECORD: usize = 1024 * 1024;
const MAX_RECORDS: usize = 100_000;
pub type Result<T> = std::result::Result<T, String>;

#[derive(Serialize, Debug)]
pub struct Document {
    pub format: &'static str,
    pub magic: String,
    pub encryption: &'static str,
    pub authenticated: bool,
    pub source_size: usize,
    pub record_count: usize,
    pub records: Vec<Record>,
}
#[derive(Serialize, Debug)]
pub struct Record {
    pub index: usize,
    pub offset: usize,
    pub message_size: usize,
    pub fields: Vec<Field>,
}
#[derive(Serialize, Debug)]
pub struct Field {
    pub id: String,
    pub name: Option<&'static str>,
    #[serde(rename = "type")]
    pub kind: String,
    pub header: String,
    pub offset: usize,
    pub value: Value,
}
impl Record {
    /// Keep duplicate known fields visible rather than silently selecting one.
    pub fn column(&self, name: &str) -> String {
        self.fields
            .iter()
            .filter(|f| f.name == Some(name))
            .map(|f| {
                f.value
                    .as_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|| f.value.to_string())
            })
            .collect::<Vec<_>>()
            .join(" | ")
    }
}
fn schema(id: u32, kind: &str) -> Option<&'static str> {
    match (id, kind) {
        (1, "string") => Some("address"),
        (2, "string") => Some("user"),
        (3, "string") => Some("password"),
        (4, "string") => Some("legacy-comment"),
        (7, "bool") => Some("with-password"),
        (8, "string") => Some("group"),
        (11, "string") => Some("romon-agent"),
        (12, "string") => Some("workspace"),
        (0xfe0001, "u32") => Some("id"),
        (0xfe0009, "string") => Some("comment"),
        _ => None,
    }
}
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(out, "{b:02x}").unwrap();
    }
    out
}
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
    base: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.bytes.len() - self.pos {
            return Err(format!(
                "truncated value at offset {:#x}",
                self.base + self.pos
            ));
        }
        let result = &self.bytes[self.pos..self.pos + n];
        self.pos += n;
        Ok(result)
    }
    fn num(&mut self, n: usize) -> Result<u64> {
        Ok(self
            .take(n)?
            .iter()
            .enumerate()
            .fold(0, |v, (i, b)| v | ((*b as u64) << (8 * i))))
    }
}
#[derive(Default)]
struct Budget {
    fields: usize,
    elements: usize,
}
fn variable(
    c: &mut Cursor<'_>,
    kind: &str,
    width: usize,
    depth: usize,
    budget: &mut Budget,
) -> Result<Value> {
    let n = c.num(width)? as usize;
    let base = c.base + c.pos;
    let bytes = c.take(n)?;
    if kind == "message" {
        return serde_json::to_value(message(bytes, base, depth + 1, budget)?)
            .map_err(|e| e.to_string());
    }
    if kind == "string"
        && let Ok(s) = std::str::from_utf8(bytes)
    {
        return Ok(json!(s));
    }
    Ok(json!({"hex":hex(bytes)}))
}
fn fixed(c: &mut Cursor<'_>, kind: &str) -> Result<Value> {
    match kind {
        "bool" => Ok(json!(c.num(1)? != 0)),
        "u32" => Ok(json!(c.num(4)?)),
        "u64" => Ok(json!(c.num(8)?)),
        _ => Ok(json!({"hex":hex(c.take(16)?)})),
    }
}
fn message(bytes: &[u8], base: usize, depth: usize, budget: &mut Budget) -> Result<Vec<Field>> {
    if depth > 32 {
        return Err("message depth limit exceeded".into());
    }
    if bytes.is_empty() {
        return Ok(vec![]);
    }
    let mut c = Cursor {
        bytes,
        pos: 0,
        base,
    };
    if c.take(2)? != b"M2" {
        return Err(format!("unsupported message marker at offset {base:#x}"));
    }
    let mut fields = Vec::new();
    while c.pos < bytes.len() {
        let offset = base + c.pos;
        let h = c.num(4)? as u32;
        let code = (h & 0xf8000000) >> 24;
        let scalar = code & 0x7f;
        let kind = match scalar {
            0 => "bool",
            8 => "u32",
            16 => "u64",
            24 => "addr6",
            32 => "string",
            40 => "message",
            48 => "raw",
            _ => return Err(format!("unsupported field type at offset {offset:#x}")),
        };
        budget.fields += 1;
        if budget.fields > 200_000 {
            return Err("field limit exceeded".into());
        }
        let array = code & 0x80 != 0;
        let wide = h & 0x02000000 != 0;
        let short = h & 0x01000000 != 0;
        let value = if array {
            let width = if wide { 4 } else { 2 };
            let count = c.num(width)? as usize;
            budget.elements += count;
            if budget.elements > 1_000_000 {
                return Err("array element limit exceeded".into());
            }
            let min = match scalar {
                0 => 1,
                8 => 4,
                16 => 8,
                24 => 16,
                _ => width,
            };
            if count > (bytes.len() - c.pos) / min {
                return Err("truncated array".into());
            }
            let mut values = Vec::with_capacity(count);
            for _ in 0..count {
                values.push(if scalar <= 24 {
                    fixed(&mut c, kind)?
                } else {
                    variable(&mut c, kind, width, depth, budget)?
                });
            }
            Value::Array(values)
        } else if scalar == 0 {
            json!(short)
        } else if scalar == 8 {
            json!(c.num(if short { 1 } else { 4 })?)
        } else if scalar <= 24 {
            fixed(&mut c, kind)?
        } else {
            variable(
                &mut c,
                kind,
                if short {
                    1
                } else if wide {
                    4
                } else {
                    2
                },
                depth,
                budget,
            )?
        };
        let kind = if array {
            format!("{kind}[]")
        } else {
            kind.to_string()
        };
        let id = h & 0xffffff;
        let name = if depth == 0 && h & 0x04000000 == 0 {
            schema(id, &kind)
        } else {
            None
        };
        fields.push(Field {
            id: format!("0x{id:06X}"),
            name,
            kind,
            header: format!("0x{h:08X}"),
            offset,
            value,
        });
    }
    Ok(fields)
}
fn rc4(data: &[u8], key: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut state = [0u8; 256];
    for (i, b) in state.iter_mut().enumerate() {
        *b = i as u8;
    }
    let mut j = 0usize;
    for i in 0..256 {
        j = (j + state[i] as usize + key[i % key.len()] as usize) & 255;
        state.swap(i, j);
    }
    let (mut i, mut j) = (0usize, 0usize);
    let mut out = Zeroizing::new(Vec::with_capacity(data.len()));
    for n in 0..768 + data.len() {
        i = (i + 1) & 255;
        j = (j + state[i] as usize) & 255;
        state.swap(i, j);
        let byte = state[(state[i] as usize + state[j] as usize) & 255];
        if n >= 768 {
            out.push(data[n - 768] ^ byte);
        }
    }
    state.zeroize();
    out
}
pub fn is_encrypted(data: &[u8]) -> bool {
    data.starts_with(&ENCRYPTED.to_le_bytes())
}
pub fn decode_cdb(data: &[u8], password: Option<&[u8]>) -> Result<Document> {
    if data.len() > MAX_FILE {
        return Err("CDB exceeds file size limit".into());
    }
    let magic = u32::from_le_bytes(
        data.get(..4)
            .ok_or("truncated CDB magic")?
            .try_into()
            .unwrap(),
    );
    let decrypted;
    let (payload, base, encryption) = match magic {
        PLAIN => (data, 0, "none"),
        ENCRYPTED => {
            if data.len() < 40 {
                return Err("truncated encrypted CDB header".into());
            }
            let password = password.ok_or("password required for encrypted CDB")?;
            let mut hash = Sha1::new();
            hash.update(&data[4..36]);
            hash.update(password);
            let mut key = hash.finalize();
            decrypted = rc4(&data[36..], &key);
            key.as_mut_slice().zeroize();
            if !decrypted.starts_with(&PLAIN.to_le_bytes()) {
                return Err("incorrect password or damaged encrypted CDB".into());
            }
            (&decrypted[..], 36, "rc4-drop768-sha1")
        }
        _ => return Err(format!("unsupported CDB magic 0x{magic:08X}")),
    };
    let mut c = Cursor {
        bytes: payload,
        pos: 4,
        base,
    };
    let mut records = Vec::new();
    while c.pos < payload.len() {
        if records.len() >= MAX_RECORDS {
            return Err("record count limit exceeded".into());
        }
        let offset = base + c.pos;
        let size = c.num(4)? as usize;
        if size > MAX_RECORD {
            return Err(format!("record size limit exceeded at offset {offset:#x}"));
        }
        let start = base + c.pos;
        let bytes = c.take(size)?;
        let fields = message(bytes, start, 0, &mut Budget::default())
            .map_err(|e| format!("invalid CDB record: {e}"))?;
        records.push(Record {
            index: records.len(),
            offset,
            message_size: size,
            fields,
        });
    }
    Ok(Document {
        format: "WinBox CDB",
        magic: format!("0x{magic:08X}"),
        encryption,
        authenticated: false,
        source_size: data.len(),
        record_count: records.len(),
        records,
    })
}
pub fn read_cdb(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let mut data = Zeroizing::new(Vec::new());
    File::open(path)
        .map_err(|e| e.to_string())?
        .take((MAX_FILE + 1) as u64)
        .read_to_end(&mut data)
        .map_err(|e| e.to_string())?;
    if data.len() > MAX_FILE {
        return Err("CDB exceeds file size limit".into());
    }
    Ok(data)
}
pub fn read_password(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let mut data = Zeroizing::new(Vec::new());
    File::open(path)
        .map_err(|e| e.to_string())?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut data)
        .map_err(|e| e.to_string())?;
    if data.len() > 1024 * 1024 {
        return Err("password file exceeds limit".into());
    }
    let len = data.len();
    if data.ends_with(b"\r\n") {
        data.truncate(len - 2);
    } else if data.ends_with(b"\n") {
        data.truncate(len - 1);
    }
    Ok(data)
}
struct SpacedJson;
impl serde_json::ser::Formatter for SpacedJson {
    fn begin_array_value<W: ?Sized + Write>(
        &mut self,
        w: &mut W,
        first: bool,
    ) -> std::io::Result<()> {
        if first { Ok(()) } else { w.write_all(b", ") }
    }
    fn begin_object_key<W: ?Sized + Write>(
        &mut self,
        w: &mut W,
        first: bool,
    ) -> std::io::Result<()> {
        if first { Ok(()) } else { w.write_all(b", ") }
    }
    fn begin_object_value<W: ?Sized + Write>(&mut self, w: &mut W) -> std::io::Result<()> {
        w.write_all(b": ")
    }
}
pub fn format_text(doc: &Document) -> Result<String> {
    use std::fmt::Write;
    let mut out = format!(
        "WinBox CDB: {} records; encryption={}\n",
        doc.record_count, doc.encryption
    );
    for record in &doc.records {
        writeln!(
            out,
            "record {} offset={:#x} size={}",
            record.index, record.offset, record.message_size
        )
        .unwrap();
        for field in &record.fields {
            let label = field
                .name
                .map(|n| format!("{n} ({})", field.id))
                .unwrap_or_else(|| field.id.clone());
            let mut buf = Vec::new();
            field
                .value
                .serialize(&mut serde_json::Serializer::with_formatter(
                    &mut buf, SpacedJson,
                ))
                .map_err(|e| e.to_string())?;
            writeln!(
                out,
                "  {label} [{}] = {}",
                field.kind,
                String::from_utf8(buf).unwrap()
            )
            .unwrap();
        }
    }
    Ok(out)
}
pub fn format_json(doc: &Document) -> Result<String> {
    serde_json::to_string_pretty(doc)
        .map(|s| s + "\n")
        .map_err(|e| e.to_string())
}
pub fn write_private(path: &Path, text: &str) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|e| e.to_string())?;
    file.write_all(text.as_bytes())
        .and_then(|_| file.sync_all())
        .map_err(|e| e.to_string())
}
#[cfg(feature = "gui")]
pub fn default_path() -> std::path::PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("MikroTik/WinBox/Addresses.cdb")
}
