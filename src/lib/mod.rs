use byteorder::{LittleEndian, ReadBytesExt};
use errors::SDSParserError;
use serde::Serialize;
use std::io::{Cursor, ErrorKind, Read, Seek};
use winstructs::security::SecurityDescriptor;
mod errors;

/// Security Descriptor Stream (SDS) entry struct.
#[derive(Debug, Serialize)]
pub struct SDSEntry {
    pub hash: u32,
    pub id: u32,
    #[serde(skip_serializing)]
    pub offset: u64,
    #[serde(skip_serializing)]
    pub size: u32,
    pub security_descriptor: SecurityDescriptor,
}

impl SDSEntry {
    pub fn from_reader<R: Read + Seek>(r: &mut R) -> std::result::Result<Self, SDSParserError> {
        let mut hash = r
            .read_u32::<LittleEndian>()
            .map_err(|e| SDSParserError::SDSEntry {
                err_msg: format!("{}", e),
            })?;
        while hash == 0 {
            hash = r
                .read_u32::<LittleEndian>()
                .map_err(|e| SDSParserError::SDSEntry {
                    err_msg: format!("{}", e),
                })?;
        }
        let id = r
            .read_u32::<LittleEndian>()
            .map_err(|e| SDSParserError::SDSEntry {
                err_msg: format!("{}", e),
            })?;
        let offset = r
            .read_u64::<LittleEndian>()
            .map_err(|e| SDSParserError::SDSEntry {
                err_msg: format!("{}", e),
            })?;
        let size = r
            .read_u32::<LittleEndian>()
            .map_err(|e| SDSParserError::SDSEntry {
                err_msg: format!("{}", e),
            })?;

        let padding_bytes = match size % 16 {
            0 => 0,
            _ => 16 - (size % 16),
        };

        let mut data = vec![0; ((size - 20) + padding_bytes) as usize];

        r.read_exact(&mut data).map_err(|e| match e.kind() {
            ErrorKind::UnexpectedEof => SDSParserError::EndOfStream,
            _ => SDSParserError::SDSEntry {
                err_msg: format!("{}", e),
            },
        })?;

        let mut stream = Cursor::new(&mut data);

        let security_descriptor = SecurityDescriptor::from_stream(&mut stream).map_err(|e| {
            SDSParserError::SecurityDescriptor {
                err_msg: format!("{}", e),
            }
        })?;

        Ok(Self {
            hash,
            id,
            offset,
            size,
            security_descriptor,
        })
    }
}

/// This struct is used to iterate through $Secure:$SDS stream and return `SDSEntry` struct
/// # Example:
/// ```
/// use sds_parser::SDSParser;
/// use std::fs::File;
/// let mut infile = File::open("samples/sds").unwrap();
/// for entry in SDSParser::from_reader(&mut infile) {
///     println!("{:?}", entry);
/// }
/// ```
#[derive(Debug, Serialize)]
pub struct SDSParser<T: Read + Seek> {
    _reader: T,
}

impl<T> SDSParser<T>
where
    T: Read + Seek,
{
    pub fn from_reader(r: T) -> Self {
        Self { _reader: r }
    }
}

impl<T: Read + Seek> Iterator for SDSParser<T> {
    type Item = std::result::Result<SDSEntry, SDSParserError>;

    fn next(&mut self) -> Option<Self::Item> {
        match SDSEntry::from_reader(&mut self._reader) {
            Ok(entry) => Some(Ok(entry)),
            Err(e) => match e {
                SDSParserError::EndOfStream => None,
                _ => Some(Err(e)),
            },
        }
    }
}
