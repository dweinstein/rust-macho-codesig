#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]

use byteorder::{BigEndian, ByteOrder, ReadBytesExt};
use std::error::Error;
use std::io::{BufRead, Cursor, Read, Seek, SeekFrom};
use std::str;

use consts::{
    CS_HASHTYPE_SHA1, CS_HASHTYPE_SHA256, CSMAGIC_EMBEDDED_SIGNATURE, CSSLOT_CODEDIRECTORY,
};

#[derive(Debug, Default, Clone)]
pub struct SuperBlob {
    /// magic number
    pub magic: u32,
    /// total length of SuperBlob
    pub length: u32,
    /// number of index entries following */
    pub count: u32,
    /// (count) entries
    pub index: Vec<Option<BlobIndex>>,
}

trait CDVersion {
    const currentVersion: u32;
    const compatibilityLimit: u32;
}

impl CDVersion for CodeDirectory {
    /// "version 2.4"
    const currentVersion: u32 = 0x20400;
    /// "version 3 with wiggle room"
    const compatibilityLimit: u32 = 0x2F000;
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
/// A CodeDirectory is a typed Blob describing the secured pieces of a program.
/// This structure describes the common header and provides access to the variable-size
/// elements packed after it. For help in constructing a CodeDirectory.
///
/// At the heart of a CodeDirectory lies a packed array of hash digests.
/// The array's zero-index element is at offset hashOffset, and the array covers
/// elements in the range [-nSpecialSlots .. nCodeSlots-1]. Non-negative indices
/// denote pages of the main executable. Negative indices indicate "special" hashes,
/// each of a different thing (see cd*Slot constants above).
/// Special slots that are in range but not present are zeroed out. Unallocated special
/// slots are also presumed absent; this is not an error. (Thus the range of special
/// slots can be extended at will.)
///
/// HOW TO MANAGE COMPATIBILITY:
/// Each CodeDirectory has a format (compatibility) version. Two constants control
/// versioning:
///	* currentVersion is the version used for newly created CodeDirectories.
///  * compatibilityLimit is the highest version the code will accept as compatible.
/// Test for version < currentVersion to detect old formats that may need special
/// handling; this is done in checkIntegrity(). The current code rejects versions
/// below earliestVersion.
pub struct CodeDirectory {
    /// magic number (CSMAGIC_CODEDIRECTORY)
    pub magic: u32,
    /// total length of CodeDirectory blob
    pub length: u32,
    /// compatibility version
    pub version: u32,
    /// setup and mode flags
    pub flags: u32,
    /// offset of hash slot element at index zero
    pub hashOffset: u32,
    /// offset of identifier string
    pub identOffset: u32,
    /// number of special hash slots
    pub nSpecialSlots: u32,
    /// number of ordinary (code) hash slots
    pub nCodeSlots: u32,
    /// limit to main image signature range
    pub codeLimit: u32,
    /// size of each hash in bytes
    pub hashSize: u8,
    /// type of hash (cdHashType* constants)
    pub hashType: u8,
    /// platform identifier; zero if not platform binary
    pub platform: u8,
    /// log2(page size in bytes), 0 => infinite
    pub pageSize: u8,
    /// unused (must be zero)
    pub spare2: u32,
    /// offset of optional scatter vector (zero if absent)
    pub scatterOffset: u32,
    /// offset of optional teamID string
    pub teamIDOffset: u32,
    /// unused (most be zero)
    pub spare3: u32,
    /// limit to main image signature range, 64 bits
    pub codeLimit64: u64,
    /// offset of executable segment
    pub execSegBase: u64,
    /// limit of executable segment
    pub execSegLimit: u64,
    /// exec segment flags
    pub execSegFlags: u64,
}

/// earliest supported version
pub const earliestVersion: u32 = 0x20001;
/// first version to support scatter option
pub const supportsScatter: u32 = 0x20100;
/// first version to support team ID option
pub const supportsTeamID: u32 = 0x20200;
/// first version to support codeLimit64
pub const supportsCodeLimit64: u32 = 0x20300;
/// first version to support exec base and limit
pub const supportsExecSegment: u32 = 0x20400;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BlobIndex {
    /// type of entry
    pub typ: u32,
    /// offset of entry
    pub offset: u32,
}

impl SuperBlob {
    pub fn parse<O: ByteOrder, T: BufRead>(buf: &mut T) -> Result<SuperBlob, Box<Error>> {
        let mut sb = SuperBlob {
            magic: buf.read_u32::<O>()?,
            length: buf.read_u32::<O>()?,
            count: buf.read_u32::<O>()?,
            index: vec![],
        };

        // index entries follow immediately after the SuperBlob meta data
        (0..sb.count as usize).for_each(|_| match (buf.read_u32::<O>(), buf.read_u32::<O>()) {
            (Ok(typ), Ok(offset)) => sb.index.push(Some(BlobIndex { typ, offset })),
            _ => sb.index.push(None),
        });

        Ok(sb)
    }
}

macro_rules! cond(
    ($($pred:expr => $body:block),+ _ => $default:block) => (
        $(if $pred $body else)+

        $default
    )
);

impl CodeDirectory {
    pub fn parse<O: ByteOrder, T: BufRead>(buf: &mut T) -> Result<CodeDirectory, Box<Error>> {
        Ok(CodeDirectory {
            magic: buf.read_u32::<O>()?,
            length: buf.read_u32::<O>()?,
            version: buf.read_u32::<O>()?,
            flags: buf.read_u32::<O>()?,
            hashOffset: buf.read_u32::<O>()?,
            identOffset: buf.read_u32::<O>()?,
            nSpecialSlots: buf.read_u32::<O>()?,
            nCodeSlots: buf.read_u32::<O>()?,
            codeLimit: buf.read_u32::<O>()?,
            hashSize: buf.read_u8()?,
            hashType: buf.read_u8()?,
            platform: buf.read_u8()?,
            pageSize: buf.read_u8()?,
            spare2: buf.read_u32::<O>()?,
            ..Default::default()
        })
    }

    pub fn hash_type_str<'a>(&self) -> Result<&'a str, Box<Error>> {
        match self.hashType as u32 {
            CS_HASHTYPE_SHA1 => Ok("SHA-1"),
            CS_HASHTYPE_SHA256 => Ok("SHA-256"),
            _ => unimplemented!(),
        }
    }

    pub fn team_id<T: AsRef<[u8]>>(&self, buf: &mut Cursor<T>) -> Result<String, Box<Error>> {
        cond!(
            self.version >= supportsTeamID => {
                // buf.seek(SeekFrom::Current(self.teamIDOffset as i64))?;
                let team_id = read_string_to_nul(buf)?;
                Ok(team_id)
            }
            _ => { Err(From::from("team id not supported in version")) }
        )
    }

    pub fn cd_hash<T: AsRef<[u8]>>(&self, buf: &mut Cursor<T>) -> Result<Vec<u8>, Box<Error>> {
        buf.seek(SeekFrom::Current(self.hashOffset as i64))?;
        let mut hash_buf = vec![0u8; 160 / 8];
        buf.read_exact(&mut hash_buf)?;
        Ok(hash_buf)
    }
}

#[derive(Debug, Clone)]
pub enum CodeSignature {
    Parsed {
        /// Magic type
        magic: u32,
        /// Offset
        offset: u32,
        /// Size
        size: u32,
        /// SuperBlob
        super_blob: Option<SuperBlob>,
        /// BlobIndex for CodeDirectory
        cd_blob_idx: Option<BlobIndex>,
        /// `CodeDirectory`
        code_directory: Option<CodeDirectory>,
        /// Identifier string
        identifier: Option<String>,
        /// Team Identifier
        team_id: Option<String>,
        /// Hash Type
        hash_type: Option<String>,
        /// Hash value
        cd_hash: Option<String>,
    },
    NotImplemented,
}

fn read_string_to_nul<T: AsRef<[u8]>>(buf: &mut Cursor<T>) -> Result<String, Box<Error>> {
    let mut ident = vec![];
    let sz = buf.read_until(0x00, &mut ident)?;
    Ok(str::from_utf8(&ident[0..sz - 1])?.to_string())
}

impl CodeSignature {
    /// Parse a code signature
    pub fn parse<T: AsRef<[u8]>>(
        offset: u32,
        size: u32,
        buf: &mut Cursor<T>,
    ) -> Result<CodeSignature, Box<Error>> {
        let pos = buf.position();
        let magic = buf.read_u32::<BigEndian>()?;
        match magic {
            CSMAGIC_EMBEDDED_SIGNATURE => {
                buf.seek(SeekFrom::Current(-4))?;
                let sb = SuperBlob::parse::<BigEndian, Cursor<T>>(buf)?;

                buf.set_position(pos);
                let blob = CodeSignature::find_code_directory(&sb)?;
                let cd_offset = blob.offset;

                buf.set_position(pos);
                buf.seek(SeekFrom::Current(cd_offset as i64))?;
                let cd = CodeDirectory::parse::<BigEndian, Cursor<T>>(buf)?;

                buf.set_position(pos);
                buf.seek(SeekFrom::Current((cd_offset + cd.identOffset) as i64))?;
                let identifier = read_string_to_nul(buf)?;

                buf.seek(SeekFrom::Current(cd.teamIDOffset as i64))?;
                let team_id = cd.team_id(buf)?;

                let hash_type = cd.hash_type_str()?.to_string();

                Ok(CodeSignature::Parsed {
                    magic,
                    offset,
                    size,
                    super_blob: Some(sb),
                    cd_blob_idx: Some(blob),
                    code_directory: Some(cd),
                    identifier: Some(identifier),
                    team_id: Some(team_id),
                    hash_type: Some(hash_type),
                    cd_hash: Some("".to_string()),
                })
            }
            _ => {
                println!("println! magic: {:08x}", magic);
                unimplemented!()
            }
        }
    }

    /// Sample code to locate the CodeDirectory from an embedded signature blob
    pub fn find_code_directory(embedded: &SuperBlob) -> Result<BlobIndex, Box<Error>> {
        if embedded.magic == CSMAGIC_EMBEDDED_SIGNATURE {
            for idx in 0..embedded.count as usize {
                if let Some(blob) = &embedded.index[idx] {
                    if blob.typ == CSSLOT_CODEDIRECTORY {
                        return Ok(blob.clone());
                    }
                }
            }
        }
        unimplemented!()
    }
}

#[cfg(test)]
pub mod tests {
    use codedir::CodeDirectory;

    #[test]
    fn test_code_directory() {
        let cd = CodeDirectory {
            ..Default::default()
        };
        assert_eq!(cd.magic, 0)
    }
}
