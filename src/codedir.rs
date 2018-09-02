#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]

use byteorder::{ByteOrder, NetworkEndian, ReadBytesExt};
use hex;
use std::io::{BufRead, Cursor, Read, Seek, SeekFrom};
use std::str;

use errors::{CDMachError::*, Result};

use consts::{
    CS_HASHTYPE_SHA1, CS_HASHTYPE_SHA256, CSMAGIC_BLOBWRAPPER, CSMAGIC_CODEDIRECTORY,
    CSMAGIC_EMBEDDED_ENTITLEMENTS, CSMAGIC_EMBEDDED_SIGNATURE, CSMAGIC_REQUIREMENTS,
    CSSLOT_CODEDIRECTORY,
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
    // pub identifier: Option<String>,
    // pub team_id: Option<String>,
    // pub cd_hash: Option<String>,
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
    pub fn parse<O: ByteOrder, T: BufRead>(buf: &mut T) -> Result<SuperBlob> {
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
    pub fn parse<O: ByteOrder, T: BufRead>(buf: &mut T) -> Result<CodeDirectory> {
        let magic = buf.read_u32::<O>()?;
        let length = buf.read_u32::<O>()?;
        let version = buf.read_u32::<O>()?;
        let flags = buf.read_u32::<O>()?;
        let hashOffset = buf.read_u32::<O>()?;
        let identOffset = buf.read_u32::<O>()?;
        let nSpecialSlots = buf.read_u32::<O>()?;
        let nCodeSlots = buf.read_u32::<O>()?;
        let codeLimit = buf.read_u32::<O>()?;
        let hashSize = buf.read_u8()?;
        let hashType = buf.read_u8()?;
        let platform = buf.read_u8()?;
        let pageSize = buf.read_u8()?;
        let spare2 = buf.read_u32::<O>()?;
        let scatterOffset = buf.read_u32::<O>()?;

        let teamIDOffset = if version >= supportsTeamID {
            buf.read_u32::<O>()?
        } else {
            0
        };

        Ok(CodeDirectory {
            magic,
            length,
            version,
            flags,
            hashOffset,
            identOffset,
            nSpecialSlots,
            nCodeSlots,
            codeLimit,
            hashSize,
            hashType,
            platform,
            pageSize,
            spare2,
            scatterOffset,
            teamIDOffset,
            ..Default::default()
        })
    }

    pub fn hash_type_str<'a>(&self) -> Result<&'a str> {
        match self.hashType as u32 {
            CS_HASHTYPE_SHA1 => Ok("SHA-1"),
            CS_HASHTYPE_SHA256 => Ok("SHA-256"),
            _ => unimplemented!(),
        }
    }

    pub fn team_id<T: AsRef<[u8]>>(&self, buf: &mut Cursor<T>) -> Result<String> {
        cond!(
            self.version >= supportsTeamID => {
                let team_id = read_string_to_nul(buf)?;
                Ok(team_id)
            }
            _ => { Err(TeamIDNotSupportedVersion(self.version).into()) }
        )
    }

    pub fn cd_hash<T: AsRef<[u8]>>(&self, buf: &mut Cursor<T>) -> Result<Vec<u8>> {
        let mut hash_buf = vec![0u8; self.hashSize as usize];
        buf.read_exact(&mut hash_buf)?;
        Ok(hash_buf)
    }
}

#[derive(Debug)]
pub enum Blob {
    CodeDirectory {
        /// `BlobIndex`
        index: BlobIndex,
        /// `CodeDirectory`
        code_directory: CodeDirectory,
        /// Identifier string
        identifier: Result<String>,
        /// Team Identifier
        team_id: Result<String>,
        /// Hash Type (e.g., "SHA-1", "SHA-256")
        hash_type: Option<String>,
        /// CodeDirectory Hash value (CDHash)
        cd_hash: Result<Vec<u8>>,
    },
    Requirements  { index: BlobIndex },
    Entitlements  { index: BlobIndex },
    Signed        { index: BlobIndex },
    Unknown       { index: BlobIndex },
}

#[derive(Debug)]
pub enum CodeSignature {
    Embedded {
        /// Offset
        offset: u32,
        /// Size
        size: u32,
        /// SuperBlob
        super_blob: Option<SuperBlob>,
        /// `BlobIndex` for `CodeDirectory`
        cd_blob_idx: Option<BlobIndex>,
        /// Vector of `Blob` objects
        blobs: Vec<Blob>,
    },
    NotImplemented {
        magic: u32,
    },
}

fn read_string_to_nul<T: AsRef<[u8]>>(buf: &mut Cursor<T>) -> Result<String> {
    let mut ident = vec![];
    let sz = buf.read_until(0x00, &mut ident)?;
    Ok(str::from_utf8(&ident[0..sz - 1])?.to_string())
}

impl CodeSignature {
    /// Load code signatures
    pub fn load_code_signatures(_path: &str) -> Result<Vec<CodeSignature>> {
        unimplemented!()
    }

    /// Parse a code signature
    pub fn lc_code_sig<T: AsRef<[u8]>>(
        offset: u32,
        size: u32,
        buf: &mut Cursor<T>,
    ) -> Result<CodeSignature> {
        let _pos = buf.position();
        let magic = buf.read_u32::<NetworkEndian>()?;
        buf.seek(SeekFrom::Current(-4))?;

        match magic {
            CSMAGIC_EMBEDDED_SIGNATURE => {
                let super_blob = SuperBlob::parse::<NetworkEndian, Cursor<T>>(buf)?;

                let mut blobs: Vec<Blob> = vec![];
                let mut cd_blob_idx: Option<BlobIndex> = None;

                for idx in 0..super_blob.count as usize {
                    // println!("\n\n");
                    if let Some(bi) = &super_blob.index[idx] {
                        buf.set_position((offset + bi.offset) as u64);
                        println!(
                            "=== blob index: typ {:?} @{}, byte offset {:?} ===",
                            bi.typ,
                            bi.offset,
                            offset + bi.offset
                        );

                        let magic = buf.read_u32::<NetworkEndian>()?;
                        let length = buf.read_u32::<NetworkEndian>()?;
                        buf.seek(SeekFrom::Current(-8))?;
                        match magic {
                            CSMAGIC_REQUIREMENTS => {
                                println!(
                                    "> CSMAGIC_REQUIREMENTS {:?} {:x?} len: {}",
                                    bi, magic, length
                                );
                                blobs.push(Blob::Requirements { index: bi.clone() });
                            }
                            CSMAGIC_CODEDIRECTORY => {
                                println!(
                                    "> CSMAGIC_CODEDIRECTORY {:?} {:x?} len: {}",
                                    bi, magic, length
                                );
                                cd_blob_idx = Some(bi.clone());
                                let cd = CodeDirectory::parse::<NetworkEndian, Cursor<T>>(buf)?;
                                println!(
                                    "+ CD.length {} bytes; end of cd {}/{}?",
                                    cd.length,
                                    buf.position(),
                                    buf.position() - offset as u64 - bi.offset as u64
                                );
                                buf.set_position((offset + bi.offset + cd.identOffset) as u64);
                                let identifier = read_string_to_nul(buf);
                                buf.set_position((offset + bi.offset + cd.teamIDOffset) as u64);
                                // buf.seek(SeekFrom::Current(cd.teamIDOffset as i64))?;
                                let team_id = cd.team_id(buf);
                                let hash_type = Some(cd.hash_type_str()?.to_string());
                                // println!("maybe cd offset: {}", buf.position() - offset as u64);
                                // buf.set_position((offset + bi.offset + cd.length) as u64);
                                // buf.set_position(offset as u64);
                                // buf.seek(SeekFrom::Current(
                                //     cd.length as i64 + cd.hashOffset as i64,
                                // ))?;
                                println!(
                                    "+ reading cd hash @ {} (hashOffset is: {})",
                                    buf.position() - offset as u64,
                                    cd.hashOffset
                                );
                                let cd_hash = cd.cd_hash(buf);
                                println!(
                                    "+ cdhash: {} {}",
                                    hash_type.as_ref().unwrap(),
                                    hex::encode(cd_hash.as_ref().unwrap())
                                );
                                blobs.push(Blob::CodeDirectory {
                                    index: bi.clone(),
                                    code_directory: cd,
                                    identifier: Ok(identifier?.clone()),
                                    team_id: Ok(team_id?.clone()),
                                    hash_type: hash_type,
                                    cd_hash: Ok(cd_hash?.clone())
                                });
                            }
                            CSMAGIC_BLOBWRAPPER => {
                                println!(
                                    "> CSMAGIC_BLOBWRAPPER {:?} {:x?} len: {}",
                                    bi, magic, length
                                );
                                blobs.push(Blob::Signed { index: bi.clone() });
                            }
                            CSMAGIC_EMBEDDED_ENTITLEMENTS => {
                                println!(
                                    "> CSMAGIC_EMBEDDED_ENTITLEMENETS {:?} {:x?} len: {}",
                                    bi, magic, length
                                );
                                blobs.push(Blob::Entitlements { index: bi.clone() });
                            }
                            _ => {
                                println!("! UNHANDLED {:?} {:x?} len: {}", bi, magic, length);
                                blobs.push(Blob::Unknown { index: bi.clone() });
                            }
                        };
                    };
                    println!("\n\n");
                };
                Ok(CodeSignature::Embedded {
                    offset,
                    size,
                    super_blob: Some(super_blob),
                    cd_blob_idx: cd_blob_idx,
                    blobs: blobs,
                })
            }
            _ => Ok(CodeSignature::NotImplemented { magic: magic }),
        }
    }

    /// Sample code to locate the CodeDirectory from an embedded signature blob
    pub fn find_code_directory(blob: &SuperBlob) -> Result<BlobIndex> {
        match blob.magic {
            CSMAGIC_EMBEDDED_SIGNATURE => {
                for idx in 0..blob.count as usize {
                    if let Some(bi) = &blob.index[idx] {
                        if bi.typ == CSSLOT_CODEDIRECTORY {
                            return Ok(bi.clone());
                        }
                    }
                }
                Err(NoCodeDirectory.into())
            }
            _ => Err(NoCodeDirectory.into()),
        }
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
