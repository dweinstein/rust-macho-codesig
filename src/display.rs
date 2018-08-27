use codedir::{CodeSignature, SuperBlob};
use consts::CSMAGIC_EMBEDDED_SIGNATURE;
use std::fmt;

impl fmt::Display for SuperBlob {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.magic {
            CSMAGIC_EMBEDDED_SIGNATURE => write!(
                f,
                "is an embedded signature of {} bytes, and {} blobs",
                self.length, self.count
            ),
            _ => unimplemented!(),
        }
    }
}

// TODO:

impl fmt::Display for CodeSignature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CodeSignature::Embedded {
                magic: CSMAGIC_EMBEDDED_SIGNATURE,
                offset,
                size,
                super_blob: Some(sb),
                cd_blob_idx: Some(bi),
                code_directory: Some(cd),
                identifier,
                team_id,
                hash_type,
                cd_hash,
            } => write!(
                f,
                r"Blob at offset {} ({} bytes) is an embedded signature of {} bytes, and {} blobs
        Blob 0: Type: {} @{}: Code Directory ({} bytes)
                Version:     {:x}
                Flags:       {} (0x{:x})
                CodeLimit:   0x{:x}
                Identifier:  {:?}
                Team ID:     {:?}
                CDHash:      {:?}
                # of Hashes: {} code + {} special
                Hashes @{} size: {} Type: {:?}
                ",
                offset,
                size,
                sb.length,
                sb.count,
                bi.typ,
                bi.offset,
                cd.length,
                cd.version,
                "none",
                cd.flags,
                cd.codeLimit,
                identifier,
                team_id,
                cd_hash,
                cd.nCodeSlots,
                cd.nSpecialSlots,
                cd.hashOffset,
                cd.hashSize,
                hash_type
            ),
            _ => unimplemented!(),
        }
    }
}
