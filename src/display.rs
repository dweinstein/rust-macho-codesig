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
// impl fmt::Display for CodeSignature {
//     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//         let team_id = cd.team_id(cur);
//         let hash_type = match cd.hashType as u32 {
//             consts::CS_HASHTYPE_SHA1 => "SHA-1",
//             consts::CS_HASHTYPE_SHA256 => "SHA-256",
//             _ => unimplemented!(),
//         };
//         cur.set_position(link.off as u64);
//         let hash_str = cd.cd_hash(cur)?;
//         write!(f, "Blob at offset {} ({} bytes) {}", link.off, link.size, sb);
//         write!(f, 
//             "        Blob 0: Type: {} @{}: Code Directory ({} bytes)",
//             bi.typ, bi.offset, cd.length
//         );
//         write!(f, "                Version:     {:x}", cd.version);
//         write!(f, "                Flags:       {} (0x{:x})", "none", cd.flags);
//         write!(f, "                CodeLimit:   0x{:x}", cd.codeLimit);
//         write!(f, "                Identifier:  {}", identifier);
//         write!(f, "                Team ID:     {:?}", team_id);
//         write!(f, "                CDHash:      {:?}", hash_str); // XXX: BROKEN
//         write!(f, 
//             "                # of Hashes: {} code + {} special",
//             cd.nCodeSlots, cd.nSpecialSlots
//         );
//         write!(f, 
//             "                Hashes @{} size: {} Type: {}",
//             cd.hashOffset, cd.hashSize, hash_type
//         );
//     }
// }
