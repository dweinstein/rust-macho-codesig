#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]

/// single Requirement blob
pub const CSMAGIC_REQUIREMENT: u32 = 0xfade0c00;
/// Requirements vector (internal requirements)
pub const CSMAGIC_REQUIREMENTS: u32 = 0xfade0c01;
/// CodeDirectory blob
pub const CSMAGIC_CODEDIRECTORY: u32 = 0xfade0c02;
/// embedded form of signature data
pub const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade0cc0;
/// multi-arch collection of embedded signatures
pub const CSMAGIC_DETACHED_SIGNATURE: u32 = 0xfade0cc1;
/// used for the cms blob
pub const CSMAGIC_BLOBWRAPPER: u32 = 0xfade0b01;

pub const CS_PAGE_SIZE: u32 = 4096;

pub const CS_HASHTYPE_SHA1: u32 = 1;
pub const CS_HASHTYPE_SHA256: u32 = 2;
pub const CS_HASHTYPE_SHA256_TRUNCATED: u32 = 3;

pub const CS_HASH_SIZE_SHA1: u32 = 20;
pub const CS_HASH_SIZE_SHA256: u32 = 32;
pub const CS_HASH_SIZE_SHA256_TRUNCATED: u32 = 20;

pub const CSSLOT_CODEDIRECTORY: u32 = 0;
pub const CSSLOT_INFOSLOT: u32 = 1;
pub const CSSLOT_REQUIREMENTS: u32 = 2;
pub const CSSLOT_RESOURCEDIR: u32 = 3;
pub const CSSLOT_APPLICATION: u32 = 4;
pub const CSSLOT_ENTITLEMENTS: u32 = 5;
pub const CSSLOT_ALTERNATE_CODEDIRECTORIES: u32 = 0x1000;
pub const CSSLOT_ALTERNATE_CODEDIRECTORY_MAX: u32 = 5;
pub const CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT: u32 =
    CSSLOT_ALTERNATE_CODEDIRECTORIES + CSSLOT_ALTERNATE_CODEDIRECTORY_MAX;
pub const CSSLOT_CMS_SIGNATURE: u32 = 0x10000;

pub const kSecCodeSignatureAdhoc: u32 = 2;
