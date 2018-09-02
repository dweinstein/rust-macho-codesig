use std::io;
use std::str;

pub use mach_object::MachError;

use failure::Error;

#[derive(Debug, Fail)]
pub enum CDMachError {
    #[fail(display = "fail to interpret a sequence of u8 as a string, {}.", _0)]
    Utf8Error(#[cause] str::Utf8Error),

    #[fail(display = "fail to do I/O operations, {}.", _0)]
    IoError(#[cause] io::Error),

    #[fail(display = "team id not supported in this version {}.", _0)]
    TeamIDNotSupportedVersion(u32),

    #[fail(display = "No Team ID")]
    NoTeamId,

    #[fail(display = "No Identifier")]
    NoIdentifier,

    #[fail(display = "No Code Directory")]
    NoCodeDirectory,
}

impl From<str::Utf8Error> for CDMachError {
    fn from(err: str::Utf8Error) -> Self {
        CDMachError::Utf8Error(err)
    }
}

impl From<io::Error> for CDMachError {
    fn from(err: io::Error) -> Self {
        CDMachError::IoError(err)
    }
}

pub type Result<T> = ::std::result::Result<T, Error>;
