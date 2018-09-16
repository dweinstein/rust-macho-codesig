#[macro_use]
extern crate slog;
extern crate slog_bunyan;
extern crate slog_stdlog;

#[macro_use]
extern crate failure;

extern crate byteorder;
extern crate hex;
extern crate mach_object;
extern crate ring;
extern crate hexdump;

pub mod codedir;
pub mod consts;
pub mod display;
pub mod errors;

pub use codedir::*;
pub use consts::*;
pub use mach_object::MachHeader;
pub use slog::Logger;

use slog::Drain;

use mach_object::{LoadCommand, MachCommand, OFile, FatArch};
use std::env;
use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::sync::Mutex;

use errors::Result;

pub fn main() -> Result<()> {
    let root = slog::Logger::root(
        Mutex::new(slog_bunyan::default(std::io::stdout())).fuse(),
        o!("name" => "codesign"),
    );

    let log = root.new(o!());

    let args: Vec<String> = env::args().collect();
    let binary = &args[1];
    trace!(
        log,
        "searching {binary} for macho headers/code signature command",
        binary = binary
    );
    let mut f = File::open(binary).unwrap();
    let mut buf = Vec::new();
    let size = f.read_to_end(&mut buf).unwrap();
    let mut cur = Cursor::new(&buf[..size]);

    match &OFile::parse(&mut cur) {
        Ok(OFile::MachFile { header, commands }) => {
            handle_mach_file(log, header, commands, &mut cur, 0)?
        }
        Ok(OFile::FatFile { magic, files }) => {
            // debug!(log, "FAT magic: 0x{:x}, files: {:?}", magic, files);
            for file in files {
                println!("FAT FILE: {:?}", file);
                match file {
                    (FatArch { offset, .. }, OFile::MachFile { header, commands }) => {
                        println!("file offset: {}", offset);
                        cur.set_position(*offset as u64);
                        handle_mach_file(log.clone(), header, commands, &mut cur, *offset)?;
                    }
                    _ => info!(log, "{:?}", file),
                }
            }
        }
        _ => unimplemented!(),
    }

    Ok(())
}

fn handle_mach_file<T: AsRef<[u8]>>(
    logger: Logger,
    header: &MachHeader,
    commands: &Vec<MachCommand>,
    cur: &mut Cursor<T>,
    slice_offset: u32
) -> Result<()> {
    assert_eq!(header.ncmds as usize, commands.len());

    info!(logger, "macho header: {:?} cur pos: {}", header, cur.position());

    for (i, &MachCommand(ref cmd, _cmdsize)) in commands.iter().enumerate() {
        if let LoadCommand::CodeSignature { 0: link } = &cmd {
            info!(
                logger,
                "LC {}: LC_CODE_SIGNATURE        Offset: {}, Size: {}", i, link.off, link.size
            );
            cur.set_position(slice_offset as u64 + link.off as u64);
            // cur.seek(SeekFrom::Current(link.off as i64))?;

            if let Some(cs) = CodeSignature::parse(logger.clone(), slice_offset + link.off, link.size, cur)? {
              // info!(logger, "{:?}", cs);

              cs.blobs.unwrap().iter().for_each(|ref blob| {
                  if let Blob::CodeDirectory { ref index, ref cd_hash, ..} = blob {
                    println!("cs cd_hash: {:?}\n\n", cd_hash);

                  }
              });
            } else {
              warn!(logger, "Skipped {:?}", cmd);
            }

        }
    }
    Ok(())
}
