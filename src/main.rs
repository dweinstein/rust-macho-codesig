#[macro_use]
extern crate slog;
extern crate slog_bunyan;
extern crate slog_stdlog;

#[macro_use]
extern crate failure;

extern crate byteorder;
extern crate hex;
extern crate hexdump;
extern crate mach_object;
extern crate ring;

pub mod codedir;
pub mod consts;
pub mod display;
pub mod errors;

pub use codedir::*;
pub use consts::*;
use mach_object::get_arch_name_from_types;
pub use mach_object::MachHeader;
pub use slog::Logger;

use slog::Drain;

use mach_object::{FatArch, LoadCommand, MachCommand, OFile};
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
            handle_mach_file(log, header, commands, &mut cur, 0 /* Not fat */)?
        }
        Ok(OFile::FatFile {
            magic,
            files: ref slices,
        }) => {
            trace!(log, "FAT magic: 0x{:x}, files: {:?}", magic, slices);
            for slice in slices {
                match slice {
                    (FatArch { ref offset, .. }, OFile::MachFile { header, commands }) => {
                        trace!(log, "file offset: {}", offset);
                        cur.set_position(*offset as u64);
                        handle_mach_file(log.clone(), header, commands, &mut cur, *offset)?;
                    }
                    _ => unimplemented!(),
                }
            }
        }
        _ => unimplemented!(),
    }

    Ok(())
}

fn handle_mach_file<T: AsRef<[u8]>>(
    log: Logger,
    header: &MachHeader,
    commands: &Vec<MachCommand>,
    cur: &mut Cursor<T>,
    slice_offset: u32,
) -> Result<()> {
    assert_eq!(header.ncmds as usize, commands.len());

    trace!(
        log,
        "macho header: {:?} cur pos: {}",
        header,
        cur.position()
    );
    for (i, &MachCommand(ref cmd, _cmdsize)) in commands.iter().enumerate() {
        if let LoadCommand::CodeSignature { 0: link } = &cmd {
            info!(
                log,
                "LC {}: LC_CODE_SIGNATURE        Offset: {}, Size: {}", i, link.off, link.size
            );
            cur.set_position(slice_offset as u64 + link.off as u64);
            if let Some(cs) =
                CodeSignature::parse(log.clone(), slice_offset + link.off, link.size, cur)?
            {
                trace!(log, "{:?}", cs);
                cs.blobs.unwrap().iter().for_each(|ref blob| {
                    if let Blob::CodeDirectory { ref cd_hash, .. } = blob {
                        let cpuinfo = get_arch_name_from_types(header.cputype, header.cpusubtype)
                            .unwrap_or("unk");
                        info!(log, "code signature"; "cd_hash" => cd_hash, "cpuinfo" => cpuinfo);
                    }
                });
            } else {
                warn!(log, "Skipped {:?}", cmd);
            }
        }
    }
    Ok(())
}
