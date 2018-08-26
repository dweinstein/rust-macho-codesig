#[macro_use]
extern crate slog;
extern crate slog_bunyan;

extern crate byteorder;
extern crate mach_object;

use mach_object::MachHeader;
use slog::Drain;

use mach_object::{LoadCommand, MachCommand, OFile};
use std::env;
use std::error::Error;
use std::fs::File;
use std::io::{Cursor, Read};
use std::sync::Mutex;

pub mod codedir;
pub mod consts;
pub mod display;

pub use codedir::*;
pub use consts::*;

pub fn main() -> Result<(), Box<Error>> {
    let root = slog::Logger::root(
        Mutex::new(slog_bunyan::default(std::io::stdout())).fuse(),
        o!("name" => "codesign"),
    );

    let log = root.new(o!("child" => 1));

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

    match OFile::parse(&mut cur) {
        Ok(OFile::MachFile {
            ref header,
            ref commands,
        }) => handle_mach_file(header, commands, &mut cur)?,
        Ok(OFile::FatFile {
            magic: _magic,
            files: _files,
        }) => unimplemented!(),
        _ => unimplemented!(),
    }

    Ok(())
}

fn handle_mach_file<T: AsRef<[u8]>>(
    header: &MachHeader,
    commands: &Vec<MachCommand>,
    cur: &mut Cursor<T>,
) -> Result<(), Box<Error>> {
    assert_eq!(header.ncmds as usize, commands.len());

    println!("macho header: {:?}", header);

    for (i, &MachCommand(ref cmd, _cmdsize)) in commands.iter().enumerate() {
        if let &LoadCommand::CodeSignature { 0: ref link } = cmd {
            println!(
                "LC {}: LC_CODE_SIGNATURE        Offset: {}, Size: {}",
                i, link.off, link.size
            );
            cur.set_position(link.off as u64);
            let cs = CodeSignature::parse(cur)?;
            if let CodeSignature::Parsed {
                super_blob: Some(sb),
                cd_blob_idx: Some(bi),
                code_directory: Some(cd),
                identifier: Some(identifier),
                ..
            } = &cs
            {
                let team_id = cd.team_id(cur);
                let hash_type = match cd.hashType as u32 {
                    consts::CS_HASHTYPE_SHA1 => "SHA-1",
                    consts::CS_HASHTYPE_SHA256 => "SHA-256",
                    _ => unimplemented!(),
                };
                cur.set_position(link.off as u64);
                // let hash_str = cd.cd_hash(cur)?;
                println!("Blob at offset {} ({} bytes) {}", link.off, link.size, sb);
                println!(
                    "        Blob 0: Type: {} @{}: Code Directory ({} bytes)",
                    bi.typ, bi.offset, cd.length
                );
                println!("                Version:     {:x}", cd.version);
                println!("                Flags:       {} (0x{:x})", "none", cd.flags);
                println!("                CodeLimit:   0x{:x}", cd.codeLimit);
                println!("                Identifier:  {}", identifier);
                println!("                Team ID:     {:?}", team_id);
                println!("                CDHash:      {:?}", Some("TODO")); // XXX: BROKEN
                println!(
                    "                # of Hashes: {} code + {} special",
                    cd.nCodeSlots, cd.nSpecialSlots
                );
                println!(
                    "                Hashes @{} size: {} Type: {}",
                    cd.hashOffset, cd.hashSize, hash_type
                );
            }
        }
    }

    Ok(())
}
