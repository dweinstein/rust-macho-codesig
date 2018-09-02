#[macro_use]
extern crate slog;
extern crate slog_bunyan;

#[macro_use]
extern crate failure;

extern crate byteorder;
extern crate hex;
extern crate mach_object;

pub mod codedir;
pub mod consts;
pub mod display;
pub mod errors;

pub use codedir::*;
pub use consts::*;
pub use mach_object::MachHeader;

use slog::Drain;

use mach_object::{LoadCommand, MachCommand, OFile};
use std::env;
use std::fs::File;
use std::io::{Cursor, Read};
use std::sync::Mutex;

use errors::Result;

pub fn main() -> Result<()> {
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
    match &OFile::parse(&mut cur) {
        Ok(OFile::MachFile { header, commands }) => handle_mach_file(header, commands, &mut cur)?,
        // Ok(OFile::FatFile { magic: _, files }) => {
        //     files.iter().for_each(|item| {
        //         match item {
        //             (
        //                 _,
        //                 OFile::MachFile {
        //                     ref header,
        //                     ref commands,
        //                 },
        //             ) => handle_mach_file(header, commands, &mut cur),
        //             _ => { println!("{:?}", item); Ok(()) }
        //         }.expect("macho");
        //     });
        // }
        _ => unimplemented!(),
    }

    Ok(())
}

fn handle_mach_file<T: AsRef<[u8]>>(
    header: &MachHeader,
    commands: &Vec<MachCommand>,
    cur: &mut Cursor<T>,
) -> Result<()> {
    assert_eq!(header.ncmds as usize, commands.len());

    println!("macho header: {:?}", header);

    for (i, &MachCommand(ref cmd, _cmdsize)) in commands.iter().enumerate() {
        if let &LoadCommand::CodeSignature { 0: ref link } = cmd {
            println!(
                "LC {}: LC_CODE_SIGNATURE        Offset: {}, Size: {}",
                i, link.off, link.size
            );
            cur.set_position(link.off as u64);
            let cs = CodeSignature::lc_code_sig(link.off, link.size, cur)?;
            // println!("{:?}", cs);
            println!("display CodeSignature: {}\n\n", cs);
            if let CodeSignature::Embedded { blobs, .. } = cs {
                blobs.iter().for_each(|blob| {
                    println!("{:?}\n\n", blob);
                })
            }
        }
    }
    Ok(())
}
