use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Name of the person to greet
    #[command(subcommand)]
    pub(crate) command: DumpType,

    /// Output folder
    #[arg(short, long, default_value = "")]
    pub(crate) path: String,

}

#[derive(Subcommand, Debug)]
pub enum DumpType {
    /// Dump all processes with this name.
    Name {
        name: String,
    },
    /// Dump specific process by pid.
    Pid {
        pid: u32,
    },
}