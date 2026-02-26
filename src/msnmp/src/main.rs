//! Main doc.
use clap::Parser as _;
use exitfailure::ExitFailure;
use msnmp::{self, Params};

fn main() -> Result<(), ExitFailure> {
    let args = Params::try_parse()?;
    msnmp::run(args)?;

    Ok(())
}
