/**
 * Simpleauth config
 */

use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(name = "simpleauth")]
pub struct Config {
    //// Host to listen to
    #[structopt(long, short, default_value="localhost")]
    pub host: String,

    //// Port to listen to
    #[structopt(long, short, default_value="3141")]
    pub port: u16,

    //// Verbose log output
    #[structopt(long, short)]
    pub verbose: bool
}

lazy_static! {
    pub static ref CFG: Config = Config::from_args();
}
