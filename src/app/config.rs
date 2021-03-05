use std::collections::HashMap;
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;

use structopt::StructOpt;
use toml::value::Table;

#[derive(StructOpt, Debug)]
#[structopt(name = "simpleauth")]
pub struct Config {
    //// Host to listen to
    #[structopt(long, short, default_value = "localhost")]
    pub host: String,

    //// Location of config file
    #[structopt(short, long, default_value = "./auth.toml")]
    pub config: String,

    //// Port to listen to
    #[structopt(long, short, default_value = "3141")]
    pub port: u16,

    //// Verbose log output
    #[structopt(long, short)]
    pub verbose: bool,
}

lazy_static! {
    pub static ref CFG: Config = Config::from_args();
    pub static ref CFILE: PathBuf = PathBuf::from(&CFG.config);
    // let raw_auths = get_auth_config(&*CFILE);
    // let auths = parse_auth_config(&raw_auths);
    static ref RAW_AUTHS: Table = get_auth_config(&*CFILE);
    pub static ref AUTHS: HashMap<&'static str, (&'static str, &'static str)> = parse_auth_config(&RAW_AUTHS);
}

fn get_auth_config(file: &PathBuf) -> Table {
    let mut f = File::open(file).expect("Could not open specified config file");
    let mut buffer = String::new();
    f.read_to_string(&mut buffer)
        .expect("Could not read specified config file");
    toml::from_str(&buffer.as_str()).expect("Failed to parse config file (invalid toml?)")
}

fn parse_auth_config(data: &Table) -> HashMap<&str, (&str, &str)> {
    let mut domains: HashMap<&str, (&str, &str)> = HashMap::new();
    let logins = data.get("login").unwrap().as_array().unwrap();

    // TODO: Find more efficient method of compressing this object?
    // without so many branches / adding complicated error handling
    logins.iter().for_each(|table| {
        if let Some(data) = table.as_table() {
            if data.contains_key("name") && data.contains_key("pass") && data.contains_key("domain")
            {
                domains.insert(
                    &data.get("domain").unwrap().as_str().unwrap(),
                    (
                        &data.get("name").unwrap().as_str().unwrap(),
                        &data.get("pass").unwrap().as_str().unwrap(),
                    ),
                );
            }
        }
    });

    domains
}
