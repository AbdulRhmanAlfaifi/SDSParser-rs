use clap::{Arg, Command};
use csv::Writer;
use sds_parser::SDSParser;
use serde_json;
use std::fs::File;
use std::io::Write;

macro_rules! init_args {
    ($default_output_name:expr) => {
        Command::new(env!("CARGO_PKG_NAME"))
            .version(env!("CARGO_PKG_VERSION"))
            .author("AbdulRhman Alfaifi <@A__ALFAIFI>")
            .about(env!("CARGO_PKG_DESCRIPTION"))
            .arg(
                Arg::new("secure_file")
                    .value_name("SECURE_FILE")
                    .required(true)
                    .help("$Secure:$SDS file path"),
            )
            .arg(
                Arg::new("output")
                    .short('o')
                    .long("output")
                    .value_name("FILE")
                    .help("Sets output file name")
                    .takes_value(true)
                    .default_value($default_output_name),
            )
            .arg(
                Arg::new("output_format")
                    .long("output-format")
                    .value_name("FORMAT")
                    .help("Sets output format")
                    .takes_value(true)
                    .possible_values(["jsonl", "csv"])
                    .default_value("jsonl"),
            )
            .arg(
                Arg::new("security_ids")
                    .short('i')
                    .long("security-ids")
                    .value_name("ID")
                    .help("Output records only corresponding to these security IDs")
                    .takes_value(true)
                    .multiple_values(true),
            )
    };
}

fn main() {
    let matches = init_args!("STDOUT").get_matches();

    let mut headers_printed = false;

    let mut output_stream: Box<dyn Write> = match matches.value_of("output").unwrap() {
        "STDOUT" => Box::new(std::io::stdout()),
        path => {
            let out_file = File::create(path).expect(&format!("Error opening the path '{}'", path));
            Box::new(out_file)
        }
    };

    let mut infile = File::open(matches.value_of("secure_file").unwrap()).unwrap();
    for i in SDSParser::from_reader(&mut infile) {
        match i {
            Ok(entry) => match matches.value_of("output_format").unwrap() {
                "csv" => {
                    let mut csv_writer = Writer::from_writer(&mut output_stream);
                    if !headers_printed {
                        csv_writer
                            .write_record(vec![
                                "hash",
                                "id",
                                "owner_sid",
                                "group_sid",
                                "dacl",
                                "sacl",
                            ])
                            .expect("Error writing CSV headers");
                        headers_printed = true;
                    }
                    match matches.values_of("security_ids") {
                        Some(ids) => {
                            for i in ids {
                                if i == &entry.id.to_string() {
                                    csv_writer
                                        .write_record(vec![
                                            entry.hash.to_string(),
                                            entry.id.to_string(),
                                            format!("{}", entry.security_descriptor.owner_sid),
                                            format!("{}", entry.security_descriptor.group_sid),
                                            format!(
                                                "{}",
                                                serde_json::to_string(
                                                    &entry.security_descriptor.dacl
                                                )
                                                .unwrap()
                                            ),
                                            format!(
                                                "{}",
                                                serde_json::to_string(
                                                    &entry.security_descriptor.sacl
                                                )
                                                .unwrap()
                                            ),
                                        ])
                                        .expect("Error writing CSV records");
                                }
                            }
                        }
                        None => {
                            csv_writer
                                .write_record(vec![
                                    entry.hash.to_string(),
                                    entry.id.to_string(),
                                    format!("{}", entry.security_descriptor.owner_sid),
                                    format!("{}", entry.security_descriptor.group_sid),
                                    format!(
                                        "{}",
                                        serde_json::to_string(&entry.security_descriptor.dacl)
                                            .unwrap()
                                    ),
                                    format!(
                                        "{}",
                                        serde_json::to_string(&entry.security_descriptor.sacl)
                                            .unwrap()
                                    ),
                                ])
                                .expect("Error writing CSV records");
                        }
                    }
                }
                _ => match matches.values_of("security_ids") {
                    Some(ids) => {
                        for i in ids {
                            if i == &entry.id.to_string() {
                                output_stream
                                    .write(
                                        format!("{}\n", serde_json::to_string(&entry).unwrap())
                                            .as_bytes(),
                                    )
                                    .expect("Error writing JSONL record");
                            }
                        }
                    }
                    None => {
                        output_stream
                            .write(
                                format!("{}\n", serde_json::to_string(&entry).unwrap()).as_bytes(),
                            )
                            .expect("Error writing JSONL record");
                    }
                },
            },
            Err(e) => {
                println!("{}", e);
            }
        }
    }
}
