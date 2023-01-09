# SDSParser

This tool is a parser for NTFS file system `$Secure:$SDS` stream. For more details in regards to $SDS artifact you can read my blog 📝 : https://u0041.co/blog/post/5

Python bindings: https://github.com/AbdulRhmanAlfaifi/SDSParser-py

## Library Usage

```rust
use sds_parser::SDSParser;
use std::fs::File;
let mut infile = File::open("samples/sds").unwrap();
for entry in SDSParser::from_reader(&mut infile) {
    println!("{:?}", entry);
}
```

## Binary Usage

```bash
sds_parser 0.1.0
AbdulRhman Alfaifi <@A__ALFAIFI>
NTFS Security Descriptor Stream ($Secure:$SDS) parser

USAGE:
    sds_parser [OPTIONS] [SECURE_FILE]

ARGS:
    <SECURE_FILE>    $Secure:$SDS file path

OPTIONS:
    -h, --help                      Print help information
    -i, --security-ids <ID>...      Output records only corresponding to these security IDs
    -o, --output <FILE>             Sets output file name [default: STDOUT]
        --output-format <FORMAT>    Sets output format [default: jsonl] [possible values: jsonl,csv]
    -V, --version
```

## Example Record
```json
{
  "hash": 855557835,
  "id": 256,
  "security_descriptor": {
    "owner_sid": "S-1-5-18",
    "group_sid": "S-1-5-32-544",
    "dacl": {
      "revision": 2,
      "count": 2,
      "entries": [
        {
          "ace_type": "ACCESS_ALLOWED",
          "ace_flags": "(empty)",
          "data": {
            "access_rights": 1179785,
            "sid": "S-1-5-18"
          }
        },
        {
          "ace_type": "ACCESS_ALLOWED",
          "ace_flags": "(empty)",
          "data": {
            "access_rights": 1179785,
            "sid": "S-1-5-32-544"
          }
        }
      ]
    },
    "sacl": null
  }
}
```

## References

* https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20(NTFS).asciidoc#access_control
* https://www.ntfs.com/ntfs-permissions-file-structure.htm
