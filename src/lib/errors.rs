use thiserror::Error;

#[derive(Debug, Error)]
pub enum SDSParserError {
    #[error("error parsing SDSEntry data, ERROR: {}", err_msg)]
    SDSEntry { err_msg: String },
    #[error("unable to read security descriptor data, ERROR: {}", err_msg)]
    SecurityDescriptor { err_msg: String },
    #[error("Reached end of stream")]
    EndOfStream,
}
