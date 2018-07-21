use byteorder::{LittleEndian, WriteBytesExt, ReadBytesExt};
use std::io::Cursor;
use std::collections::HashMap;
use errors::common::CommonError;
use std::path::PathBuf;
use utils::environment::EnvironmentUtils;

pub fn usize_to_byte_array(n: usize) -> Vec<u8> {
    let mut wtr: Vec<u8> = Vec::new();
    wtr.write_u64::<LittleEndian>(n as u64).unwrap();
    wtr
}

pub fn byte_array_to_usize(v: Vec<u8>) -> usize {
    let mut rdr = Cursor::new(v);
    rdr.read_u64::<LittleEndian>().unwrap() as usize
}

pub fn parse_options(options: HashMap<String, String>) -> Result<HashMap<String, String>, CommonError> {
    // TODO: Support in-memory storage type
    match options.get("storage_type") {
        Some(s) => {
            if s != "sqlite" {
                return Err(CommonError::InvalidStructure(format!("storage_type needs to be sqlite")))
            }
        }
        None => return Err(CommonError::InvalidStructure(format!("storage_type needs to be provided")))
    }
    if options.get("storage_path").is_none() {
        // TODO: Make sure storage path is valid OsString
        return Err(CommonError::InvalidStructure(format!("storage_path needs to be provided")))
    }
    Ok(options)
}

// TODO: This should be enhanced further
pub fn create_storage_options(base_storage_path: Option<&str>, extra_paths: Vec<&str>) -> HashMap<String, String> {
    let mut options: HashMap<String, String> = HashMap::new();
    options.insert("storage_type".to_string(), "sqlite".to_string());
    let mut path = match base_storage_path {
        Some(m) => {
            let mut pf = PathBuf::new();
            pf.push(m);
            pf
        },
        None => {
            EnvironmentUtils::tmp_path()
        }
    };
    for ep in extra_paths{
        path.push(ep);
    }
    let storage_path = path.to_str().unwrap().to_owned();
    options.insert("storage_path".to_string(), storage_path);
    options
}

pub mod tests {
    use super::*;
    use utils::environment::EnvironmentUtils;
    use services::microledger::constants::*;
    use std::collections::HashMap;
    use services::microledger::microledger::Microledger;
    use services::microledger::did_microledger::DidMicroledger;

    pub fn valid_storage_options() -> HashMap<String, String>{
        let mut options: HashMap<String, String> = HashMap::new();
        let mut path = EnvironmentUtils::tmp_path();
        path.push("did_ml_path");
        let storage_path = path.to_str().unwrap().to_owned();
        options.insert("storage_type".to_string(), "sqlite".to_string());
        options.insert("storage_path".to_string(), storage_path);
        options
    }

    pub fn get_new_microledger(did: &str) -> DidMicroledger {
        let options = valid_storage_options();
        DidMicroledger::new(did, options).unwrap()
    }

    pub fn get_4_txns() -> Vec<String> {
        let txn = r#"{"protocolVersion":1,"txnVersion":1,"operation":{"dest":"75KUW8tPUQNBS4W7ibFeY8","type":"1"}}"#;
        let txn_2 = r#"{"protocolVersion":1,"txnVersion":1,"operation":{"dest":"75KUW8tPUQNBS4W7ibFeY8","type":"1","verkey":"6baBEYA94sAphWBA5efEsaA6X2wCdyaH7PXuBtv2H5S1"}}"#;
        let txn_3 = r#"{"protocolVersion":1,"txnVersion":1,"operation":{"authorizations":["all"],"type":"2","verkey":"6baBEYA94sAphWBA5efEsaA6X2wCdyaH7PXuBtv2H5S1"}}"#;
        let txn_4 = r#"{"protocolVersion":1,"txnVersion":1,"operation":{"address":"https://agent.example.com","type":"3","verkey":"6baBEYA94sAphWBA5efEsaA6X2wCdyaH7PXuBtv2H5S1"}}"#;
        vec![txn.to_string(), txn_2.to_string(), txn_3.to_string(), txn_4.to_string()]
    }

    pub fn get_10_txns() -> Vec<String> {
        let txns = vec![
            r#"{"protocolVersion":1,"txnVersion":1,"operation":{"authorizations":[],"type":"2","verkey":"6baBEYA94sAphWBA5efEsaA6X2wCdyaH7PXuBtv2H5S1"}}"#,
            r#"{"protocolVersion":1,"txnVersion":1,"operation":{"authorizations":["all","add_key","rem_key"],"type":"2","verkey":"6baBEYA94sAphWBA5efEsaA6X2wCdyaH7PXuBtv2H5S1"}}"#,
            r#"{"protocolVersion":1,"txnVersion":1,"operation":{"address":"https://agent1.example.com:9080","type":"3","verkey":"6baBEYA94sAphWBA5efEsaA6X2wCdyaH7PXuBtv2H5S1"}}"#,
            r#"{"protocolVersion":1,"txnVersion":1,"operation":{"address":"tcp://123.88.912.091:9876","type":"3","verkey":"6baBEYA94sAphWBA5efEsaA6X2wCdyaH7PXuBtv2H5S1"}}"#,
            r#"{"protocolVersion":2,"txnVersion":2,"operation":{"address":"https://agent1.example.com","type":"3","verkey":"6baBEYA94sAphWBA5efEsaA6X2wCdyaH7PXuBtv2H5S1"}}"#,
            r#"{"protocolVersion":2,"txnVersion":1,"operation":{"address":"http://agent2.example.org","type":"3","verkey":"6baBEYA94sAphWBA5efEsaA6X2wCdyaH7PXuBtv2H5S1"}}"#
        ];
        let mut txns: Vec<String> = txns.iter().map(|s|s.to_string()).collect();
        for txn in get_4_txns() {
            txns.push(txn)
        }
        txns
    }

    #[test]
    fn test_parse_valid_options() {
        let options = valid_storage_options();
        let expected_options: HashMap<String, String> = options.clone();
        assert_eq!(parse_options(options).unwrap(), expected_options);
    }

    #[test]
    fn test_parse_options_without_required_keys() {
        let mut options: HashMap<String, String> = HashMap::new();
        options.insert("storage_type".to_string(), "sqlite".to_string());
        assert!(parse_options(options).is_err());

        let mut options: HashMap<String, String> = HashMap::new();
        options.insert("storage_path".to_string(), "storage_path".to_string());
        assert!(parse_options(options).is_err());

        let mut options: HashMap<String, String> = HashMap::new();
        options.insert("unknown key".to_string(), "unknown value".to_string());
        assert!(parse_options(options).is_err());
    }

    #[test]
    fn test_parse_options_incorrect_storage_type() {
        let mut options: HashMap<String, String> = HashMap::new();
        options.insert("storage_type".to_string(), "mysql".to_string());
        options.insert("storage_path".to_string(), "/tmp".to_string());
        let expected_options: HashMap<String, String> = options.clone();
        assert!(parse_options(options).is_err());
    }
}