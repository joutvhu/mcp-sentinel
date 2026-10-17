use keyring::Entry;

pub const SERVICE_NAME: &str = "mcp-sentinel";

pub fn set_secret(key: &str, value: &str) -> Result<(), keyring::Error> {
    let entry = Entry::new(SERVICE_NAME, key)?;
    entry.set_password(value)
}

pub fn get_secret(key: &str) -> Result<String, keyring::Error> {
    let entry = Entry::new(SERVICE_NAME, key)?;
    entry.get_password()
}

pub fn delete_secret(key: &str) -> Result<(), keyring::Error> {
    let entry = Entry::new(SERVICE_NAME, key)?;
    entry.delete_credential()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_roundtrip() {
        let key = "MCP_SENTINEL_UNIT_TEST_KEY";
        let val = "test_val_12345";
        match set_secret(key, val) {
            Ok(_) => {
                let res_get = get_secret(key);
                assert_eq!(res_get.unwrap(), val);

                let res_del = delete_secret(key);
                assert!(res_del.is_ok());
            }
            Err(e) => {
                eprintln!(
                    "[vault_test] Secure storage not available in this environment ({:?}), skipping.",
                    e
                );
            }
        }
    }
}
