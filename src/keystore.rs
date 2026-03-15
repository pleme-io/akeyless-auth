use crate::config::KeyProtection;
use crate::error::{Error, Result};
use crate::protocol::Jwk;
use crate::traits::KeyStore;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey};
use security_framework_sys::access_control::{
    kSecAccessControlBiometryAny, kSecAccessControlPrivateKeyUsage,
};

/// macOS Keychain-backed key store with biometric protection.
///
/// Keys are P-256 EC key pairs stored in the Keychain. Every signing
/// operation requires Touch ID (enforced by `kSecAccessControlBiometryAny`).
///
/// With `KeyProtection::SecureEnclave`, the key is generated in the Secure
/// Enclave (requires Apple Developer ID code signing + entitlements).
/// With `KeyProtection::Biometric`, the key is in the software Keychain
/// but still requires Touch ID for every use.
#[derive(Debug)]
pub struct KeychainKeyStore {
    protection: KeyProtection,
}

impl KeychainKeyStore {
    #[must_use]
    pub fn new(protection: KeyProtection) -> Self {
        Self { protection }
    }
}

impl KeyStore for KeychainKeyStore {
    fn generate(&self, label: &str) -> Result<()> {
        if self.exists(label)? {
            return Err(Error::KeyStore(format!(
                "key '{label}' already exists — delete first with `akeyless-auth delete`"
            )));
        }

        // Biometric access control: Touch ID required for every signing operation.
        let flags = kSecAccessControlBiometryAny | kSecAccessControlPrivateKeyUsage;
        let access_control = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenPasscodeSetThisDeviceOnly),
            flags,
        )
        .map_err(|e| Error::KeyStore(format!("failed to create access control: {e}")))?;

        let mut options = GenerateKeyOptions::default();
        options.set_key_type(KeyType::ec());
        options.set_size_in_bits(256);
        options.set_label(label);
        options.set_access_control(access_control);

        if self.protection == KeyProtection::SecureEnclave {
            options.set_token(security_framework::key::Token::SecureEnclave);
        }

        #[allow(deprecated)]
        SecKey::generate(options.to_dictionary())
            .map_err(|e| Error::KeyStore(format!("key generation failed: {e}")))?;

        Ok(())
    }

    fn exists(&self, label: &str) -> Result<bool> {
        // Try to find the key by label via SecKey lookup.
        match find_key_by_label(label) {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
            Err(_) => Ok(false),
        }
    }

    fn sign(&self, label: &str, data: &[u8]) -> Result<Vec<u8>> {
        let key = find_key_by_label(label)?
            .ok_or_else(|| Error::KeyNotFound {
                label: label.into(),
            })?;

        // This triggers Touch ID!
        key.create_signature(Algorithm::ECDSASignatureMessageX962SHA256, data)
            .map_err(|e| {
                let msg = format!("{e}");
                if msg.contains("User canceled") || msg.contains("-128") {
                    Error::BiometricDenied
                } else {
                    Error::Signing(format!("signing failed: {e}"))
                }
            })
    }

    fn public_key_jwk(&self, label: &str) -> Result<Jwk> {
        let key = find_key_by_label(label)?
            .ok_or_else(|| Error::KeyNotFound {
                label: label.into(),
            })?;

        let public_key = key
            .public_key()
            .ok_or_else(|| Error::KeyStore("failed to extract public key".into()))?;

        let external = public_key
            .external_representation()
            .ok_or_else(|| Error::KeyStore("failed to export public key".into()))?;

        let bytes: &[u8] = &external;

        // P-256 uncompressed point: 0x04 || x (32 bytes) || y (32 bytes) = 65 bytes
        if bytes.len() != 65 || bytes[0] != 0x04 {
            return Err(Error::KeyStore(format!(
                "unexpected public key format: {} bytes",
                bytes.len(),
            )));
        }

        let x = URL_SAFE_NO_PAD.encode(&bytes[1..33]);
        let y = URL_SAFE_NO_PAD.encode(&bytes[33..65]);

        Ok(Jwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            x,
            y,
            kid: label.into(),
            key_use: "sig".into(),
            alg: "ES256".into(),
        })
    }

    fn delete(&self, label: &str) -> Result<()> {
        // Delete by finding and removing the key.
        if let Ok(Some(key)) = find_key_by_label(label) {
            key.delete()
                .map_err(|e| Error::KeyStore(format!("delete failed: {e}")))?;
        }
        Ok(())
    }
}

/// Find a key in the Keychain by its label using SecItemCopyMatching.
fn find_key_by_label(label: &str) -> Result<Option<SecKey>> {
    use core_foundation::base::TCFType;
    use core_foundation::boolean::CFBoolean;
    use core_foundation::dictionary::CFMutableDictionary;
    use core_foundation::string::CFString;
    use core_foundation::base::ToVoid;
    use security_framework_sys::item::{
        kSecAttrKeyClass, kSecAttrKeyClassPrivate, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrLabel, kSecClass, kSecClassKey, kSecMatchLimit, kSecReturnRef,
    };
    use security_framework_sys::keychain_item::SecItemCopyMatching;

    unsafe {
        let mut query = CFMutableDictionary::new();
        query.set(kSecClass.to_void(), kSecClassKey.to_void());
        query.set(kSecAttrKeyType.to_void(), kSecAttrKeyTypeECSECPrimeRandom.to_void());
        query.set(kSecAttrKeyClass.to_void(), kSecAttrKeyClassPrivate.to_void());
        query.set(kSecAttrLabel.to_void(), CFString::new(label).to_void());
        query.set(kSecReturnRef.to_void(), CFBoolean::true_value().to_void());
        query.set(kSecMatchLimit.to_void(), core_foundation::number::CFNumber::from(1i32).to_void());

        let mut result = std::ptr::null();
        let status = SecItemCopyMatching(query.as_concrete_TypeRef().cast(), &mut result);

        if status == 0 && !result.is_null() {
            let key = SecKey::wrap_under_create_rule(result as security_framework_sys::base::SecKeyRef);
            Ok(Some(key))
        } else if status == -25300 {
            // errSecItemNotFound
            Ok(None)
        } else {
            Err(Error::KeyStore(format!(
                "keychain query failed with status {status}"
            )))
        }
    }
}

#[cfg(test)]
pub mod mocks {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    /// In-memory key store for testing (no Keychain, no Touch ID).
    #[derive(Debug, Default)]
    pub struct InMemoryKeyStore {
        keys: Mutex<BTreeMap<String, Vec<u8>>>,
    }

    impl InMemoryKeyStore {
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }
    }

    impl KeyStore for InMemoryKeyStore {
        fn generate(&self, label: &str) -> Result<()> {
            let mut keys = self.keys.lock().unwrap();
            if keys.contains_key(label) {
                return Err(Error::KeyStore(format!("key '{label}' already exists")));
            }
            keys.insert(label.into(), vec![0x42; 32]);
            Ok(())
        }

        fn exists(&self, label: &str) -> Result<bool> {
            Ok(self.keys.lock().unwrap().contains_key(label))
        }

        fn sign(&self, label: &str, data: &[u8]) -> Result<Vec<u8>> {
            let keys = self.keys.lock().unwrap();
            let key = keys.get(label).ok_or_else(|| Error::KeyNotFound {
                label: label.into(),
            })?;
            // Fake DER-encoded signature (valid structure for der_to_jws)
            let mut r = vec![0u8; 32];
            let mut s = vec![0u8; 32];
            for (i, &b) in data.iter().take(32).enumerate() {
                r[i] = b ^ key[i % key.len()];
                s[i] = b.wrapping_add(key[i % key.len()]);
            }
            // Build DER: 0x30 <len> 0x02 <r_len> <r> 0x02 <s_len> <s>
            let mut der = vec![0x30, 68, 0x02, 32];
            der.extend_from_slice(&r);
            der.push(0x02);
            der.push(32);
            der.extend_from_slice(&s);
            Ok(der)
        }

        fn public_key_jwk(&self, label: &str) -> Result<Jwk> {
            let keys = self.keys.lock().unwrap();
            if !keys.contains_key(label) {
                return Err(Error::KeyNotFound {
                    label: label.into(),
                });
            }
            Ok(Jwk {
                kty: "EC".into(),
                crv: "P-256".into(),
                x: URL_SAFE_NO_PAD.encode(vec![0x01; 32]),
                y: URL_SAFE_NO_PAD.encode(vec![0x02; 32]),
                kid: label.into(),
                key_use: "sig".into(),
                alg: "ES256".into(),
            })
        }

        fn delete(&self, label: &str) -> Result<()> {
            self.keys.lock().unwrap().remove(label);
            Ok(())
        }
    }
}
