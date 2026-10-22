use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType,
};
use rustls_pki_types::CertificateDer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const CA_DIR_NAME: &str = "ca";
const CA_CERT_FILE: &str = "root-ca.pem";
const CA_KEY_FILE: &str = "root-ca.key";
const CA_KEY_DPAPI_FILE: &str = "root-ca.key.dpapi";
const CA_META_FILE: &str = "root-ca.meta.json";
const CA_PARAMS_FILE: &str = "root-ca.params.json";

pub const LEAF_VALIDITY: Duration = Duration::from_secs(7 * 24 * 3600);
const LEAF_SKEW: Duration = Duration::from_secs(3600);

#[derive(Debug, thiserror::Error)]
pub enum CaError {
    #[error("the CA private key could not be read: {0}")]
    Key(String),
    #[error("the CA certificate could not be parsed: {0}")]
    Cert(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("the CA material is inconsistent: {0}")]
    Inconsistent(String),
    #[error("certificate generation failed: {0}")]
    Generation(String),
    #[error("no root CA has been generated")]
    NotGenerated,
}

pub struct CaManager {
    dir: PathBuf,
}

pub struct CaMaterial {
    pub cert_der: CertificateDer<'static>,
    pub cert: Certificate,
    pub key_der: Vec<u8>,
    pub fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaStatus {
    pub present: bool,
    pub fingerprint: Option<String>,
    pub not_before_unix: Option<i64>,
    pub not_after_unix: Option<i64>,
    pub key_protection: &'static str,
    pub cert_pem: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct CaMeta {
    not_before_unix: i64,
    not_after_unix: i64,
    fingerprint_sha256: String,
    algorithm: String,
    version: u32,
}

/// Serializable CA parameters for reconstruction.
#[derive(Serialize, Deserialize)]
struct CaParamsSerializable {
    common_name: String,
    org_name: String,
    not_before_unix: i64,
    not_after_unix: i64,
    serial_number: u64,
}

pub struct LeafCert {
    pub cert_der: CertificateDer<'static>,
    pub key_der: Vec<u8>,
}

impl CaManager {
    pub fn new(dir: PathBuf) -> Self {
        CaManager { dir }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn load_or_generate(&self) -> Result<CaMaterial, CaError> {
        std::fs::create_dir_all(&self.dir)?;
        let cert_path = self.dir.join(CA_CERT_FILE);
        if cert_path.exists() {
            return self.load_existing();
        }
        self.generate_new()
    }

    /// Load the CA from disk. Never creates one: generation is the user's explicit action
    /// ([`Self::load_or_generate`]).
    pub fn load(&self) -> Result<CaMaterial, CaError> {
        if !self.dir.join(CA_CERT_FILE).exists() {
            return Err(CaError::NotGenerated);
        }
        self.load_existing()
    }

    pub fn status(&self) -> CaStatus {
        let cert_path = self.dir.join(CA_CERT_FILE);
        if !cert_path.exists() {
            return CaStatus {
                present: false,
                fingerprint: None,
                not_before_unix: None,
                not_after_unix: None,
                key_protection: protection_label(),
                cert_pem: None,
            };
        }
        let meta_path = self.dir.join(CA_META_FILE);
        let meta: Option<CaMeta> = std::fs::read_to_string(&meta_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok());
        let cert_pem = std::fs::read_to_string(&cert_path).ok();
        let fingerprint = meta.as_ref().map(|m| m.fingerprint_sha256.clone());
        let (nb, na) = meta
            .as_ref()
            .map(|m| (Some(m.not_before_unix), Some(m.not_after_unix)))
            .unwrap_or((None, None));
        CaStatus {
            present: true,
            fingerprint,
            not_before_unix: nb,
            not_after_unix: na,
            key_protection: protection_label(),
            cert_pem,
        }
    }

    pub fn remove(&self) -> Result<(), CaError> {
        for name in [
            CA_CERT_FILE,
            CA_KEY_FILE,
            CA_KEY_DPAPI_FILE,
            CA_META_FILE,
            CA_PARAMS_FILE,
        ] {
            let p = self.dir.join(name);
            if p.exists() {
                std::fs::remove_file(&p)?;
            }
        }
        Ok(())
    }

    fn load_existing(&self) -> Result<CaMaterial, CaError> {
        let params_path = self.dir.join(CA_PARAMS_FILE);
        let params: CaParamsSerializable =
            serde_json::from_str(&std::fs::read_to_string(&params_path).map_err(|_| {
                CaError::Key("CA params file not found. CA must be regenerated.".into())
            })?)
            .map_err(|e| CaError::Cert(e.to_string()))?;

        let key_der = self.load_key()?;
        let key = make_key(&key_der)?;

        // Reconstruct params and self-sign to get the Certificate
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, &params.common_name);
        dn.push(DnType::OrganizationName, &params.org_name);

        let mut ca_params = CertificateParams::default();
        ca_params.distinguished_name = dn;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        ca_params.serial_number = Some(params.serial_number.into());
        ca_params.not_before = time::OffsetDateTime::from_unix_timestamp(params.not_before_unix)
            .unwrap_or_else(|_| time::OffsetDateTime::now_utc());
        ca_params.not_after = time::OffsetDateTime::from_unix_timestamp(params.not_after_unix)
            .unwrap_or_else(|_| time::OffsetDateTime::now_utc() + time::Duration::days(3650));

        let cert = ca_params
            .self_signed(&key)
            .map_err(|e| CaError::Generation(e.to_string()))?;

        // Load stored cert DER
        let stored_pem = std::fs::read_to_string(self.dir.join(CA_CERT_FILE))?;
        let mut cursor = std::io::Cursor::new(stored_pem.as_bytes());
        let stored_certs: Vec<_> = rustls_pemfile::certs(&mut cursor)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| CaError::Cert(e.to_string()))?;
        let cert_der = stored_certs
            .into_iter()
            .next()
            .ok_or_else(|| CaError::Cert("no certificate found".into()))?;

        let fingerprint = sha256_hex(cert_der.as_ref());

        Ok(CaMaterial {
            cert_der,
            cert,
            key_der,
            fingerprint,
        })
    }

    fn generate_new(&self) -> Result<CaMaterial, CaError> {
        let key = KeyPair::generate().map_err(|e| CaError::Generation(e.to_string()))?;

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "DropSuite Local Root CA");
        dn.push(DnType::OrganizationName, "DropSuite");

        let mut params = CertificateParams::default();
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let now = time::OffsetDateTime::now_utc();
        let serial = 1_000_000_000u64 + (now.unix_timestamp() as u64 % 1_000_000_000);
        params.serial_number = Some(serial.into());

        let not_before = now - time::Duration::days(1);
        let not_after = now + time::Duration::days(3650);
        params.not_before = not_before;
        params.not_after = not_after;

        let cert = params
            .self_signed(&key)
            .map_err(|e| CaError::Generation(e.to_string()))?;

        let cert_der = cert.der().clone();
        let fingerprint = sha256_hex(cert_der.as_ref());

        std::fs::write(self.dir.join(CA_CERT_FILE), cert.pem().as_bytes())?;

        let key_der = key.serialize_der();
        self.store_key(&key_der)?;

        let meta = CaMeta {
            not_before_unix: (not_before - time::OffsetDateTime::UNIX_EPOCH).whole_seconds(),
            not_after_unix: (not_after - time::OffsetDateTime::UNIX_EPOCH).whole_seconds(),
            fingerprint_sha256: fingerprint.clone(),
            algorithm: "ECDSA P-256".into(),
            version: 1,
        };
        let meta_json =
            serde_json::to_string_pretty(&meta).map_err(|e| CaError::Generation(e.to_string()))?;
        std::fs::write(self.dir.join(CA_META_FILE), meta_json)?;

        // Save params for reconstruction
        let params_ser = CaParamsSerializable {
            common_name: "DropSuite Local Root CA".into(),
            org_name: "DropSuite".into(),
            not_before_unix: (not_before - time::OffsetDateTime::UNIX_EPOCH).whole_seconds(),
            not_after_unix: (not_after - time::OffsetDateTime::UNIX_EPOCH).whole_seconds(),
            serial_number: serial,
        };
        let params_json = serde_json::to_string_pretty(&params_ser)
            .map_err(|e| CaError::Generation(e.to_string()))?;
        std::fs::write(self.dir.join(CA_PARAMS_FILE), params_json)?;

        tracing::info!(fingerprint = %fingerprint, "Generated local root CA at {}", self.dir.display());

        Ok(CaMaterial {
            cert_der,
            cert,
            key_der,
            fingerprint,
        })
    }

    #[cfg(windows)]
    fn store_key(&self, key_der: &[u8]) -> Result<(), CaError> {
        let blob = dpapi::protect(key_der).map_err(|e| CaError::Key(e.to_string()))?;
        std::fs::write(self.dir.join(CA_KEY_DPAPI_FILE), &blob)?;
        Ok(())
    }

    #[cfg(not(windows))]
    fn store_key(&self, key_der: &[u8]) -> Result<(), CaError> {
        let pem_str = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
            &rustls_pki_types::PrivatePkcs8KeyDer::from(key_der.to_vec()),
            &rcgen::PKCS_ECDSA_P256_SHA256,
        )
        .map_err(|e| CaError::Key(e.to_string()))?
        .serialize_pem();
        let key_path = self.dir.join(CA_KEY_FILE);
        std::fs::write(&key_path, pem_str.as_bytes())?;
        set_restrictive_perms(&key_path)?;
        Ok(())
    }

    #[cfg(windows)]
    fn load_key(&self) -> Result<Vec<u8>, CaError> {
        let dpapi_path = self.dir.join(CA_KEY_DPAPI_FILE);
        if !dpapi_path.exists() {
            return Err(CaError::Key(
                "CA private key not found or not DPAPI-protected".into(),
            ));
        }
        let blob = std::fs::read(&dpapi_path)?;
        dpapi::unprotect(&blob).map_err(|e| CaError::Key(e.to_string()))
    }

    #[cfg(not(windows))]
    fn load_key(&self) -> Result<Vec<u8>, CaError> {
        self.load_key_pem()
    }

    #[cfg(not(windows))]
    fn load_key_pem(&self) -> Result<Vec<u8>, CaError> {
        let key_path = self.dir.join(CA_KEY_FILE);
        if !key_path.exists() {
            return Err(CaError::Key("CA private key not found".into()));
        }
        let pem_data = std::fs::read_to_string(&key_path)?;
        let key = rcgen::KeyPair::from_pem(&pem_data).map_err(|e| CaError::Key(e.to_string()))?;
        Ok(key.serialize_der())
    }
}

fn make_key(der: &[u8]) -> Result<KeyPair, CaError> {
    use rustls_pki_types::PrivatePkcs8KeyDer;
    KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(der.to_vec()),
        &rcgen::PKCS_ECDSA_P256_SHA256,
    )
    .map_err(|e| CaError::Key(e.to_string()))
}

pub fn issue_leaf(ca: &CaMaterial, host: &str) -> Result<LeafCert, CaError> {
    let leaf_key = KeyPair::generate().map_err(|e| CaError::Generation(e.to_string()))?;

    let clean_host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);

    let mut params = CertificateParams::default();
    if let Ok(ip) = clean_host.parse::<IpAddr>() {
        params.subject_alt_names = vec![SanType::IpAddress(ip)];
    } else {
        params.subject_alt_names = vec![SanType::DnsName(
            clean_host
                .to_string()
                .try_into()
                .map_err(|_| CaError::Generation("invalid DNS name".into()))?,
        )];
    }

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, clean_host);
    params.distinguished_name = dn;

    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::seconds(LEAF_SKEW.as_secs() as i64);
    params.not_after = now + time::Duration::seconds(LEAF_VALIDITY.as_secs() as i64);

    let issuer_key = make_key(&ca.key_der)?;
    let cert = params
        .signed_by(&leaf_key, &ca.cert, &issuer_key)
        .map_err(|e| CaError::Generation(e.to_string()))?;

    Ok(LeafCert {
        cert_der: cert.der().clone(),
        key_der: leaf_key.serialize_der(),
    })
}

pub fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn protection_label() -> &'static str {
    if cfg!(windows) {
        "Windows DPAPI (current user)"
    } else {
        "file permissions (0600)"
    }
}

#[cfg(unix)]
fn set_restrictive_perms(path: &Path) -> Result<(), CaError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
#[allow(dead_code)]
fn set_restrictive_perms(_path: &Path) -> Result<(), CaError> {
    Ok(())
}

#[cfg(windows)]
mod dpapi {
    use std::io;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    pub fn protect(plain: &[u8]) -> io::Result<Vec<u8>> {
        let input = CRYPT_INTEGER_BLOB {
            cbData: plain.len() as u32,
            pbData: plain.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        let ok = unsafe {
            CryptProtectData(
                &input,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let result =
            unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
        unsafe { LocalFree(output.pbData as _) };
        Ok(result)
    }

    pub fn unprotect(blob: &[u8]) -> io::Result<Vec<u8>> {
        let input = CRYPT_INTEGER_BLOB {
            cbData: blob.len() as u32,
            pbData: blob.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        let ok = unsafe {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let result =
            unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
        unsafe { LocalFree(output.pbData as _) };
        Ok(result)
    }
}
