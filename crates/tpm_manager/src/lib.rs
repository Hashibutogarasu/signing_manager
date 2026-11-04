use signing_core::{Closable, Openable, Result, SigningError};
use tss_esapi::{
    Context, TctiNameConf,
    attributes::ObjectAttributesBuilder,
    handles::KeyHandle,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm, SymmetricMode},
        key_bits::AesKeyBits,
        resource_handles::Hierarchy,
    },
    structures::{
        Digest, InitialValue, MaxBuffer, PublicBuilder, SymmetricCipherParameters,
        SymmetricDefinitionObject,
    },
};

const IV_SIZE: usize = 16;
const MODE: SymmetricMode = SymmetricMode::Cfb;

fn tpm_error(error: tss_esapi::Error) -> SigningError {
    SigningError::Tpm(error.to_string())
}

struct Session {
    context: Context,
    key: KeyHandle,
}

pub struct TpmManager {
    tcti: TctiNameConf,
    session: Option<Session>,
}

impl TpmManager {
    pub fn new(tcti: TctiNameConf) -> Self {
        Self {
            tcti,
            session: None,
        }
    }

    pub fn from_environment() -> Result<Self> {
        TctiNameConf::from_environment_variable()
            .map(Self::new)
            .map_err(tpm_error)
    }

    pub fn encrypt(&mut self, plain: &[u8]) -> Result<Vec<u8>> {
        let session = self.session.as_mut().ok_or(SigningError::NotOpened)?;
        let iv = session.context.get_random(IV_SIZE).map_err(tpm_error)?;
        let mut out = iv.value().to_vec();
        out.extend(session.transform(false, plain, iv.value())?);
        Ok(out)
    }

    pub fn decrypt(&mut self, encrypted: &[u8]) -> Result<Vec<u8>> {
        let session = self.session.as_mut().ok_or(SigningError::NotOpened)?;
        if encrypted.len() < IV_SIZE {
            return Err(SigningError::Tpm("encrypted data is too short".into()));
        }
        let (iv, cipher) = encrypted.split_at(IV_SIZE);
        session.transform(true, cipher, iv)
    }
}

impl Session {
    fn create(tcti: TctiNameConf) -> Result<Self> {
        let mut context = Context::new(tcti).map_err(tpm_error)?;
        let attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_st_clear(false)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_decrypt(true)
            .with_sign_encrypt(true)
            .with_restricted(false)
            .build()
            .map_err(tpm_error)?;
        let public = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::SymCipher)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(attributes)
            .with_symmetric_cipher_parameters(SymmetricCipherParameters::new(
                SymmetricDefinitionObject::Aes {
                    key_bits: AesKeyBits::Aes256,
                    mode: MODE,
                },
            ))
            .with_symmetric_cipher_unique_identifier(Digest::default())
            .build()
            .map_err(tpm_error)?;
        let key = context
            .execute_with_nullauth_session(|ctx| {
                ctx.create_primary(Hierarchy::Owner, public, None, None, None, None)
            })
            .map_err(tpm_error)?
            .key_handle;
        Ok(Self { context, key })
    }

    fn transform(&mut self, decrypt: bool, data: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        let key = self.key;
        let mut iv = InitialValue::try_from(iv.to_vec()).map_err(tpm_error)?;
        let mut out = Vec::with_capacity(data.len());
        for chunk in data.chunks(MaxBuffer::MAX_SIZE) {
            let input = MaxBuffer::try_from(chunk.to_vec()).map_err(tpm_error)?;
            let (output, next_iv) = self
                .context
                .execute_with_nullauth_session(|ctx| {
                    ctx.encrypt_decrypt_2(key, decrypt, MODE, input, iv.clone())
                })
                .map_err(tpm_error)?;
            out.extend_from_slice(output.value());
            iv = next_iv;
        }
        Ok(out)
    }
}

impl Openable for TpmManager {
    fn open(&mut self) -> Result<()> {
        if self.session.is_some() {
            return Err(SigningError::AlreadyOpened);
        }
        self.session = Some(Session::create(self.tcti.clone())?);
        Ok(())
    }
}

impl Closable for TpmManager {
    fn close(&mut self) {
        if let Some(mut session) = self.session.take() {
            let _ = session.context.flush_context(session.key.into());
        }
    }
}

impl Drop for TpmManager {
    fn drop(&mut self) {
        self.close();
    }
}
