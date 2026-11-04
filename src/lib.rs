use zeroize::{Zeroize, ZeroizeOnDrop};

pub use signing_core::{Closable, Openable, Result, SigningError};

pub trait SecretKey: Openable + Closable {
    fn get(&self) -> Result<&[u8]>;

    fn get_in_memory(&self) -> Result<Vec<u8>>;
}

type KeyProvider = Box<dyn Fn() -> Result<Vec<u8>>>;

#[derive(ZeroizeOnDrop)]
pub struct MemorySecretKey {
    #[zeroize(skip)]
    provider: KeyProvider,
    buffer: Option<Box<[u8]>>,
    #[zeroize(skip)]
    location: Option<(*const u8, usize)>,
}

impl MemorySecretKey {
    pub fn new(provider: KeyProvider) -> Self {
        Self {
            provider,
            buffer: None,
            location: None,
        }
    }
}

impl Openable for MemorySecretKey {
    fn open(&mut self) -> Result<()> {
        if self.location.is_some() {
            return Err(SigningError::AlreadyOpened);
        }
        let buffer = (self.provider)()?.into_boxed_slice();
        self.location = Some((buffer.as_ptr(), buffer.len()));
        self.buffer = Some(buffer);
        Ok(())
    }
}

impl Closable for MemorySecretKey {
    fn close(&mut self) {
        if let Some(buffer) = self.buffer.as_mut() {
            buffer.zeroize();
        }
        self.location = None;
    }
}

impl SecretKey for MemorySecretKey {
    fn get(&self) -> Result<&[u8]> {
        match (self.location, self.buffer.as_deref()) {
            (Some(_), Some(buffer)) => Ok(buffer),
            _ => Err(SigningError::NotOpened),
        }
    }

    fn get_in_memory(&self) -> Result<Vec<u8>> {
        let (ptr, len) = self.location.ok_or(SigningError::NotOpened)?;
        Ok(unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec())
    }
}

pub struct SigningContext {
    on_stream: bool,
    binary: Vec<u8>,
    binary_ptr: *const u8,
    public_key: Vec<u8>,
    secret_key: Box<dyn SecretKey>,
}

impl SigningContext {
    pub fn new(
        on_stream: bool,
        binary: Vec<u8>,
        public_key: Vec<u8>,
        secret_key: Box<dyn SecretKey>,
    ) -> Self {
        let binary_ptr = binary.as_ptr();
        Self {
            on_stream,
            binary,
            binary_ptr,
            public_key,
            secret_key,
        }
    }

    pub fn on_stream(&self) -> bool {
        self.on_stream
    }

    pub fn binary(&self) -> &[u8] {
        &self.binary
    }

    pub fn binary_ptr(&self) -> *const u8 {
        self.binary_ptr
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub fn secret_key(&self) -> &dyn SecretKey {
        self.secret_key.as_ref()
    }

    pub fn secret_key_mut(&mut self) -> &mut dyn SecretKey {
        self.secret_key.as_mut()
    }
}

pub trait Signing: Openable + Closable {
    fn verify(&self, signature: &[u8]) -> Result<bool>;
    fn get_context(&self) -> &SigningContext;
}
