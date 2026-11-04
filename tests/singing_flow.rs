use signing_manager::{Closable, MemorySecretKey, Openable, Signing, SigningContext, SigningError};

#[derive(Clone)]
struct TestConfig {
    secret_key: Vec<u8>,
    binary: Vec<u8>,
    public_key: Vec<u8>,
    on_stream: bool,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            secret_key: b"test-secret-key".to_vec(),
            binary: b"binary-on-stream".to_vec(),
            public_key: b"test-public-key".to_vec(),
            on_stream: true,
        }
    }
}

struct SingingTestStub {
    context: SigningContext,
}

impl SingingTestStub {
    fn new(config: &TestConfig) -> Self {
        let secret = config.secret_key.clone();
        let secret_key = MemorySecretKey::new(Box::new(move || Ok(secret.clone())));
        Self {
            context: SigningContext::new(
                config.on_stream,
                config.binary.clone(),
                config.public_key.clone(),
                Box::new(secret_key),
            ),
        }
    }
}

impl Openable for SingingTestStub {
    fn open(&mut self) -> signing_manager::Result<()> {
        self.context.secret_key_mut().open()
    }
}

impl Closable for SingingTestStub {
    fn close(&mut self) {
        self.context.secret_key_mut().close();
    }
}

impl Signing for SingingTestStub {
    fn verify(&self, signature: &[u8]) -> signing_manager::Result<bool> {
        Ok(signature == self.context.secret_key().get()?)
    }

    fn get_context(&self) -> &SigningContext {
        &self.context
    }
}

#[test]
fn secret_key_is_injected_on_open() {
    let config = TestConfig::default();
    let mut stub = SingingTestStub::new(&config);
    assert_eq!(
        stub.get_context().secret_key().get(),
        Err(SigningError::NotOpened)
    );

    stub.open().unwrap();

    assert_eq!(
        stub.get_context().secret_key().get(),
        Ok(config.secret_key.as_slice())
    );
}

#[test]
fn memory_pointer_exposes_injected_value() {
    let config = TestConfig::default();
    let mut stub = SingingTestStub::new(&config);
    stub.open().unwrap();
    let secret_key = stub.get_context().secret_key();

    assert_eq!(secret_key.get_in_memory().unwrap(), config.secret_key);

    let ptr = secret_key.get().unwrap().as_ptr();
    let raw = unsafe { std::slice::from_raw_parts(ptr, config.secret_key.len()) };
    assert_eq!(raw, config.secret_key);
}

#[test]
fn close_clears_memory_and_blocks_access() {
    let config = TestConfig::default();
    let mut stub = SingingTestStub::new(&config);
    stub.open().unwrap();
    let ptr = stub.get_context().secret_key().get().unwrap().as_ptr();

    stub.close();

    let secret_key = stub.get_context().secret_key();
    assert_eq!(secret_key.get(), Err(SigningError::NotOpened));
    assert_eq!(secret_key.get_in_memory(), Err(SigningError::NotOpened));
    let raw = unsafe { std::slice::from_raw_parts(ptr, config.secret_key.len()) };
    assert!(raw.iter().all(|&byte| byte == 0));
}

#[test]
fn context_exposes_binary_and_keys() {
    let config = TestConfig::default();
    let mut stub = SingingTestStub::new(&config);
    stub.open().unwrap();
    let context = stub.get_context();

    assert_eq!(context.on_stream(), config.on_stream);
    assert_eq!(context.binary(), config.binary);
    assert_eq!(context.binary_ptr(), context.binary().as_ptr());
    let raw = unsafe { std::slice::from_raw_parts(context.binary_ptr(), config.binary.len()) };
    assert_eq!(raw, config.binary);
    assert_eq!(context.public_key(), config.public_key);
    assert_eq!(stub.verify(&config.secret_key), Ok(true));
    assert_eq!(stub.verify(b"other"), Ok(false));
}

#[test]
fn verify_fails_when_closed() {
    let config = TestConfig::default();
    let mut stub = SingingTestStub::new(&config);
    stub.open().unwrap();
    stub.close();

    assert_eq!(
        stub.verify(&config.secret_key),
        Err(SigningError::NotOpened)
    );
}

#[test]
fn reopen_after_close_works() {
    let config = TestConfig::default();
    let mut stub = SingingTestStub::new(&config);
    stub.open().unwrap();
    stub.close();

    stub.open().unwrap();

    let secret_key = stub.get_context().secret_key();
    assert_eq!(secret_key.get(), Ok(config.secret_key.as_slice()));
    assert_eq!(secret_key.get_in_memory().unwrap(), config.secret_key);
}

#[test]
fn double_open_returns_error() {
    let config = TestConfig::default();
    let mut stub = SingingTestStub::new(&config);
    stub.open().unwrap();

    assert_eq!(stub.open(), Err(SigningError::AlreadyOpened));
}
