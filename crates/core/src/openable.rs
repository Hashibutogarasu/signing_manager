use crate::Result;

pub trait Openable {
    fn open(&mut self) -> Result<()>;
}
