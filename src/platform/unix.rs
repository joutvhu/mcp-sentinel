#[cfg(unix)]
pub struct ProcessGroupGuard;

#[cfg(unix)]
impl ProcessGroupGuard {
    pub fn new() -> Result<Self, String> {
        Ok(Self)
    }
}
