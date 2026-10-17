#[cfg(unix)]
pub struct ProcessGroupGuard {
    child_pid: Option<u32>,
}

#[cfg(unix)]
impl ProcessGroupGuard {
    pub fn new() -> Result<Self, String> {
        Ok(Self { child_pid: None })
    }

    pub fn set_child_pid(&mut self, pid: u32) {
        self.child_pid = Some(pid);
    }
}

#[cfg(unix)]
impl Drop for ProcessGroupGuard {
    fn drop(&mut self) {
        if let Some(pid) = self.child_pid {
            // Signal process group with SIGTERM to cleanly terminate orphan child tree
            unsafe {
                libc::kill(-(pid as i32), libc::SIGTERM);
            }
        }
    }
}
