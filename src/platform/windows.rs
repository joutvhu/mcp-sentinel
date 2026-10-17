#[cfg(windows)]
pub struct JobObjectGuard {
    job_handle: windows_sys::Win32::Foundation::HANDLE,
}

#[cfg(windows)]
impl JobObjectGuard {
    pub fn new() -> Result<Self, String> {
        use std::mem::size_of;
        use windows_sys::Win32::System::JobObjects::*;

        unsafe {
            let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if job.is_null() {
                return Err("Failed to create Job Object".into());
            }

            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

            let res = SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const _,
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            );

            if res == 0 {
                windows_sys::Win32::Foundation::CloseHandle(job);
                return Err("Failed to set Job Object info".into());
            }

            Ok(Self { job_handle: job })
        }
    }

    /// Assigns a native process handle to the Job Object.
    ///
    /// # Safety
    /// The caller must ensure that `process_handle` is a valid Windows process handle.
    pub unsafe fn assign_process(
        &self,
        process_handle: windows_sys::Win32::Foundation::HANDLE,
    ) -> Result<(), String> {
        use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;
        if AssignProcessToJobObject(self.job_handle, process_handle) == 0 {
            return Err("Failed to assign process to Job Object".into());
        }
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for JobObjectGuard {
    fn drop(&mut self) {
        unsafe {
            if !self.job_handle.is_null() {
                windows_sys::Win32::Foundation::CloseHandle(self.job_handle);
            }
        }
    }
}
