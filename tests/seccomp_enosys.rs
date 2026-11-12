//! A sandbox that blocks `getrandom(2)` must produce an error, never a
//! silent switch to another source.
//!
//! Each case forks a child, installs a seccomp filter in the child that
//! makes `getrandom` fail with the given errno, calls
//! `tier3::fill_bytes`, and reports the outcome through its exit code.
//! The running kernel is newer than 3.17, so `ENOSYS` here can only come
//! from the filter.

#![cfg(all(feature = "tier3", target_os = "linux", target_arch = "x86_64"))]

#[repr(C)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

extern "C" {
    fn prctl(option: i32, a2: usize, a3: usize, a4: usize, a5: usize) -> i32;
    fn fork() -> i32;
    fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
    fn _exit(code: i32) -> !;
}

const PR_SET_NO_NEW_PRIVS: i32 = 38;
const PR_SET_SECCOMP: i32 = 22;
const SECCOMP_MODE_FILTER: usize = 2;
const SYS_GETRANDOM: u32 = 318;
const ENOSYS: u32 = 38;
const EPERM: u32 = 1;

/// Exit codes the child uses to report.
const CHILD_ERR_MATCHES: i32 = 0;
const CHILD_OK: i32 = 1;
const CHILD_OTHER_ERR: i32 = 2;
const CHILD_NO_FILTER: i32 = 3;

/// Make `getrandom` fail with `errno` for this process.
fn install_filter(errno: u32) -> bool {
    let prog = [
        // Load the syscall number.
        SockFilter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 0,
        },
        // If it is getrandom, fall through to the errno return.
        SockFilter {
            code: 0x15,
            jt: 0,
            jf: 1,
            k: SYS_GETRANDOM,
        },
        SockFilter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x0005_0000 | errno,
        },
        // Allow everything else.
        SockFilter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x7fff_0000,
        },
    ];
    let fprog = SockFprog {
        len: prog.len() as u16,
        filter: prog.as_ptr(),
    };
    // SAFETY: plain prctl calls with valid arguments; `fprog` and
    // `prog` outlive the call.
    unsafe {
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0
            && prctl(
                PR_SET_SECCOMP,
                SECCOMP_MODE_FILTER,
                &fprog as *const SockFprog as usize,
                0,
                0,
            ) == 0
    }
}

/// Run `fill_bytes` in a child under the filter; return its exit code.
fn run_child(errno: u32) -> i32 {
    // SAFETY: the child installs a filter, makes one call and exits
    // with `_exit`; it never returns into the test harness.
    let pid = unsafe { fork() };
    assert!(pid >= 0, "fork failed");
    if pid == 0 {
        let code = if !install_filter(errno) {
            CHILD_NO_FILTER
        } else {
            let mut buf = [0u8; 16];
            match mod_rand::tier3::fill_bytes(&mut buf) {
                Ok(()) => CHILD_OK,
                Err(e) if e.raw_os_error() == Some(errno as i32) => CHILD_ERR_MATCHES,
                Err(_) => CHILD_OTHER_ERR,
            }
        };
        // SAFETY: ends the child immediately.
        unsafe { _exit(code) };
    }
    let mut status = 0;
    // SAFETY: `pid` is our child; `status` is a valid pointer.
    let waited = unsafe { waitpid(pid, &mut status, 0) };
    assert_eq!(waited, pid);
    assert_eq!(status & 0x7f, 0, "child did not exit normally");
    (status >> 8) & 0xff
}

#[test]
fn enosys_from_a_filter_is_an_error() {
    let code = run_child(ENOSYS);
    assert_ne!(
        code, CHILD_NO_FILTER,
        "could not install the seccomp filter"
    );
    assert_eq!(
        code, CHILD_ERR_MATCHES,
        "a filtered getrandom must return ENOSYS (child code {code}; 1 means it fell back and succeeded)"
    );
}

#[test]
fn eperm_from_a_filter_is_an_error() {
    let code = run_child(EPERM);
    assert_ne!(
        code, CHILD_NO_FILTER,
        "could not install the seccomp filter"
    );
    assert_eq!(code, CHILD_ERR_MATCHES, "child code {code}");
}
