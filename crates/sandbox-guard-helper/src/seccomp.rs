use std::io;

const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JMP_JEQ_K: u16 = 0x15;
#[cfg(target_arch = "x86_64")]
const BPF_JMP_JGE_K: u16 = 0x35;
const BPF_ALU_AND_K: u16 = 0x54;
const BPF_RET_K: u16 = 0x06;

const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
const SECCOMP_DATA_NR: u32 = 0;
const SECCOMP_DATA_ARCH: u32 = 4;
const SECCOMP_DATA_ARG0_LOW: u32 = 16;
#[cfg(target_arch = "x86_64")]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH_NATIVE: u32 = 0xc000_003e;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH_NATIVE: u32 = 0xc000_00b7;

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("Sandbox Guard seccomp supports x86_64 and aarch64 Linux only");

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct SockFilter {
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

const fn statement(code: u16, value: u32) -> SockFilter {
    SockFilter {
        code,
        jt: 0,
        jf: 0,
        k: value,
    }
}

const fn jump(code: u16, value: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter {
        code,
        jt,
        jf,
        k: value,
    }
}

pub(crate) fn build_filter() -> Vec<SockFilter> {
    let errno = SECCOMP_RET_ERRNO | libc::EPERM as u32;
    let unavailable = SECCOMP_RET_ERRNO | libc::ENOSYS as u32;
    let mut program = vec![
        statement(BPF_LD_W_ABS, SECCOMP_DATA_ARCH),
        jump(BPF_JMP_JEQ_K, AUDIT_ARCH_NATIVE, 1, 0),
        statement(BPF_RET_K, SECCOMP_RET_KILL_PROCESS),
        statement(BPF_LD_W_ABS, SECCOMP_DATA_NR),
    ];

    #[cfg(target_arch = "x86_64")]
    {
        program.push(jump(BPF_JMP_JGE_K, X32_SYSCALL_BIT, 0, 1));
        program.push(statement(BPF_RET_K, SECCOMP_RET_KILL_PROCESS));
    }

    // clone3 stores flags behind a userspace pointer, which classic seccomp BPF cannot inspect.
    // Report it unavailable so libc can fall back to clone, whose namespace bits are filtered
    // below. EPERM here breaks ordinary pthread creation in several runtimes.
    program.push(jump(BPF_JMP_JEQ_K, libc::SYS_clone3 as u32, 0, 1));
    program.push(statement(BPF_RET_K, unavailable));

    for syscall in denied_syscalls() {
        program.push(jump(BPF_JMP_JEQ_K, syscall, 0, 1));
        program.push(statement(BPF_RET_K, errno));
    }

    let namespace_flags = (libc::CLONE_NEWCGROUP
        | libc::CLONE_NEWIPC
        | libc::CLONE_NEWNET
        | libc::CLONE_NEWNS
        | libc::CLONE_NEWPID
        | libc::CLONE_NEWUSER
        | libc::CLONE_NEWUTS) as u32;
    program.extend([
        jump(BPF_JMP_JEQ_K, libc::SYS_clone as u32, 0, 4),
        statement(BPF_LD_W_ABS, SECCOMP_DATA_ARG0_LOW),
        statement(BPF_ALU_AND_K, namespace_flags),
        jump(BPF_JMP_JEQ_K, 0, 1, 0),
        statement(BPF_RET_K, errno),
        statement(BPF_RET_K, SECCOMP_RET_ALLOW),
    ]);
    program
}

fn denied_syscalls() -> Vec<u32> {
    vec![
        libc::SYS_unshare as u32,
        libc::SYS_setns as u32,
        libc::SYS_mount as u32,
        libc::SYS_umount2 as u32,
        libc::SYS_pivot_root as u32,
        libc::SYS_open_tree as u32,
        libc::SYS_move_mount as u32,
        libc::SYS_fsopen as u32,
        libc::SYS_fsconfig as u32,
        libc::SYS_fsmount as u32,
        libc::SYS_mount_setattr as u32,
        libc::SYS_bpf as u32,
        libc::SYS_perf_event_open as u32,
        libc::SYS_io_uring_setup as u32,
        libc::SYS_io_uring_enter as u32,
        libc::SYS_io_uring_register as u32,
        libc::SYS_open_by_handle_at as u32,
        libc::SYS_name_to_handle_at as u32,
        libc::SYS_process_vm_readv as u32,
        libc::SYS_process_vm_writev as u32,
        libc::SYS_process_madvise as u32,
        libc::SYS_pidfd_open as u32,
        libc::SYS_pidfd_send_signal as u32,
        libc::SYS_pidfd_getfd as u32,
        libc::SYS_ptrace as u32,
        libc::SYS_userfaultfd as u32,
        libc::SYS_kexec_load as u32,
        libc::SYS_kexec_file_load as u32,
        libc::SYS_init_module as u32,
        libc::SYS_finit_module as u32,
        libc::SYS_delete_module as u32,
        libc::SYS_reboot as u32,
        libc::SYS_swapon as u32,
        libc::SYS_swapoff as u32,
        libc::SYS_acct as u32,
        libc::SYS_add_key as u32,
        libc::SYS_request_key as u32,
        libc::SYS_keyctl as u32,
    ]
}

/// Install a prebuilt filter in the post-fork child. This function performs only raw syscalls and
/// is suitable for use from `CommandExt::pre_exec`.
pub(crate) unsafe fn install_filter(program: &[SockFilter]) -> io::Result<()> {
    // SAFETY: called in a child process with constant arguments.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let descriptor = SockFprog {
        len: program
            .len()
            .try_into()
            .map_err(|_| io::Error::other("seccomp program is too large"))?,
        filter: program.as_ptr(),
    };
    // SAFETY: descriptor points to a valid filter program retained by the pre-exec closure.
    let result = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            0_u32,
            &descriptor as *const SockFprog,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandbox_guard_core::builtin_grok_profile;

    #[test]
    fn filter_is_arch_checked_and_ends_in_allow() {
        let filter = build_filter();
        assert_eq!(filter[0].k, SECCOMP_DATA_ARCH);
        assert_eq!(filter[1].k, AUDIT_ARCH_NATIVE);
        assert_eq!(filter.last().unwrap().k, SECCOMP_RET_ALLOW);
    }

    #[test]
    fn dangerous_syscalls_are_present_in_the_deny_program() {
        let filter = build_filter();
        for syscall in [
            libc::SYS_unshare as u32,
            libc::SYS_setns as u32,
            libc::SYS_clone3 as u32,
            libc::SYS_bpf as u32,
            libc::SYS_perf_event_open as u32,
            libc::SYS_io_uring_setup as u32,
            libc::SYS_process_madvise as u32,
            libc::SYS_pidfd_open as u32,
            libc::SYS_pidfd_getfd as u32,
        ] {
            assert!(filter.iter().any(|instruction| instruction.k == syscall));
        }
    }

    #[test]
    fn compiled_grok_profile_matches_the_clone3_compatibility_rule() {
        // This is the CI cross-pin referenced by README: profiles describe compatibility but
        // never configure the production filter built above.
        let profile = builtin_grok_profile();
        profile.validate().unwrap();
        let unavailable = SECCOMP_RET_ERRNO | libc::ENOSYS as u32;
        let filter = build_filter();
        let clone3_returns_enosys = filter.windows(2).any(|instructions| {
            instructions[0].code == BPF_JMP_JEQ_K
                && instructions[0].k == libc::SYS_clone3 as u32
                && instructions[0].jt == 0
                && instructions[0].jf == 1
                && instructions[1].code == BPF_RET_K
                && instructions[1].k == unavailable
        });
        assert_eq!(
            clone3_returns_enosys,
            profile.seccomp.clone3_enosys_shim_expected
        );
    }
}
