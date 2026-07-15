use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use crate::RunnerError;

const CTRL_V: u8 = 0x16;
const POLL_INTERVAL_MS: i32 = 50;
const EXIT_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_OSC_BYTES: usize = 1024 * 1024;
const MAX_CSI_BYTES: usize = 4096;
const DISABLE_MOUSE_REPORTING: &[u8] =
    b"\x1b[?9l\x1b[?1000l\x1b[?1001l\x1b[?1002l\x1b[?1003l\x1b[?1005l\x1b[?1006l\x1b[?1015l\x1b[?1016l";

pub(crate) struct ClipboardPaste {
    pub(crate) text: String,
    pub(crate) audit: String,
}

pub(crate) struct InteractiveOutcome {
    pub(crate) status: ExitStatus,
    pub(crate) clipboard_imports: Vec<String>,
}

pub(crate) fn run_interactive<F>(
    program: &Path,
    args: &[OsString],
    mut clipboard: F,
) -> Result<InteractiveOutcome, RunnerError>
where
    F: FnMut() -> Result<ClipboardPaste, RunnerError>,
{
    let stdin_fd = io::stdin().as_raw_fd();
    let stdout_fd = io::stdout().as_raw_fd();
    let original_termios = terminal_attributes(stdin_fd)?;
    let mut window = terminal_size(stdout_fd).unwrap_or(libc::winsize {
        ws_row: 24,
        ws_col: 80,
        ws_xpixel: 0,
        ws_ypixel: 0,
    });
    let (master, slave) = open_pty(&original_termios, &window)?;
    let child_stdin = slave
        .try_clone()
        .map_err(|source| execute_error(program, source))?;
    let child_stdout = slave
        .try_clone()
        .map_err(|source| execute_error(program, source))?;
    let child_stderr = slave
        .try_clone()
        .map_err(|source| execute_error(program, source))?;
    let mut command = Command::new(program);
    command.args(args);
    command
        .stdin(Stdio::from(child_stdin))
        .stdout(Stdio::from(child_stdout))
        .stderr(Stdio::from(child_stderr));
    // SAFETY: this closure runs after fork and before exec. It calls only async-signal-safe libc
    // operations, creates a fresh session, and makes the already-open PTY slave on fd 0 the
    // controlling terminal for the child.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::ioctl(libc::STDIN_FILENO, libc::TIOCSCTTY as _, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command
        .spawn()
        .map_err(|source| execute_error(program, source))?;
    drop(slave);
    let _raw_terminal = RawTerminal::enter(stdin_fd, original_termios)?;
    let mut child = ChildGuard::new(child);
    let mut master_reader = master
        .try_clone()
        .map_err(|source| execute_error(program, source))?;
    let mut master_writer = master;
    let mut stdin_open = true;
    let mut master_open = true;
    let mut exit_status = None;
    let mut exit_seen = None;
    let mut clipboard_imports = Vec::new();
    let mut output_filter = TerminalOutputFilter::default();

    while exit_status.is_none() || master_open {
        let mut descriptors = [
            libc::pollfd {
                fd: stdin_fd,
                events: if stdin_open { libc::POLLIN } else { 0 },
                revents: 0,
            },
            libc::pollfd {
                fd: master_reader.as_raw_fd(),
                events: if master_open { libc::POLLIN } else { 0 },
                revents: 0,
            },
        ];
        // SAFETY: descriptors points to two initialized pollfd values for the duration of poll.
        let poll_result = unsafe {
            libc::poll(
                descriptors.as_mut_ptr(),
                descriptors.len() as libc::nfds_t,
                POLL_INTERVAL_MS,
            )
        };
        if poll_result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(execute_error(program, error));
            }
        }

        if stdin_open && descriptors[0].revents & libc::POLLIN != 0 {
            let mut input = [0_u8; 4096];
            // SAFETY: input is a valid writable buffer and stdin_fd remains open.
            let count = unsafe { libc::read(stdin_fd, input.as_mut_ptr().cast(), input.len()) };
            if count > 0 {
                for segment in input[..count as usize].split_inclusive(|byte| *byte == CTRL_V) {
                    let has_clipboard = segment.last() == Some(&CTRL_V);
                    let ordinary = if has_clipboard {
                        &segment[..segment.len() - 1]
                    } else {
                        segment
                    };
                    if !ordinary.is_empty() {
                        master_writer
                            .write_all(ordinary)
                            .map_err(|source| execute_error(program, source))?;
                    }
                    if has_clipboard {
                        match clipboard() {
                            Ok(paste) => {
                                write_bracketed_paste(&mut master_writer, &paste.text)
                                    .map_err(|source| execute_error(program, source))?;
                                clipboard_imports.push(paste.audit);
                            }
                            Err(error) => {
                                write_host_notice(&format!("{error}"));
                            }
                        }
                    }
                }
            } else if count == 0 {
                stdin_open = false;
            } else {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    stdin_open = false;
                }
            }
        }
        if descriptors[0].revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
            stdin_open = false;
        }

        if master_open
            && descriptors[1].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0
        {
            let mut output = [0_u8; 32 * 1024];
            match master_reader.read(&mut output) {
                Ok(0) => master_open = false,
                Ok(count) => {
                    let safe = output_filter.filter(&output[..count]);
                    io::stdout()
                        .write_all(&safe)
                        .and_then(|()| io::stdout().flush())
                        .map_err(|source| execute_error(program, source))?;
                }
                Err(error)
                    if matches!(
                        error.raw_os_error(),
                        Some(libc::EIO) | Some(libc::EINTR) | Some(libc::EAGAIN)
                    ) =>
                {
                    if error.raw_os_error() == Some(libc::EIO) {
                        master_open = false;
                    }
                }
                Err(error) => return Err(execute_error(program, error)),
            }
        }
        if descriptors[1].revents & libc::POLLNVAL != 0 {
            master_open = false;
        }

        if let Some(size) = terminal_size(stdout_fd)
            && !same_window_size(&window, &size)
        {
            set_terminal_size(master_reader.as_raw_fd(), &size)?;
            window = size;
        }

        if exit_status.is_none()
            && let Some(status) = child
                .child_mut()
                .try_wait()
                .map_err(|source| execute_error(program, source))?
        {
            exit_status = Some(status);
            exit_seen = Some(Instant::now());
        }
        if exit_seen.is_some_and(|seen| seen.elapsed() >= EXIT_DRAIN_TIMEOUT) {
            master_open = false;
        }
    }

    child.disarm();
    Ok(InteractiveOutcome {
        status: exit_status.ok_or_else(|| RunnerError::Execute {
            program: program.to_path_buf(),
            source: io::Error::other("interactive child exited without a status"),
        })?,
        clipboard_imports,
    })
}

fn open_pty(termios: &libc::termios, window: &libc::winsize) -> Result<(File, File), RunnerError> {
    let mut master: RawFd = -1;
    let mut slave: RawFd = -1;
    #[cfg(target_os = "macos")]
    let mut termios = *termios;
    #[cfg(not(target_os = "macos"))]
    let termios = *termios;
    #[cfg(target_os = "macos")]
    let mut window = *window;
    #[cfg(not(target_os = "macos"))]
    let window = *window;
    // SAFETY: openpty initializes both descriptors. The termios and window pointers remain valid
    // for the duration of the call.
    #[cfg(target_os = "macos")]
    let result = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            &mut termios,
            &mut window,
        )
    };
    #[cfg(not(target_os = "macos"))]
    let result = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            &termios,
            &window,
        )
    };
    if result != 0 {
        return Err(execute_error(
            Path::new("openpty"),
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: openpty returned two new owned descriptors on success.
    Ok(unsafe { (File::from_raw_fd(master), File::from_raw_fd(slave)) })
}

fn terminal_attributes(fd: RawFd) -> Result<libc::termios, RunnerError> {
    let mut attributes = std::mem::MaybeUninit::<libc::termios>::uninit();
    // SAFETY: tcgetattr initializes attributes when it succeeds.
    if unsafe { libc::tcgetattr(fd, attributes.as_mut_ptr()) } != 0 {
        return Err(execute_error(
            Path::new("terminal"),
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: successful tcgetattr initialized the value.
    Ok(unsafe { attributes.assume_init() })
}

fn terminal_size(fd: RawFd) -> Option<libc::winsize> {
    let mut size = std::mem::MaybeUninit::<libc::winsize>::zeroed();
    // SAFETY: ioctl initializes the winsize on success.
    if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ as _, size.as_mut_ptr()) } == 0 {
        // SAFETY: successful ioctl initialized the value.
        Some(unsafe { size.assume_init() })
    } else {
        None
    }
}

fn set_terminal_size(fd: RawFd, size: &libc::winsize) -> Result<(), RunnerError> {
    // SAFETY: fd is the live PTY master and size points to a valid winsize.
    if unsafe { libc::ioctl(fd, libc::TIOCSWINSZ as _, size) } != 0 {
        return Err(execute_error(
            Path::new("terminal resize"),
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}

fn same_window_size(left: &libc::winsize, right: &libc::winsize) -> bool {
    left.ws_row == right.ws_row
        && left.ws_col == right.ws_col
        && left.ws_xpixel == right.ws_xpixel
        && left.ws_ypixel == right.ws_ypixel
}

struct RawTerminal {
    fd: RawFd,
    original: libc::termios,
}

impl RawTerminal {
    fn enter(fd: RawFd, original: libc::termios) -> Result<Self, RunnerError> {
        disable_host_mouse_reporting();
        let mut raw = original;
        // SAFETY: raw is a valid mutable termios structure.
        unsafe {
            libc::cfmakeraw(&mut raw);
        }
        // SAFETY: fd is the current terminal and raw remains valid during the call.
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } != 0 {
            return Err(execute_error(
                Path::new("terminal"),
                io::Error::last_os_error(),
            ));
        }
        Ok(Self { fd, original })
    }
}

impl Drop for RawTerminal {
    fn drop(&mut self) {
        disable_host_mouse_reporting();
        // SAFETY: best-effort restoration of the same terminal descriptor.
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSANOW, &self.original);
        }
    }
}

struct ChildGuard {
    child: Option<Child>,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    fn child_mut(&mut self) -> &mut Child {
        self.child.as_mut().expect("child must remain armed")
    }

    fn disarm(&mut self) {
        self.child.take();
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn write_bracketed_paste(writer: &mut File, text: &str) -> io::Result<()> {
    writer.write_all(b"\x1b[200~")?;
    writer.write_all(text.as_bytes())?;
    writer.write_all(b"\x1b[201~")?;
    writer.flush()
}

fn write_host_notice(message: &str) {
    let _ = writeln!(io::stderr(), "\r\nguard: {message}\r");
}

fn execute_error(program: &Path, source: io::Error) -> RunnerError {
    RunnerError::Execute {
        program: PathBuf::from(program),
        source,
    }
}

fn disable_host_mouse_reporting() {
    let _ = io::stdout()
        .write_all(DISABLE_MOUSE_REPORTING)
        .and_then(|()| io::stdout().flush());
}

#[derive(Default)]
struct TerminalOutputFilter {
    state: OutputState,
}

#[derive(Default)]
enum OutputState {
    #[default]
    Normal,
    Escape,
    Osc {
        bytes: Vec<u8>,
        previous_escape: bool,
    },
    DiscardControlString {
        previous_escape: bool,
    },
    Csi {
        bytes: Vec<u8>,
    },
    DiscardOsc {
        previous_escape: bool,
    },
    DiscardCsi,
}

impl TerminalOutputFilter {
    fn filter(&mut self, input: &[u8]) -> Vec<u8> {
        let mut output = Vec::with_capacity(input.len());
        for &byte in input {
            let state = std::mem::take(&mut self.state);
            self.state = match state {
                OutputState::Normal if byte == 0x1b => OutputState::Escape,
                OutputState::Normal => {
                    output.push(byte);
                    OutputState::Normal
                }
                OutputState::Escape if byte == b']' => OutputState::Osc {
                    bytes: vec![0x1b, b']'],
                    previous_escape: false,
                },
                OutputState::Escape if byte == b'[' => OutputState::Csi {
                    bytes: vec![0x1b, b'['],
                },
                OutputState::Escape if matches!(byte, b'P' | b'X' | b'^' | b'_') => {
                    OutputState::DiscardControlString {
                        previous_escape: false,
                    }
                }
                OutputState::Escape => {
                    output.push(0x1b);
                    output.push(byte);
                    OutputState::Normal
                }
                OutputState::Osc {
                    mut bytes,
                    previous_escape,
                } => {
                    bytes.push(byte);
                    let terminated = byte == 0x07 || previous_escape && byte == b'\\';
                    if terminated {
                        if !is_host_sensitive_osc(&bytes) {
                            output.extend_from_slice(&bytes);
                        }
                        OutputState::Normal
                    } else if bytes.len() > MAX_OSC_BYTES {
                        OutputState::DiscardOsc {
                            previous_escape: byte == 0x1b,
                        }
                    } else {
                        OutputState::Osc {
                            bytes,
                            previous_escape: byte == 0x1b,
                        }
                    }
                }
                OutputState::DiscardOsc { previous_escape } => {
                    if byte == 0x07 || previous_escape && byte == b'\\' {
                        OutputState::Normal
                    } else {
                        OutputState::DiscardOsc {
                            previous_escape: byte == 0x1b,
                        }
                    }
                }
                OutputState::DiscardControlString { previous_escape } => {
                    if previous_escape && byte == b'\\' {
                        OutputState::Normal
                    } else {
                        OutputState::DiscardControlString {
                            previous_escape: byte == 0x1b,
                        }
                    }
                }
                OutputState::Csi { mut bytes } => {
                    bytes.push(byte);
                    if (0x40..=0x7e).contains(&byte) {
                        output.extend_from_slice(&without_mouse_reporting_modes(&bytes));
                        OutputState::Normal
                    } else if bytes.len() > MAX_CSI_BYTES {
                        OutputState::DiscardCsi
                    } else {
                        OutputState::Csi { bytes }
                    }
                }
                OutputState::DiscardCsi => {
                    if (0x40..=0x7e).contains(&byte) {
                        OutputState::Normal
                    } else {
                        OutputState::DiscardCsi
                    }
                }
            };
        }
        output
    }
}

fn is_host_sensitive_osc(sequence: &[u8]) -> bool {
    let payload = sequence.strip_prefix(b"\x1b]");
    let Some(command) = payload.and_then(|payload| payload.split(|byte| *byte == b';').next())
    else {
        return false;
    };
    std::str::from_utf8(command)
        .ok()
        .and_then(|command| command.parse::<u16>().ok())
        .is_some_and(|command| matches!(command, 52 | 1337))
}

fn without_mouse_reporting_modes(sequence: &[u8]) -> Vec<u8> {
    let (prefix, body) = if let Some(body) = sequence.strip_prefix(b"\x1b[?") {
        (b"\x1b[?".as_slice(), body)
    } else {
        return sequence.to_vec();
    };
    let Some((&final_byte, parameters)) = body.split_last() else {
        return sequence.to_vec();
    };
    if !matches!(final_byte, b'h' | b'l') || parameters.is_empty() {
        return sequence.to_vec();
    }

    let mut retained = Vec::new();
    for parameter in parameters.split(|byte| *byte == b';') {
        let Ok(parameter_text) = std::str::from_utf8(parameter) else {
            return sequence.to_vec();
        };
        let Ok(mode) = parameter_text.parse::<u16>() else {
            return sequence.to_vec();
        };
        if !matches!(
            mode,
            9 | 1000 | 1001 | 1002 | 1003 | 1005 | 1006 | 1015 | 1016
        ) {
            retained.push(parameter);
        }
    }
    if retained.is_empty() {
        return Vec::new();
    }

    let mut rewritten = Vec::with_capacity(sequence.len());
    rewritten.extend_from_slice(prefix);
    for (index, parameter) in retained.iter().enumerate() {
        if index > 0 {
            rewritten.push(b';');
        }
        rewritten.extend_from_slice(parameter);
    }
    rewritten.push(final_byte);
    rewritten
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_filter_blocks_osc_52_queries_and_writes_across_chunks() {
        let mut filter = TerminalOutputFilter::default();
        assert_eq!(filter.filter(b"before\x1b]52;c;?"), b"before");
        assert_eq!(filter.filter(b"\x07after"), b"after");
        assert_eq!(
            filter.filter(b"\x1b]0;safe title\x07visible"),
            b"\x1b]0;safe title\x07visible"
        );
    }

    #[test]
    fn osc_classifier_matches_host_clipboard_and_iterm_control_commands() {
        assert!(is_host_sensitive_osc(b"\x1b]52;c;?\x07"));
        assert!(is_host_sensitive_osc(b"\x1b]052;c;?\x07"));
        assert!(is_host_sensitive_osc(b"\x1b]1337;CopyToClipboard=YQ==\x07"));
        assert!(!is_host_sensitive_osc(b"\x1b]520;c;?\x07"));
        assert!(!is_host_sensitive_osc(b"ordinary"));
    }

    #[test]
    fn output_filter_preserves_utf8_and_blocks_opaque_multiplexer_passthrough() {
        let mut filter = TerminalOutputFilter::default();
        let utf8 = "before ┐ ├ ┘ 四 中文 after";
        assert_eq!(filter.filter(utf8.as_bytes()), utf8.as_bytes());
        assert_eq!(
            filter.filter(b"raw C1 \x9d52;c;?\x9c remains data"),
            b"raw C1 \x9d52;c;?\x9c remains data"
        );
        assert_eq!(
            filter.filter(b"visible\x1bPtmux;\x1b\x1b]52;c;?"),
            b"visible"
        );
        assert_eq!(filter.filter(b"\x1b\\after"), b"after");
    }

    #[test]
    fn output_filter_suppresses_mouse_reporting_without_breaking_other_private_modes() {
        let mut filter = TerminalOutputFilter::default();
        assert_eq!(
            filter.filter(b"before\x1b[?1000h\x1b[?1002;1006hafter"),
            b"beforeafter"
        );
        assert_eq!(
            filter.filter(b"\x1b[?25;1003l\x1b[?2004h"),
            b"\x1b[?25l\x1b[?2004h"
        );
        assert_eq!(filter.filter(b"\x1b[?10"), b"");
        assert_eq!(filter.filter(b"00hvisible"), b"visible");
    }
}
