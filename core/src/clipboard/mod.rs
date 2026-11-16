use std::thread;
use std::time::Duration;

pub fn clear_after(seconds: u64) {
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(seconds));
        #[cfg(target_os = "macos")]
        {
            let _ = std::process::Command::new("sh")
                .arg("-c")
                .arg("pbcopy < /dev/null")
                .spawn();
        }
        #[cfg(target_os = "linux")]
        {
            let _ = std::process::Command::new("sh")
                .arg("-c")
                .arg("command -v wl-copy >/dev/null 2>&1 && wl-copy --clear || command -v xclip >/dev/null 2>&1 && xclip -selection clipboard /dev/null || true")
                .spawn();
        }
    });
}

pub fn copy(_data: &[u8]) {}

pub fn clear() {
    clear_after(0);
}
