#![allow(dead_code)]
use std::process::Command;

pub fn copy_with_notification(content: &str, timeout_secs: u64) {
    if let Ok(mut board) = arboard::Clipboard::new() {
        let _ = board.set_text(content);
    }

    // Schedule detached background clipboard wipe
    if timeout_secs > 0 {
        #[cfg(target_os = "macos")]
        {
            let _ = Command::new("sh")
                .arg("-c")
                .arg(format!(
                    "(sleep {} && pbcopy < /dev/null) >/dev/null 2>&1 &",
                    timeout_secs
                ))
                .spawn();
        }
        #[cfg(target_os = "linux")]
        {
            let _ = Command::new("sh")
                .arg("-c")
                .arg(format!(
                    "(sleep {} && (command -v wl-copy >/dev/null 2>&1 && wl-copy --clear || command -v xclip >/dev/null 2>&1 && xclip -selection clipboard /dev/null || true)) >/dev/null 2>&1 &",
                    timeout_secs
                ))
                .spawn();
        }
        #[cfg(windows)]
        {
            let _ = Command::new("cmd")
                .args([
                    "/c",
                    &format!(
                        "start /b \"\" powershell -NoProfile -Command \"Start-Sleep -Seconds {}; [Windows.Forms.Clipboard]::Clear()\"",
                        timeout_secs
                    ),
                ])
                .spawn();
        }
    }

    println!(
        "\x1b[1;38;2;52;211;153m✔\x1b[0m Copied to clipboard. Auto-wipes in {}s...",
        timeout_secs
    );
}

pub fn copy_with_bell(content: &str) {
    print!("\x07");
    copy_with_notification(content, 15);
}
