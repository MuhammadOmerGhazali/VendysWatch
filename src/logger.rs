use chrono::Local;
use std::fs::{OpenOptions};
use std::io::Write;
use std::path::Path;

pub fn log_change<P: AsRef<Path>>(log_file: P, message: &str) {
    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let full_message = format!("[{}] {}\n", timestamp, message);

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_file)
        .expect("Failed to open log file");

    file.write_all(full_message.as_bytes()).expect("Failed to write to log file");
}
