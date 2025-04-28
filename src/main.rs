use std::path::Path;
use std::env;
use std::fs;

mod database;
mod hashing;
mod logger;
mod realtime_monitoring;
mod auditd;

#[tokio::main]
async fn main() {
    // Get the current working directory
    let current_dir = env::current_dir().expect("Failed to get current directory");
    
    // Convert relative path to absolute path
    let dir_to_watch = current_dir.join("watch_dir");
    let dir_to_watch_str = dir_to_watch.to_str().expect("Failed to convert path to string");
    
    let db_path = "file_integrity.db";
    let log_file = "integrity_log.txt";

    // Create watch directory if it doesn't exist
    if !dir_to_watch.exists() {
        fs::create_dir_all(&dir_to_watch).expect("Failed to create watch directory");
    }

    // Setup auditd rules with absolute path
    if let Err(e) = auditd::setup_auditd_rules(dir_to_watch_str) {
        println!("⚠️ Failed to setup auditd rules: {}", e);
        println!("⚠️ Audit logging will not be available. Please run with sudo privileges.");
    }

    println!("🔍 Performing initial scan...");
    realtime_monitoring::monitor_directory(dir_to_watch_str, db_path, log_file).await;
}