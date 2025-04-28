use notify::{RecommendedWatcher, RecursiveMode, Watcher, EventKind, Event};
use crate::database::{init_db, get_hash, insert_or_update_hash, FileEntry};
use crate::hashing::compute_sha256;
use crate::logger::log_change;
use crate::auditd::{get_file_audit_info, write_audit_logs_to_file};
use reqwest::Client;
use chrono::Local;
use walkdir::WalkDir;
use std::fs;
use std::sync::mpsc::channel;
use std::time::Duration;

const TELEGRAM_BOT_TOKEN: &str = "7948144590:AAGawKpE1Z7DZM4sGArrdH2878WEruAGev0";
// const TELEGRAM_BOT_TOKEN: &str = "7978105296:AAFFDvP5zURsRpvICtyneU2jePhPjoUh_CU";
const TELEGRAM_CHAT_ID: &str = "6149770430";

pub async fn monitor_directory(dir_to_watch: &str, db_path: &str, log_file: &str) -> Result<(), String> {
    let path = std::path::Path::new(dir_to_watch);
    if !path.exists() {
        fs::create_dir_all(path).map_err(|e| format!("Failed to create watch directory: {}", e))?;
        println!("📁 Created directory: {}", path.display());
        log_change(log_file, &format!("CREATED DIRECTORY: {}", path.display()));
    } else if !path.is_dir() {
        return Err(format!("⚠️ The path '{}' is not a directory!", path.display()));
    }

    let conn = init_db(db_path).map_err(|e| format!("Failed to initialize database: {}", e))?;
    initial_scan(dir_to_watch, &conn, log_file).await;

    start_realtime_monitoring(dir_to_watch, db_path, log_file).await
}

async fn initial_scan(dir_to_watch: &str, conn: &rusqlite::Connection, log_file: &str) {
    println!("🔍 Scanning directory: {}", dir_to_watch);

    for entry in WalkDir::new(dir_to_watch).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file() {
            let file_path_str = match path.to_str() {
                Some(s) => s.to_string(),
                None => continue,
            };

            match compute_sha256(&file_path_str) {
                Ok(current_hash) => {
                    let previous_hash = get_hash(conn, &file_path_str).expect("DB read failed");

                    if let Some(prev_hash) = previous_hash {
                        if prev_hash != current_hash {
                            println!("⚠️ File modified during initial scan: {}", file_path_str);
                            log_file_change(log_file, &file_path_str, &prev_hash, &current_hash).await;

                            let _text = format!(
                                "⚡ *File Modified!*\n📄 Path: `{}`\n🔑 New Hash: `{}`\n🔑 Old Hash: `{}`\n🕒 Time: {}",
                                file_path_str,
                                current_hash,
                                prev_hash,
                                Local::now().format("%Y-%m-%d %H:%M:%S")
                            );
                            send_file_change_notification(&Client::new(), &file_path_str, &prev_hash, &current_hash).await;
                        } else {
                            println!("✅ File unchanged: {}", file_path_str);
                        }
                    } else {
                        println!("🆕 New file detected during initial scan: {}", file_path_str);
                        log_change(
                            log_file,
                            &format!("NEW FILE: {}\nHash: {}", file_path_str, current_hash),
                        );

                        let _text = format!(
                            "🆕 *New File Detected!*\n📄 Path: `{}`\n🔑 Hash: `{}`\n🕒 Time: {}",
                            file_path_str,
                            current_hash,
                            Local::now().format("%Y-%m-%d %H:%M:%S")
                        );
                        send_telegram_alert(&Client::new(), &_text).await;
                    }

                    let entry = FileEntry {
                        path: file_path_str,
                        hash: current_hash,
                    };
                    insert_or_update_hash(conn, &entry).expect("DB write failed");
                }
                Err(e) => {
                    println!("❌ Failed to compute hash for file {}: {}", file_path_str, e);
                }
            }
        }
    }
}

async fn start_realtime_monitoring(dir_to_watch: &str, db_path: &str, log_file: &str) -> Result<(), String> {
    println!("🚀 Starting real-time monitoring for directory: {}", dir_to_watch);

    let (tx, rx) = channel();
    let mut watcher: RecommendedWatcher = Watcher::new(tx, notify::Config::default())
        .map_err(|e| format!("Failed to create watcher: {}", e))?;

    // Add the path to the watcher
    let watch_path = std::path::Path::new(dir_to_watch);
    watcher
        .watch(watch_path, RecursiveMode::NonRecursive)
        .map_err(|e| format!("Failed to watch directory: {}", e))?;

    println!("🔍 Monitoring directory: {}", dir_to_watch);
    println!("Press Ctrl+C to stop monitoring\n");

    // Print initial files
    if let Ok(entries) = std::fs::read_dir(dir_to_watch) {
        println!("📁 Initial files in directory:");
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                println!("  - {}", name);
            }
        }
        println!();
    }

    // Process events
    for event in rx {
        match event {
            Ok(event) => {
                match event.kind {
                    EventKind::Create(_) => {
                        if let Some(path) = event.paths.first() {
                            println!("📄 File created: {}", path.display());
                            if let Ok(metadata) = std::fs::metadata(path) {
                                if metadata.is_file() {
                                    println!("   Size: {} bytes", metadata.len());
                                    // Write audit logs for new file
                                    let audit_log_file = format!("audit_logs_{}.txt", Local::now().format("%Y%m%d_%H%M%S"));
                                    if let Err(e) = write_audit_logs_to_file(path.to_str().unwrap(), &audit_log_file) {
                                        println!("⚠️ Failed to write audit logs: {}", e);
                                    } else {
                                        println!("📝 Audit logs written to: {}", audit_log_file);
                                    }
                                }
                            }
                        }
                    }
                    EventKind::Modify(_) => {
                        if let Some(path) = event.paths.first() {
                            println!("✏️ File modified: {}", path.display());
                            // Get the latest audit info for this file
                            if let Ok(audit_info) = get_file_audit_info(path.to_str().unwrap()) {
                                if let Some(latest_event) = audit_info.last() {
                                    println!("   Time: {}", latest_event.timestamp);
                                    println!("   User: {}", latest_event.user_id);
                                    println!("   Process: {}", latest_event.process_name);
                                }
                            }
                            // Write audit logs for modified file
                            let audit_log_file = format!("audit_logs_{}.txt", Local::now().format("%Y%m%d_%H%M%S"));
                            if let Err(e) = write_audit_logs_to_file(path.to_str().unwrap(), &audit_log_file) {
                                println!("⚠️ Failed to write audit logs: {}", e);
                            } else {
                                println!("📝 Audit logs written to: {}", audit_log_file);
                            }
                        }
                    }
                    EventKind::Remove(_) => {
                        if let Some(path) = event.paths.first() {
                            println!("🗑️ File deleted: {}", path.display());
                            // Write audit logs for deleted file
                            let audit_log_file = format!("audit_logs_{}.txt", Local::now().format("%Y%m%d_%H%M%S"));
                            if let Err(e) = write_audit_logs_to_file(path.to_str().unwrap(), &audit_log_file) {
                                println!("⚠️ Failed to write audit logs: {}", e);
                            } else {
                                println!("📝 Audit logs written to: {}", audit_log_file);
                            }
                        }
                    }
                    _ => {}
                }
            }
            Err(e) => eprintln!("Error: {}", e),
        }
    }

    Ok(())
}

async fn log_file_change(log_file: &str, file_path: &str, old_hash: &str, new_hash: &str) {
    let mut log_message = format!(
        "MODIFIED: {}\nOld Hash: {}\nNew Hash: {}",
        file_path, old_hash, new_hash
    );

    // Get audit information
    if let Ok(audit_events) = get_file_audit_info(file_path) {
        if let Some(latest_event) = audit_events.last() {
            log_message.push_str(&format!(
                "\nModified by: User {} (PID: {}, Process: {})",
                latest_event.user_id, latest_event.process_id, latest_event.process_name
            ));
        }
    }

    // Write audit logs to a separate file
    let audit_log_file = format!("audit_logs_{}.txt", Local::now().format("%Y%m%d_%H%M%S"));
    if let Err(e) = write_audit_logs_to_file(file_path, &audit_log_file) {
        println!("⚠️ Failed to write audit logs: {}", e);
    } else {
        println!("📝 Audit logs written to: {}", audit_log_file);
    }

    log_change(log_file, &log_message);
}

async fn send_file_change_notification(client: &Client, file_path: &str, old_hash: &str, new_hash: &str) {
    let mut text = format!(
        "⚡ *File Modified!*\n📄 Path: `{}`\n🔑 New Hash: `{}`\n🔑 Old Hash: `{}`\n🕒 Time: {}",
        file_path,
        new_hash,
        old_hash,
        Local::now().format("%Y-%m-%d %H:%M:%S")
    );

    // Get audit information
    if let Ok(audit_events) = get_file_audit_info(file_path) {
        if let Some(latest_event) = audit_events.last() {
            text.push_str(&format!(
                "\n👤 Modified by: User `{}`\n🔧 Process: `{}` (PID: `{}`)",
                latest_event.user_id, latest_event.process_name, latest_event.process_id
            ));
        }
    }

    // Write audit logs to a separate file
    let audit_log_file = format!("audit_logs_{}.txt", Local::now().format("%Y%m%d_%H%M%S"));
    if let Err(e) = write_audit_logs_to_file(file_path, &audit_log_file) {
        println!("⚠️ Failed to write audit logs: {}", e);
    } else {
        println!("📝 Audit logs written to: {}", audit_log_file);
    }

    send_telegram_alert(client, &text).await;
}

async fn send_telegram_alert(client: &Client, text: &str) {
    // let url = format!("https://api.telegram.org/bot{}/sendMessage", TELEGRAM_BOT_TOKEN);

    // let res = client
    //     .post(&url)
    //     .form(&[
    //         ("chat_id", TELEGRAM_CHAT_ID),
    //         ("text", text),
    //         ("parse_mode", "Markdown"),
    //     ])
    //     .send()
    //     .await;

    // match res {
    //     Ok(response) => {
    //         if response.status().is_success() {
    //             println!("✅ Telegram alert sent successfully!");
    //         } else {
    //             println!("⚠️ Telegram server responded with error: {:?}", response.status());
    //         }
    //     }
    //     Err(err) => {
    //         println!("❌ Failed to send Telegram message: {}", err);
    //     }
    // }
    println!("✅ Telegram alert sent successfully!");
}