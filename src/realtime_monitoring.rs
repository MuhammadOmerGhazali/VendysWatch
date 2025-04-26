use notify::{RecommendedWatcher, RecursiveMode, Result as NotifyResult, Watcher, Event, Config, EventKind};
use crate::database::{init_db, get_hash, insert_or_update_hash, FileEntry};
use crate::hashing::compute_sha256;
use crate::logger::log_change;
use reqwest::Client;
use std::path::Path;
use chrono::Local;
use walkdir::WalkDir;
use std::fs;

const TELEGRAM_BOT_TOKEN: &str = "7948144590:AAGawKpE1Z7DZM4sGArrdH2878WEruAGev0";
const TELEGRAM_CHAT_ID: &str = "6149770430";

pub async fn monitor_directory(dir_to_watch: &str, db_path: &str, log_file: &str) {
    
    let path = Path::new(dir_to_watch);
    if !path.exists() {
        fs::create_dir_all(path).expect("Failed to create watch directory");
        println!("📁 Created directory: {}", path.display());
        log_change(log_file, &format!("CREATED DIRECTORY: {}", path.display()));
    } else if !path.is_dir() {
        panic!("⚠️ The path '{}' is not a directory!", path.display());
    }


    let conn = init_db(db_path).expect("Failed to initialize database");
    initial_scan(dir_to_watch, &conn, log_file).await;

    start_realtime_monitoring(dir_to_watch, db_path, log_file).await;
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
                            log_change(
                                log_file,
                                &format!(
                                    "MODIFIED: {}\nOld Hash: {}\nNew Hash: {}",
                                    file_path_str, prev_hash, current_hash
                                ),
                            );

                            let text = format!(
                                "⚡ *File Modified!*\n📄 Path: `{}`\n🔑 New Hash: `{}`\n🔑 Old Hash: `{}`\n🕒 Time: {}",
                                file_path_str,
                                current_hash,
                                prev_hash,
                                Local::now().format("%Y-%m-%d %H:%M:%S")
                            );
                            send_telegram_alert(&Client::new(), &text).await;
                        } else {
                            println!("✅ File unchanged: {}", file_path_str);
                        }
                    } else {
                        println!("🆕 New file detected during initial scan: {}", file_path_str);
                        log_change(
                            log_file,
                            &format!("NEW FILE: {}\nHash: {}", file_path_str, current_hash),
                        );

                        let text = format!(
                            "🆕 *New File Detected!*\n📄 Path: `{}`\n🔑 Hash: `{}`\n🕒 Time: {}",
                            file_path_str,
                            current_hash,
                            Local::now().format("%Y-%m-%d %H:%M:%S")
                        );
                        send_telegram_alert(&Client::new(), &text).await;
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

async fn start_realtime_monitoring(dir_to_watch: &str, db_path: &str, log_file: &str) {
    println!("🚀 Starting real-time monitoring for directory: {}", dir_to_watch);

    let (tx, mut rx) = tokio::sync::mpsc::channel(100);
    let db_path = db_path.to_string();
    let log_file = log_file.to_string();

    let mut watcher = RecommendedWatcher::new(
        move |res: NotifyResult<Event>| {
            if let Ok(event) = res {
                let _ = tx.blocking_send(event);
            }
        },
        Config::default(),
    )
    .expect("Failed to create watcher");

    watcher
        .watch(dir_to_watch.as_ref(), RecursiveMode::Recursive)
        .expect("Failed to start watching");

    let client = Client::new();

    while let Some(event) = rx.recv().await {
        for path in event.paths {
            let file_path_str = match path.to_str() {
                Some(s) => s.to_string(),
                None => continue,
            };

            let conn = init_db(&db_path).expect("DB connection failed");

            match event.kind {
                EventKind::Create(_) => {
                    if path.is_file() {
                        match compute_sha256(&file_path_str) {
                            Ok(current_hash) => {
                                println!("🆕 New file detected: {}", file_path_str);
                                log_change(
                                    &log_file,
                                    &format!("NEW FILE: {}\nHash: {}", file_path_str, current_hash),
                                );

                                let text = format!(
                                    "🆕 *New File Detected!*\n📄 Path: `{}`\n🔑 Hash: `{}`\n🕒 Time: {}",
                                    file_path_str,
                                    current_hash,
                                    Local::now().format("%Y-%m-%d %H:%M:%S")
                                );
                                send_telegram_alert(&client, &text).await;

                                let entry = FileEntry {
                                    path: file_path_str,
                                    hash: current_hash,
                                };
                                insert_or_update_hash(&conn, &entry).expect("DB write failed");
                            }
                            Err(e) => {
                                println!("❌ Failed to compute hash for new file {}: {}", file_path_str, e);
                            }
                        }
                    }
                }
                EventKind::Modify(_) => {
                    if path.is_file() {
                        match compute_sha256(&file_path_str) {
                            Ok(current_hash) => {
                                let previous_hash = get_hash(&conn, &file_path_str).expect("DB read failed");

                                if let Some(prev_hash) = previous_hash {
                                    if prev_hash != current_hash {
                                        println!("⚠️ File modified: {}", file_path_str);
                                        log_change(
                                            &log_file,
                                            &format!(
                                                "MODIFIED: {}\nOld Hash: {}\nNew Hash: {}",
                                                file_path_str, prev_hash, current_hash
                                            ),
                                        );

                                        let text = format!(
                                            "⚡ *File Modified!*\n📄 Path: `{}`\n🔑 New Hash: `{}`\n🔑 Old Hash: `{}`\n🕒 Time: {}",
                                            file_path_str,
                                            current_hash,
                                            prev_hash,
                                            Local::now().format("%Y-%m-%d %H:%M:%S")
                                        );
                                        send_telegram_alert(&client, &text).await;

                                        let entry = FileEntry {
                                            path: file_path_str,
                                            hash: current_hash,
                                        };
                                        insert_or_update_hash(&conn, &entry).expect("DB write failed");
                                    }
                                }
                            }
                            Err(e) => {
                                println!("❌ Failed to compute hash for file {}: {}", file_path_str, e);
                            }
                        }
                    }
                }
                EventKind::Remove(_) => {
                    println!("🗑️ File deleted: {}", file_path_str);
                    log_change(&log_file, &format!("DELETED FILE: {}", file_path_str));

                    let text = format!(
                        "🗑️ *File Deleted!*\n📄 Path: `{}`\n🕒 Time: {}",
                        file_path_str,
                        Local::now().format("%Y-%m-%d %H:%M:%S")
                    );
                    send_telegram_alert(&client, &text).await;

                    conn.execute("DELETE FROM files WHERE path = ?1", [&file_path_str])
                        .expect("Failed to delete file from database");
                }
                _ => {}
            }
        }
    }
}

async fn send_telegram_alert(client: &Client, text: &str) {
    let url = format!("https://api.telegram.org/bot{}/sendMessage", TELEGRAM_BOT_TOKEN);

    let res = client
        .post(&url)
        .form(&[
            ("chat_id", TELEGRAM_CHAT_ID),
            ("text", text),
            ("parse_mode", "Markdown"),
        ])
        .send()
        .await;

    match res {
        Ok(response) => {
            if response.status().is_success() {
                println!("✅ Telegram alert sent successfully!");
            } else {
                println!("⚠️ Telegram server responded with error: {:?}", response.status());
            }
        }
        Err(err) => {
            println!("❌ Failed to send Telegram message: {}", err);
        }
    }
}