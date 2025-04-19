mod database;
mod hashing;
mod logger;
mod realtime_monitoring;

#[tokio::main]
async fn main() {
    let dir_to_watch = "./test.txt"; 
    let db_path = "file_integrity.db";
    let log_file = "integrity_log.txt";

    println!("🔍 Performing initial scan...");
    realtime_monitoring::monitor_directory(dir_to_watch, db_path, log_file).await;
}
