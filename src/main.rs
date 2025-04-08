mod hashing;
mod database;
mod logger;

use database::{init_db, insert_or_update_hash, get_hash, FileEntry};
use logger::log_change;

fn main() {
    let file_path = "test.txt";
    let db_path = "file_integrity.db";
    let log_file = "integrity_log.txt";

    let hash = hashing::compute_sha256(file_path).expect("Failed to hash file");
    println!("Current hash: {}", hash);

    let conn = init_db(db_path).expect("Failed to connect to DB");

    let previous = get_hash(&conn, file_path).expect("DB read error");

    if let Some(prev_hash) = previous {
        if prev_hash != hash {
            println!("⚠️ File has been modified!");
            log_change(log_file, &format!(
                "MODIFIED: {}\nOld Hash: {}\nNew Hash: {}",
                file_path, prev_hash, hash
            ));
        } else {
            println!("✅ File is unchanged.");
            log_change(log_file, &format!("UNCHANGED: {}", file_path));
        }
    } else {
        println!("🔍 No record found. Storing initial hash.");
        log_change(log_file, &format!("NEW FILE: {}\nHash: {}", file_path, hash));
    }

    let entry = FileEntry {
        path: file_path.to_string(),
        hash,
    };

    insert_or_update_hash(&conn, &entry).expect("Failed to write to DB");
}
