use rusqlite::{params, Connection, Result};
use std::path::Path;

#[derive(Debug)]
pub struct FileEntry {
    pub path: String,
    pub hash: String,
}

pub fn init_db(db_path: &str) -> Result<Connection> {
    let conn = Connection::open(db_path)?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS files (
            path TEXT PRIMARY KEY,
            hash TEXT NOT NULL
        )",
        [],
    )?;
    Ok(conn)
}

pub fn insert_or_update_hash(conn: &Connection, entry: &FileEntry) -> Result<()> {
    conn.execute(
        "INSERT INTO files (path, hash) VALUES (?1, ?2)
         ON CONFLICT(path) DO UPDATE SET hash = excluded.hash",
        params![entry.path, entry.hash],
    )?;
    Ok(())
}

pub fn get_hash(conn: &Connection, path: &str) -> Result<Option<String>> {
    let mut stmt = conn.prepare("SELECT hash FROM files WHERE path = ?1")?;
    let mut rows = stmt.query(params![path])?;
    if let Some(row) = rows.next()? {
        Ok(Some(row.get(0)?))
    } else {
        Ok(None)
    }
}
