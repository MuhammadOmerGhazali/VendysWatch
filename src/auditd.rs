use std::process::Command;
use std::io::{BufRead, BufReader, Write};
use std::fs::{File, OpenOptions};
use std::path::Path;
use chrono::{NaiveDateTime, DateTime, Utc, Local};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditEvent {
    #[serde(with = "chrono::serde::ts_seconds")]
    pub timestamp: DateTime<Utc>,
    pub user_id: String,
    pub process_id: String,
    pub process_name: String,
    pub action: String,
    pub file_path: String,
}

pub fn setup_auditd_rules(file_path: &str) -> Result<(), String> {
    // First, ensure auditd is running
    let status = Command::new("sudo")
        .args(&["systemctl", "is-active", "auditd"])
        .output()
        .map_err(|e| format!("Failed to check auditd status: {}", e))?;

    if !status.status.success() {
        // Try to start auditd
        let start = Command::new("sudo")
            .args(&["systemctl", "start", "auditd"])
            .output()
            .map_err(|e| format!("Failed to start auditd: {}", e))?;

        if !start.status.success() {
            return Err("Failed to start auditd service".to_string());
        }
    }

    // Remove all existing rules first
    let _ = Command::new("sudo")
        .args(&["auditctl", "-D"])
        .output();

    // Create formatted strings for path and dir
    let path_str = format!("path={}", file_path);
    let dir_str = format!("dir={}", file_path);

    // Add comprehensive rules to monitor all possible file operations
    let rules = [
        // Monitor all file operations (read, write, execute, attribute changes)
        vec!["-w", file_path, "-p", "rwxa", "-k", "file_operations"],
        // Monitor directory itself for any changes
        vec!["-w", file_path, "-p", "wa", "-k", "dir_changes"],
        // Monitor all file modifications with detailed information
        vec!["-a", "always,exit", "-F", &path_str, "-F", "perm=w", "-F", "auid>=1000", "-F", "auid!=-1", "-k", "file_modifications"],
        // Monitor file creation and deletion in the directory
        vec!["-a", "always,exit", "-F", &dir_str, "-F", "perm=w", "-k", "dir_modifications"],
        // Monitor file attribute changes
        vec!["-a", "always,exit", "-F", &path_str, "-F", "perm=a", "-k", "attr_changes"],
        // Monitor file reads
        vec!["-a", "always,exit", "-F", &path_str, "-F", "perm=r", "-k", "file_reads"],
        // Monitor all processes that access the file
        vec!["-a", "always,exit", "-F", &path_str, "-F", "auid>=1000", "-F", "auid!=-1", "-k", "file_access"],
        // Monitor file moves (using write permission since moves involve write operations)
        vec!["-a", "always,exit", "-F", &dir_str, "-F", "perm=w", "-k", "file_moves"],
        // Monitor specific editor processes
        vec!["-a", "always,exit", "-F", &path_str, "-F", "exe=/usr/bin/vim", "-k", "vim_editor"],
        vec!["-a", "always,exit", "-F", &path_str, "-F", "exe=/bin/vim", "-k", "vim_editor"],
        vec!["-a", "always,exit", "-F", &path_str, "-F", "exe=/usr/local/bin/vim", "-k", "vim_editor"],
        vec!["-a", "always,exit", "-F", &path_str, "-F", "exe=/usr/bin/nano", "-k", "nano_editor"],
        vec!["-a", "always,exit", "-F", &path_str, "-F", "exe=/usr/bin/gedit", "-k", "gedit_editor"],
    ];

    for rule in rules.iter() {
        let output = Command::new("sudo")
            .args(&["auditctl"])
            .args(rule)
            .output()
            .map_err(|e| format!("Failed to add audit rule: {}", e))?;

        if !output.status.success() {
            return Err(format!(
                "Failed to add audit rule: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
    }

    // Verify the rules were added
    let verify = Command::new("sudo")
        .args(&["auditctl", "-l"])
        .output()
        .map_err(|e| format!("Failed to verify audit rules: {}", e))?;

    if !verify.status.success() {
        return Err("Failed to verify audit rules".to_string());
    }

    println!("✅ Comprehensive monitoring rules set up for: {}", file_path);
    println!("📝 Now monitoring:");
    println!("   - All file operations (read, write, execute, attributes)");
    println!("   - Directory changes");
    println!("   - File modifications by any program");
    println!("   - File creation and deletion");
    println!("   - File reads");
    println!("   - File attribute changes");
    println!("   - All file access attempts");
    println!("   - File moves and renames");
    println!("   - Specific editor processes (vim, nano, gedit)");
    Ok(())
}

pub fn parse_audit_log<P: AsRef<Path>>(log_file: P) -> Result<Vec<AuditEvent>, String> {
    let file = File::open(log_file).map_err(|e| format!("Failed to open audit log: {}", e))?;
    let reader = BufReader::new(file);
    let mut events = Vec::new();

    for line in reader.lines() {
        let line = line.map_err(|e| format!("Failed to read line: {}", e))?;
        
        if let Some(event) = parse_audit_line(&line) {
            events.push(event);
        }
    }

    Ok(events)
}

fn parse_audit_line(line: &str) -> Option<AuditEvent> {
    let mut timestamp = None;
    let mut user_id = None;
    let mut process_id = None;
    let mut process_name = None;
    let mut action = None;
    let mut file_path = None;

    for field in line.split_whitespace() {
        if let Some((key, value)) = field.split_once('=') {
            match key {
                "time" => {
                    if let Ok(seconds) = value.parse::<i64>() {
                        timestamp = Some(DateTime::<Utc>::from_utc(
                            NaiveDateTime::from_timestamp_opt(seconds, 0).unwrap_or_default(),
                            Utc,
                        ));
                    }
                }
                "uid" => user_id = Some(value.to_string()),
                "pid" => process_id = Some(value.to_string()),
                "comm" => process_name = Some(value.to_string()),
                "type" => action = Some(value.to_string()),
                "name" => file_path = Some(value.to_string()),
                "exe" => process_name = Some(value.to_string()), // Get the full executable path
                _ => {}
            }
        }
    }

    if let (Some(timestamp), Some(user_id), Some(process_id), Some(process_name), Some(action), Some(file_path)) = 
        (timestamp, user_id, process_id, process_name, action, file_path) {
        Some(AuditEvent {
            timestamp,
            user_id,
            process_id,
            process_name,
            action,
            file_path,
        })
    } else {
        None
    }
}

pub fn get_file_audit_info(file_path: &str) -> Result<Vec<AuditEvent>, String> {
    // Query audit logs for the specific file with more detailed information
    let output = Command::new("sudo")
        .args(&["ausearch", "-f", file_path, "-i"])  // -i for interpreting numeric values
        .output()
        .map_err(|e| format!("Failed to execute ausearch: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("no matches") {
            return Ok(Vec::new());
        }
        return Err(format!("Failed to query audit logs: {}", stderr));
    }

    let logs = String::from_utf8_lossy(&output.stdout);
    let mut events = Vec::new();

    for line in logs.lines() {
        if let Some(event) = parse_audit_line(line) {
            events.push(event);
        }
    }

    Ok(events)
}

pub fn write_audit_logs_to_file(file_path: &str, audit_log_file: &str) -> Result<(), String> {
    // Clean up old log files
    let log_dir = Path::new(audit_log_file).parent().unwrap_or(Path::new("."));
    if let Ok(entries) = std::fs::read_dir(log_dir) {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if name.starts_with("audit_logs_") && name.ends_with(".txt") {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
    }

    // Query audit logs for the specific file with more detailed information
    let output = Command::new("sudo")
        .args(&["ausearch", "-f", file_path, "-i"])  // -i for interpreting numeric values
        .output()
        .map_err(|e| format!("Failed to execute ausearch: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "Failed to query audit logs: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let logs = String::from_utf8_lossy(&output.stdout);
    
    // Open file in append mode
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(audit_log_file)
        .map_err(|e| format!("Failed to open audit log file: {}", e))?;
    
    // Write a separator and timestamp for this batch of logs
    let now = Local::now();
    writeln!(file, "\n=== Audit Logs for {} - {} ===", file_path, now.format("%Y-%m-%d %H:%M:%S"))
        .map_err(|e| format!("Failed to write timestamp: {}", e))?;
    
    // Parse and format each log entry
    let mut current_event = String::new();
    for line in logs.lines() {
        if line.starts_with("----") {
            // Process the completed event
            if !current_event.is_empty() {
                if let Some(formatted_event) = format_audit_event(&current_event) {
                    writeln!(file, "{}", formatted_event)
                        .map_err(|e| format!("Failed to write formatted event: {}", e))?;
                }
                current_event.clear();
            }
        } else {
            current_event.push_str(line);
            current_event.push('\n');
        }
    }
    
    // Process the last event if any
    if !current_event.is_empty() {
        if let Some(formatted_event) = format_audit_event(&current_event) {
            writeln!(file, "{}", formatted_event)
                .map_err(|e| format!("Failed to write formatted event: {}", e))?;
        }
    }

    Ok(())
}

fn format_audit_event(event: &str) -> Option<String> {
    let mut timestamp = None;
    let mut user = None;
    let mut process = None;
    let mut file = None;
    let mut working_dir = None;

    for line in event.lines() {
        if line.starts_with("type=SYSCALL") {
            // Parse timestamp from msg=audit field
            if let Some(msg) = line.split("msg=audit(").nth(1) {
                if let Some(time_str) = msg.split(')').next() {
                    // Format: MM/DD/YYYY HH:MM:SS.mmm:nnn
                    if let Some((date_time, _)) = time_str.split_once('.') {
                        timestamp = Some(date_time.to_string());
                    }
                }
            }
            // Parse user ID
            if let Some(uid) = line.split("uid=").nth(1) {
                if let Some(uid_str) = uid.split_whitespace().next() {
                    user = Some(uid_str.to_string());
                }
            }
            // Parse process name
            if let Some(comm) = line.split("comm=").nth(1) {
                if let Some(comm_str) = comm.split_whitespace().next() {
                    process = Some(comm_str.trim_matches('"').to_string());
                }
            }
        } else if line.starts_with("type=PATH") {
            // Parse file path
            if let Some(name) = line.split("name=").nth(1) {
                if let Some(name_str) = name.split_whitespace().next() {
                    file = Some(name_str.trim_matches('"').to_string());
                }
            }
        } else if line.starts_with("type=CWD") {
            // Parse working directory
            if let Some(cwd) = line.split("cwd=").nth(1) {
                if let Some(cwd_str) = cwd.split_whitespace().next() {
                    working_dir = Some(cwd_str.trim_matches('"').to_string());
                }
            }
        }
    }

    // Skip events from vendysWatch
    if let Some(proc) = &process {
        if proc.to_lowercase().contains("vendyswatch") {
            return None;
        }
    }

    if let (Some(process), Some(file)) = (process, file) {
        let timestamp = timestamp.unwrap_or_else(|| "Unknown time".to_string());
        let user = user.unwrap_or_else(|| "Unknown user".to_string());
        let working_dir = working_dir.unwrap_or_else(|| "Unknown directory".to_string());
        println!(
            "Time: {}\nProcess: {}\nUser: {}\nFile: {}\nWorking Directory: {}\n{}",
            timestamp,
            process,
            user,
            file,
            working_dir,
            "-".repeat(80)
        );
        Some(format!(
            "Time: {}\nProcess: {}\nUser: {}\nFile: {}\nWorking Directory: {}\n{}",
            timestamp,
            process,
            user,
            file,
            working_dir,
            "-".repeat(80)
        ))
    } else {
        None
    }
} 