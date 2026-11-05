use crate::config::Config;
use crate::scanners;
use crate::utils;
use serde_json::Value;
use std::time::SystemTime;
#[allow(clippy::too_many_arguments)]
pub fn run(
    config: &Config,
    issues: &bool,
    json: &bool,
    summary: &bool,
    fix_explanation: &bool,
    fix_diff: &bool,
    include_reachability: &bool,
    id: &String,
) {
    fn print_section(title: &str, value: impl ToString) {
        println!("{:<15}: {}", title, value.to_string());
        println!("-------------------------");
    }
    println!();
    if *issues {
        let show_everything = !*summary && !*fix_explanation && !*fix_diff;
        let issue_details = match utils::api::get_issue(
            &config.get_url(),
            id,
            *include_reachability,
        ) {
            Ok(issue) => issue,
            Err(e) => {
                log::error!(
                    "Failed to fetch issue details for issue ID {} with error:\n{}",
                    id,
                    e
                );
                if e.to_string().contains("404") {
                    println!("If you're trying to inspect a scan make sure to remove the --issue argument");
                }
                std::process::exit(1);
            }
        };
        if *json {
            // `Issue` does not serialize these maps. List and scan-report JSON
            // re-emit that struct, and the blocking-rules list path uses a
            // second struct that never had the fields.
            let mut body = serde_json::to_value(&issue_details).unwrap();
            if let Some(issue) = body
                .get_mut("issue")
                .and_then(|value| value.as_object_mut())
            {
                if let Some(scanner_metadata) = &issue_details.issue.scanner_metadata {
                    issue.insert(
                        "scanner_metadata".to_string(),
                        serde_json::Value::Object(scanner_metadata.clone()),
                    );
                }
                if let Some(metadata) = &issue_details.issue.metadata {
                    issue.insert(
                        "metadata".to_string(),
                        serde_json::Value::Object(metadata.clone()),
                    );
                }
            }
            println!("{}", serde_json::to_string_pretty(&body).unwrap());
            return;
        }
        if *summary || show_everything {
            print_section("Issue ID", &issue_details.issue.id);
            print_section("Urgency", &issue_details.issue.urgency);
            print_section("Category", &issue_details.issue.classification.name);
            print_section("File Path", &issue_details.issue.location.file.path);
            print_section(
                "Line Num",
                issue_details.issue.location.line_number.to_string(),
            );
            print_section(
                "Status",
                utils::generic::get_status(&issue_details.issue.status),
            );
            let scanner_metadata = issue_details.issue.combined_scanner_metadata();
            if !scanner_metadata.is_empty() {
                println!("Scanner Metadata:");
                for (key, value) in &scanner_metadata {
                    println!("  {:<13}: {}", key, value);
                }
                println!("-------------------------");
            }
            if *include_reachability {
                for line in format_reachability_lines(issue_details.issue.reachability.as_ref()) {
                    println!("{}", line);
                }
                println!("-------------------------");
            }
        }
        if let Some(ref details) = issue_details.issue.details {
            if let Some(ref explanation) = details.explanation {
                if *summary || show_everything {
                    println!(
                        "Explanation:\n\n{}\n-------------------------",
                        utils::terminal::format_code(explanation)
                    )
                }
            }
        }
        if let Some(auto_fix_suggestion) = issue_details.issue.auto_fix_suggestion {
            if *fix_explanation || show_everything {
                if show_everything {
                    utils::terminal::prompt_to_continue_or_exit(Some("\nTo continue to viewing the fix explanation please press enter, otherwise Ctrl+C to exit.\n"));
                }
                if let Some(ref patch) = &auto_fix_suggestion.patch {
                    utils::terminal::print_with_pagination(&format!(
                        "Fix Explanation:\n\n{}\n-------------------------",
                        utils::terminal::format_code(&patch.explanation)
                    ));
                }
            }
            if *fix_diff || show_everything {
                if show_everything {
                    utils::terminal::prompt_to_continue_or_exit(Some("\nTo continue to viewing the diff of the fix please press enter, otherwise Ctrl+C to exit.\n"));
                }
                if let Some(ref patch) = &auto_fix_suggestion.patch {
                    utils::terminal::print_with_pagination(&utils::terminal::format_diff(
                        &patch.diff,
                    ));
                }
            }
        }
    } else {
        let scan_details = match utils::api::get_scan(&config.get_url(), id, None) {
            Ok(details) => details,
            Err(e) => {
                log::error!("Failed to fetch scan details for scan ID {}: {}", id, e);
                if e.to_string().contains("404") {
                    println!(
                        "If you're trying to inspect an issues make sure to pass --issue argument"
                    );
                }
                std::process::exit(1);
            }
        };
        if *json {
            println!("{}", serde_json::to_string_pretty(&scan_details).unwrap());
            return;
        }
        print_section("Scan ID", &scan_details.id);
        print_section("Repository", scan_details.repo.as_deref().unwrap_or("N/A"));
        print_section("Branch", scan_details.branch.as_deref().unwrap_or("N/A"));

        print_section("Status", scan_details.status);
        print_section("Project", &scan_details.project);
        print_section("Engine", &scan_details.engine);
        let created_at = chrono::DateTime::<chrono::Utc>::from(SystemTime::now())
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        print_section("Created At", &created_at);
        if let Ok(counts) = scanners::blast::fetch_and_group_scan_issues(
            &config.get_url(),
            &scan_details.project,
            &scan_details.id,
        ) {
            let total_issues = counts.values().sum::<usize>();
            let order = vec!["CR", "HI", "ME", "LO"];
            for urgency in order {
                if let Some(count) = counts.get(urgency) {
                    print_section(&format!("{} Issues", urgency), count.to_string());
                }
            }
            print_section("Total Issues", total_issues);
        };
    }
}

/// Text rendering of an issue detail's reachability: whether it is reachable,
/// then one line per endpoint (`METHOD path (file:line)`). Fields that are
/// missing or of an unexpected type are shown as `N/A` or left out.
fn format_reachability_lines(reachability: Option<&Value>) -> Vec<String> {
    let is_reachable = reachability
        .and_then(|r| r.get("is_reachable"))
        .and_then(Value::as_bool)
        .map_or_else(|| "N/A".to_string(), |b| b.to_string());
    let mut lines = vec![format!("{:<15}: {}", "Reachable", is_reachable)];
    let endpoints = reachability
        .and_then(|r| r.get("endpoints"))
        .and_then(Value::as_array);
    match endpoints {
        Some(endpoints) if !endpoints.is_empty() => {
            lines.push(format!("Endpoints ({}):", endpoints.len()));
            for endpoint in endpoints {
                let field = |key: &str| endpoint.get(key).and_then(Value::as_str);
                let mut line = format!(
                    "  {} {}",
                    field("method").unwrap_or("N/A"),
                    field("path").unwrap_or("N/A")
                );
                if let Some(file) = field("file_path") {
                    match endpoint.get("line_number").and_then(Value::as_u64) {
                        Some(n) => line.push_str(&format!(" ({}:{})", file, n)),
                        None => line.push_str(&format!(" ({})", file)),
                    }
                }
                lines.push(line);
            }
        }
        Some(_) => lines.push(format!("{:<15}: {}", "Endpoints", 0)),
        None => lines.push(format!("{:<15}: {}", "Endpoints", "N/A")),
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn reachability_lines_when_absent() {
        assert_eq!(
            format_reachability_lines(None),
            vec![
                "Reachable      : N/A".to_string(),
                "Endpoints      : N/A".to_string()
            ]
        );
    }

    #[test]
    fn reachability_lines_list_each_endpoint() {
        let r = json!({
            "is_reachable": true,
            "endpoints": [
                {"path": "/login", "method": "POST", "file_path": "app/views.py",
                 "line_number": 42, "pathways": []},
                {"path": "/health", "method": "GET"}
            ]
        });
        assert_eq!(
            format_reachability_lines(Some(&r)),
            vec![
                "Reachable      : true".to_string(),
                "Endpoints (2):".to_string(),
                "  POST /login (app/views.py:42)".to_string(),
                "  GET /health".to_string(),
            ]
        );
    }

    #[test]
    fn reachability_lines_with_no_endpoints() {
        let r = json!({"is_reachable": false, "endpoints": []});
        assert_eq!(
            format_reachability_lines(Some(&r)),
            vec![
                "Reachable      : false".to_string(),
                "Endpoints      : 0".to_string()
            ]
        );
    }
}
