pub mod analyzer;
pub mod baseline;
pub mod cost_model;
pub mod debug_info;
pub mod loader;
pub mod multi_program;
pub mod patterns;
pub mod report;

/// Format a number with comma-separated thousands (e.g. 1400000 -> "1,400,000").
pub fn format_number(n: u64) -> String {
    let s = n.to_string();
    let bytes = s.as_bytes();
    let len = bytes.len();
    let mut result = String::with_capacity(len + len / 3);

    for (i, &b) in bytes.iter().enumerate() {
        if i > 0 && (len - i).is_multiple_of(3) {
            result.push(',');
        }
        result.push(b as char);
    }

    result
}
