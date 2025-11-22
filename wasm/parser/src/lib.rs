// DKIM Email Parser - WebAssembly Module
//
// High-performance email header and body parsing.
// Compiled to WebAssembly for faster parsing of large emails.
//
// Copyright (c) 2025 DKIM Verifier Contributors
// Licensed under MIT License

use wasm_bindgen::prelude::*;
use regex::Regex;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};

/// Parsed email structure
#[derive(Serialize, Deserialize)]
pub struct ParsedEmail {
    pub headers: HashMap<String, Vec<String>>,
    pub body: String,
}

/// Initialize the WASM module
#[wasm_bindgen(start)]
pub fn init() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();

    web_sys::console::log_1(&"DKIM Parser WASM module initialized".into());
}

/// Parse email message into headers and body
///
/// # Arguments
/// * `raw_message` - Raw email message (RFC 5322 format)
///
/// # Returns
/// JSON string containing parsed headers and body
#[wasm_bindgen]
pub fn parse_email(raw_message: &str) -> Result<JsValue, JsValue> {
    let parsed = parse_email_internal(raw_message)
        .map_err(|e| JsValue::from_str(&format!("Parse error: {}", e)))?;

    serde_wasm_bindgen::to_value(&parsed)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
}

/// Internal email parsing function
fn parse_email_internal(raw_message: &str) -> Result<ParsedEmail, String> {
    // Normalize line endings to CRLF
    let normalized = raw_message
        .replace("\r\n", "\n")
        .replace('\r', "\n")
        .replace('\n', "\r\n");

    // Find header/body separator (blank line)
    let separator = "\r\n\r\n";
    let parts: Vec<&str> = normalized.splitn(2, separator).collect();

    let (header_section, body) = match parts.as_slice() {
        [headers, body] => (headers, body.to_string()),
        [headers] => {
            // No body, just headers
            if !headers.ends_with("\r\n") {
                return Err("Headers don't end with CRLF".to_string());
            }
            (headers, String::new())
        }
        _ => return Err("Invalid email format".to_string()),
    };

    // Parse headers
    let headers = parse_headers(header_section)?;

    Ok(ParsedEmail { headers, body })
}

/// Parse email headers
fn parse_headers(header_section: &str) -> Result<HashMap<String, Vec<String>>, String> {
    let mut headers: HashMap<String, Vec<String>> = HashMap::new();

    // Split headers (accounting for folding - continuation lines start with whitespace)
    let header_regex = Regex::new(r"\r\n(?=[^\s])")
        .map_err(|e| format!("Regex error: {}", e))?;

    let header_lines: Vec<&str> = header_regex.split(header_section).collect();

    for header_line in header_lines {
        if header_line.trim().is_empty() {
            continue;
        }

        // Parse header name and value
        let colon_pos = header_line.find(':')
            .ok_or_else(|| format!("Invalid header line: {}", header_line))?;

        let name = header_line[..colon_pos].trim().to_lowercase();
        let value = format!("{}\r\n", header_line); // Include full header with CRLF

        headers.entry(name).or_insert_with(Vec::new).push(value);
    }

    Ok(headers)
}

/// Extract email address from From/Reply-To header
///
/// # Arguments
/// * `header_value` - Header value (e.g., "John Doe <john@example.com>")
///
/// # Returns
/// Email address (e.g., "john@example.com")
#[wasm_bindgen]
pub fn extract_email_address(header_value: &str) -> Result<String, JsValue> {
    // Try angle brackets first: "Name <email@example.com>"
    let angle_regex = Regex::new(r"<([^>]+)>")
        .map_err(|e| JsValue::from_str(&format!("Regex error: {}", e)))?;

    if let Some(captures) = angle_regex.captures(header_value) {
        if let Some(email) = captures.get(1) {
            return Ok(email.as_str().to_string());
        }
    }

    // Try plain email: "email@example.com"
    let email_regex = Regex::new(r"\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b")
        .map_err(|e| JsValue::from_str(&format!("Regex error: {}", e)))?;

    if let Some(captures) = email_regex.captures(header_value) {
        if let Some(email) = captures.get(1) {
            return Ok(email.as_str().to_string());
        }
    }

    Err(JsValue::from_str("No email address found"))
}

/// Fast token extraction for Bayesian filter
///
/// # Arguments
/// * `text` - Text to tokenize (subject + body)
///
/// # Returns
/// Array of unique tokens (lowercase, 3-50 chars)
#[wasm_bindgen]
pub fn extract_tokens(text: &str) -> Vec<String> {
    let text_lower = text.to_lowercase();
    let word_regex = Regex::new(r"\b[a-z0-9]{3,50}\b").unwrap();

    let mut tokens: Vec<String> = word_regex
        .find_iter(&text_lower)
        .map(|m| m.as_str().to_string())
        .collect();

    // Remove duplicates while preserving order
    tokens.sort();
    tokens.dedup();

    tokens
}

/// Canonicalize email body for DKIM (simple canonicalization)
///
/// # Arguments
/// * `body` - Raw email body
///
/// # Returns
/// Canonicalized body (CRLF line endings, trailing CRLF)
#[wasm_bindgen]
pub fn canonicalize_body_simple(body: &str) -> String {
    // Convert to CRLF
    let mut canonical = body
        .replace("\r\n", "\n")
        .replace('\r', "\n")
        .replace('\n', "\r\n");

    // Remove trailing whitespace from each line
    let lines: Vec<String> = canonical
        .lines()
        .map(|line| line.trim_end().to_string())
        .collect();

    canonical = lines.join("\r\n");

    // Ensure ends with CRLF
    if !canonical.ends_with("\r\n") {
        canonical.push_str("\r\n");
    }

    canonical
}

/// Count Received headers (email hops)
///
/// # Arguments
/// * `headers_json` - JSON string of parsed headers
///
/// # Returns
/// Number of Received headers
#[wasm_bindgen]
pub fn count_received_headers(headers_json: &str) -> Result<usize, JsValue> {
    let headers: HashMap<String, Vec<String>> = serde_json::from_str(headers_json)
        .map_err(|e| JsValue::from_str(&format!("JSON parse error: {}", e)))?;

    Ok(headers.get("received").map(|v| v.len()).unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_email() {
        let email = "From: test@example.com\r\nSubject: Test\r\n\r\nBody";
        let result = parse_email_internal(email).unwrap();
        assert!(result.headers.contains_key("from"));
        assert!(result.headers.contains_key("subject"));
        assert_eq!(result.body, "Body");
    }

    #[test]
    fn test_extract_email() {
        let header = "John Doe <john@example.com>";
        let email = extract_email_address(header).unwrap();
        assert_eq!(email, "john@example.com");
    }

    #[test]
    fn test_tokenize() {
        let text = "Hello world! This is a test.";
        let tokens = extract_tokens(text);
        assert!(tokens.contains(&"hello".to_string()));
        assert!(tokens.contains(&"world".to_string()));
        assert!(tokens.contains(&"test".to_string()));
    }
}
