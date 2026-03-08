use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileType {
    Jpeg,
    Png,
    Gif,
    Bmp,
    Pdf,
    Zip,
    Gzip,
    Rar,
    Exe,
    Dll,
    Elf,
    Mach,
    Jar,
    Apk,
    Svg,
    Xml,
    Html,
    Js,
    Php,
    Py,
    Sh,
    Bat,
    Doc,
    Docx,
    Xls,
    Xlsx,
    Csv,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileAnomaly {
    pub kind: String,
    pub description: String,
    pub score: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileAnalysisResult {
    pub detected_type: FileType,
    pub claimed_type: FileType,
    pub type_mismatch: bool,
    pub anomalies: Vec<FileAnomaly>,
    pub risk_score: u8,
}

impl FileAnomaly {
    fn new(kind: &str, description: impl Into<String>, score: u8) -> Self {
        Self {
            kind: kind.to_string(),
            description: description.into(),
            score,
        }
    }
}

pub fn detect_file_type(content: &[u8]) -> FileType {
    if content.is_empty() {
        return FileType::Unknown;
    }

    if is_jpeg(content) {
        return FileType::Jpeg;
    }
    if is_png(content) {
        return FileType::Png;
    }
    if is_gif(content) {
        return FileType::Gif;
    }
    if is_bmp(content) {
        return FileType::Bmp;
    }
    if is_pdf(content) {
        return FileType::Pdf;
    }

    if is_pe(content) {
        return if is_pe_dll(content) {
            FileType::Dll
        } else {
            FileType::Exe
        };
    }

    if is_elf(content) {
        return FileType::Elf;
    }

    if is_mach(content) {
        return FileType::Mach;
    }

    if is_gzip(content) {
        return FileType::Gzip;
    }

    if is_rar(content) {
        return FileType::Rar;
    }

    if is_zip_like(content) {
        let lower = to_lower_ascii(content);
        if lower.contains("androidmanifest.xml") {
            return FileType::Apk;
        }
        if lower.contains("meta-inf/manifest.mf") {
            return FileType::Jar;
        }
        if lower.contains("[content_types].xml") && lower.contains("word/") {
            return FileType::Docx;
        }
        if lower.contains("[content_types].xml") && lower.contains("xl/") {
            return FileType::Xlsx;
        }
        return FileType::Zip;
    }

    if is_ole(content) {
        let lower = to_lower_ascii(content);
        if lower.contains("workbook") {
            return FileType::Xls;
        }
        return FileType::Doc;
    }

    let text = to_lower_ascii(content);
    let text_trim = text.trim_start();

    if text_trim.starts_with("<svg") || text.contains("<svg") {
        return FileType::Svg;
    }
    if text_trim.starts_with("<?xml") {
        return FileType::Xml;
    }
    if text_trim.starts_with("<!doctype html") || text.contains("<html") {
        return FileType::Html;
    }
    if text.contains("<?php") || text_trim.starts_with("#!/usr/bin/php") {
        return FileType::Php;
    }
    if text_trim.starts_with("#!/usr/bin/python") || text_trim.starts_with("#!/bin/python") {
        return FileType::Py;
    }
    if text_trim.starts_with("#!/bin/sh") || text_trim.starts_with("#!/bin/bash") {
        return FileType::Sh;
    }
    if text_trim.starts_with("@echo off") || text.contains("\r\nset ") {
        return FileType::Bat;
    }
    if looks_like_javascript(&text) {
        return FileType::Js;
    }
    if looks_like_csv(&text) {
        return FileType::Csv;
    }

    FileType::Unknown
}

pub fn validate_extension_matches(filename: &str, content: &[u8]) -> bool {
    let claimed = file_type_from_filename(filename);
    let detected = detect_file_type(content);

    if claimed == FileType::Unknown || detected == FileType::Unknown {
        return true;
    }

    are_compatible_types(claimed, detected)
}

pub fn detect_embedded_scripts(content: &[u8], file_type: FileType) -> Vec<FileAnomaly> {
    let lower = to_lower_ascii(content);
    let mut anomalies = Vec::new();

    let has_script = lower.contains("<script") || lower.contains("javascript:");
    let has_php = lower.contains("<?php") || lower.contains("<?=");

    match file_type {
        FileType::Jpeg | FileType::Png | FileType::Gif | FileType::Bmp => {
            if has_script || has_php {
                anomalies.push(FileAnomaly::new(
                    "embedded_script",
                    "image payload contains script-like content",
                    35,
                ));
            }
            if lower.contains("exif") && (lower.contains("eval(") || lower.contains("<script")) {
                anomalies.push(FileAnomaly::new(
                    "embedded_script",
                    "possible script hidden in EXIF metadata",
                    40,
                ));
            }
        }
        FileType::Svg => {
            if has_script || lower.contains("onload=") || lower.contains("onerror=") {
                anomalies.push(FileAnomaly::new(
                    "active_content",
                    "svg contains executable script/event handlers",
                    45,
                ));
            }
        }
        FileType::Html | FileType::Xml => {
            if has_script || lower.contains("onload=") || lower.contains("onerror=") {
                anomalies.push(FileAnomaly::new(
                    "active_content",
                    "markup contains executable script constructs",
                    30,
                ));
            }
        }
        FileType::Pdf => {
            if lower.contains("/javascript") || lower.contains("/js") || lower.contains("/openaction") {
                anomalies.push(FileAnomaly::new(
                    "active_content",
                    "pdf contains JavaScript or automatic actions",
                    45,
                ));
            }
        }
        FileType::Doc | FileType::Docx | FileType::Xls | FileType::Xlsx => {
            if lower.contains("vbaproject.bin")
                || lower.contains("word/vba")
                || lower.contains("xl/vba")
                || lower.contains("macro")
                || lower.contains("autoopen")
            {
                anomalies.push(FileAnomaly::new(
                    "macro",
                    "office document contains macro indicators",
                    45,
                ));
            }
        }
        _ => {
            if has_php {
                anomalies.push(FileAnomaly::new(
                    "embedded_script",
                    "file contains inline PHP payload markers",
                    35,
                ));
            }
        }
    }

    anomalies
}

pub fn detect_polyglot_file(content: &[u8]) -> Vec<FileAnomaly> {
    let mut candidates = HashSet::new();

    if is_jpeg(content) {
        candidates.insert(FileType::Jpeg);
    }
    if is_png(content) {
        candidates.insert(FileType::Png);
    }
    if is_gif(content) {
        candidates.insert(FileType::Gif);
    }
    if is_pdf(content) {
        candidates.insert(FileType::Pdf);
    }
    if is_zip_like(content) || contains_zip_signature(content) {
        candidates.insert(FileType::Zip);
    }

    let lower = to_lower_ascii(content);
    if lower.contains("<html") || lower.contains("<!doctype html") {
        candidates.insert(FileType::Html);
    }
    if lower.contains("<svg") {
        candidates.insert(FileType::Svg);
    }
    if lower.contains("<?php") {
        candidates.insert(FileType::Php);
    }
    if lower.contains("#!/bin/sh") {
        candidates.insert(FileType::Sh);
    }

    let mut anomalies = Vec::new();
    if is_gif(content) && contains_zip_signature_after_prefix(content) {
        anomalies.push(FileAnomaly::new(
            "polyglot",
            "GIFAR-style polyglot detected (GIF + ZIP/JAR)",
            60,
        ));
    }
    if is_png(content) && (lower.contains("<html") || lower.contains("<script")) {
        anomalies.push(FileAnomaly::new(
            "polyglot",
            "PNG+HTML/JS polyglot-style payload detected",
            60,
        ));
    }
    if is_pdf(content) && (lower.contains("<script") || lower.contains("/javascript") || lower.contains("<html")) {
        anomalies.push(FileAnomaly::new(
            "polyglot",
            "PDF active-content polyglot indicators detected",
            60,
        ));
    }

    if candidates.len() < 2 {
        return anomalies;
    }

    let mut names: Vec<&'static str> = candidates.iter().map(|t| file_type_name(*t)).collect();
    names.sort_unstable();

    if anomalies.is_empty() {
        anomalies.push(FileAnomaly::new(
            "polyglot",
            format!("content matches multiple file formats: {}", names.join(", ")),
            50,
        ));
    }

    anomalies
}

pub fn detect_content_type_mismatch(content: &[u8], content_type_header: Option<&str>) -> Vec<FileAnomaly> {
    let mut anomalies = Vec::new();
    let Some(content_type) = content_type_header else {
        return anomalies;
    };

    let detected = detect_file_type(content);
    let lower = to_lower_ascii(content);
    let normalized = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();

    if let Some(claimed) = file_type_from_content_type(&normalized) {
        if detected != FileType::Unknown && !are_compatible_types(claimed, detected) {
            anomalies.push(FileAnomaly::new(
                "content_type_mismatch",
                format!(
                    "content-type {} does not match detected {}",
                    normalized,
                    file_type_name(detected)
                ),
                45,
            ));
        }
    }

    if normalized.starts_with("image/")
        && (lower.contains("<html")
            || lower.contains("<script")
            || lower.contains("javascript:")
            || lower.contains("<?php"))
    {
        anomalies.push(FileAnomaly::new(
            "content_type_mismatch",
            "image content-type carries HTML/JS/PHP payload markers",
            55,
        ));
    }

    anomalies
}

pub fn detect_magic_byte_spoofing(content: &[u8]) -> Vec<FileAnomaly> {
    let mut anomalies = Vec::new();
    let lower = to_lower_ascii(content);
    let has_script_payload = lower.contains("<script")
        || lower.contains("javascript:")
        || lower.contains("<?php")
        || lower.contains("<html");

    if !has_script_payload {
        return anomalies;
    }

    if (is_gif(content) || is_png(content) || is_jpeg(content))
        && has_script_payload
    {
        anomalies.push(FileAnomaly::new(
            "magic_byte_spoofing",
            "binary file magic bytes are followed by script/markup payload indicators",
            55,
        ));
    }

    anomalies
}

pub fn detect_svg_script_payload(content: &[u8]) -> Vec<FileAnomaly> {
    let mut anomalies = Vec::new();
    let lower = to_lower_ascii(content);
    if !lower.contains("<svg") {
        return anomalies;
    }

    if lower.contains("<script")
        || lower.contains("javascript:")
        || lower.contains("onload=")
        || lower.contains("onerror=")
        || lower.contains("onclick=")
        || lower.contains("onbegin=")
        || lower.contains("xlink:href=\"javascript:")
        || lower.contains("href=\"javascript:")
    {
        anomalies.push(FileAnomaly::new(
            "svg_script",
            "svg contains executable script/event-handler payload",
            50,
        ));
    }

    anomalies
}

pub fn detect_xml_xslt_injection(content: &[u8]) -> Vec<FileAnomaly> {
    let mut anomalies = Vec::new();
    let lower = to_lower_ascii(content);
    let is_markup = lower.contains("<?xml") || lower.contains("<!doctype") || lower.contains("<xsl:");
    if !is_markup {
        return anomalies;
    }

    if lower.contains("<!doctype") && lower.contains("<!entity") {
        anomalies.push(FileAnomaly::new(
            "xml_entity_expansion",
            "xml payload includes doctype+entity expansion constructs",
            55,
        ));
    }

    if (lower.contains("<xsl:stylesheet") || lower.contains("<xsl:transform"))
        && (lower.contains("document(")
            || lower.contains("unparsed-text(")
            || lower.contains("xsl:import")
            || lower.contains("xsl:include")
            || lower.contains("msxsl:script"))
    {
        anomalies.push(FileAnomaly::new(
            "xslt_execution",
            "xslt payload includes code execution/data-fetch primitives",
            55,
        ));
    }

    anomalies
}

pub fn detect_archive_slip(content: &[u8]) -> Vec<FileAnomaly> {
    let mut anomalies = Vec::new();
    if is_zip_like(content) {
        for name in parse_zip_entry_names(content) {
            if looks_like_archive_traversal_path(&name) {
                anomalies.push(FileAnomaly::new(
                    "archive_slip",
                    format!("archive entry path traversal detected: {}", name),
                    55,
                ));
                break;
            }
        }
    }

    let lower = to_lower_ascii(content);
    if lower.contains("ustar")
        && (lower.contains("../")
            || lower.contains("..\\")
            || lower.contains("/etc/passwd")
            || lower.contains("c:\\"))
    {
        anomalies.push(FileAnomaly::new(
            "archive_slip",
            "tar archive contains traversal/absolute path indicators",
            55,
        ));
    }

    anomalies
}

pub fn detect_embedded_macros_and_hta(content: &[u8], file_type: FileType) -> Vec<FileAnomaly> {
    let mut anomalies = Vec::new();
    let lower = to_lower_ascii(content);
    let is_office = matches!(file_type, FileType::Doc | FileType::Docx | FileType::Xls | FileType::Xlsx);

    if is_office
        && (lower.contains("vbaproject.bin")
            || lower.contains("word/vba")
            || lower.contains("xl/vba")
            || lower.contains("autoopen")
            || lower.contains("vba"))
    {
        anomalies.push(FileAnomaly::new(
            "macro",
            "office payload contains VBA macro indicators",
            50,
        ));
    }

    if lower.contains("<hta:application")
        || lower.contains("mshta")
        || lower.contains("vbscript:")
        || lower.contains("wscript.shell")
        || lower.contains("shell.application")
    {
        anomalies.push(FileAnomaly::new(
            "hta_payload",
            "payload contains HTA/VBScript execution markers",
            50,
        ));
    }

    anomalies
}

pub fn detect_mime_sniffing_attack(
    content: &[u8],
    content_type_header: Option<&str>,
    x_content_type_options: Option<&str>,
) -> Vec<FileAnomaly> {
    let mut anomalies = Vec::new();
    let lower = to_lower_ascii(content);
    let xcto = x_content_type_options.unwrap_or_default().to_ascii_lowercase();
    let nosniff_missing = !xcto.contains("nosniff");
    if !nosniff_missing {
        return anomalies;
    }

    let declared = content_type_header
        .unwrap_or_default()
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();

    let has_active_markup = lower.contains("<html")
        || lower.contains("<script")
        || lower.contains("<svg")
        || lower.contains("javascript:");
    let ambiguous_binary_text = (is_png(content) || is_gif(content) || is_jpeg(content) || is_pdf(content))
        && has_active_markup;
    let ambiguously_typed = declared.is_empty()
        || declared == "application/octet-stream"
        || declared == "text/plain";

    if ambiguous_binary_text || (ambiguously_typed && has_active_markup) {
        anomalies.push(FileAnomaly::new(
            "mime_sniffing",
            "nosniff is missing while payload has ambiguous executable content",
            45,
        ));
    }

    anomalies
}

pub fn detect_zip_bomb(content: &[u8]) -> Option<FileAnomaly> {
    if is_gzip(content) {
        if content.len() >= 4 {
            let isize = u32::from_le_bytes([
                content[content.len() - 4],
                content[content.len() - 3],
                content[content.len() - 2],
                content[content.len() - 1],
            ]) as u64;
            let compressed = content.len() as u64;
            if compressed > 0 {
                let ratio = isize as f64 / compressed as f64;
                if ratio > 100.0 || isize > 500 * 1024 * 1024 {
                    return Some(FileAnomaly::new(
                        "zip_bomb",
                        format!(
                            "gzip advertised uncompressed size is suspicious (ratio {:.1}x)",
                            ratio
                        ),
                        60,
                    ));
                }
            }
        }
        return None;
    }

    if !is_zip_like(content) {
        return None;
    }

    let stats = parse_zip_local_headers(content);

    if stats.entry_count > 4000 {
        return Some(FileAnomaly::new(
            "zip_bomb",
            "archive has an unusually high number of entries",
            60,
        ));
    }

    if stats.total_compressed > 0 {
        let ratio = stats.total_uncompressed as f64 / stats.total_compressed as f64;
        if ratio > 120.0 || stats.total_uncompressed > 800 * 1024 * 1024 {
            return Some(FileAnomaly::new(
                "zip_bomb",
                format!(
                    "archive compression ratio is suspicious (ratio {:.1}x)",
                    ratio
                ),
                60,
            ));
        }
    }

    if stats.nested_archive_entries > 20 {
        return Some(FileAnomaly::new(
            "zip_bomb",
            "archive contains excessive nested archives",
            55,
        ));
    }

    None
}

pub fn detect_path_traversal_filename(filename: &str) -> Option<FileAnomaly> {
    let lowered = filename.to_ascii_lowercase();
    let normalized = lowered.replace('\\', "/");

    if normalized.contains("../")
        || normalized.starts_with("../")
        || normalized.contains("..%2f")
        || normalized.contains("%2e%2e")
        || normalized.contains("..\\")
    {
        return Some(FileAnomaly::new(
            "path_traversal",
            "filename contains path traversal sequences",
            50,
        ));
    }

    if let Some(anomaly) = detect_null_byte_extension(filename) {
        return Some(anomaly);
    }

    if let Some(anomaly) = detect_double_extension(filename) {
        return Some(anomaly);
    }

    None
}

pub fn is_eicar_test(content: &[u8]) -> bool {
    const EICAR: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    if content.windows(EICAR.len()).any(|w| w == EICAR) {
        return true;
    }

    let lower = to_lower_ascii(content);
    lower.contains("eicar-standard-antivirus-test-file")
}

pub fn scan_file_content(filename: &str, content: &[u8]) -> FileAnalysisResult {
    let detected_type = detect_file_type(content);
    let claimed_type = file_type_from_filename(filename);
    let type_mismatch = !validate_extension_matches(filename, content);

    let mut anomalies = Vec::new();

    if type_mismatch {
        anomalies.push(FileAnomaly::new(
            "type_mismatch",
            format!(
                "file extension suggests {} but content appears to be {}",
                file_type_name(claimed_type),
                file_type_name(detected_type)
            ),
            30,
        ));
    }

    anomalies.extend(detect_embedded_scripts(content, detected_type));
    anomalies.extend(detect_polyglot_file(content));
    anomalies.extend(detect_magic_byte_spoofing(content));
    anomalies.extend(detect_svg_script_payload(content));
    anomalies.extend(detect_xml_xslt_injection(content));
    anomalies.extend(detect_archive_slip(content));
    anomalies.extend(detect_embedded_macros_and_hta(content, detected_type));

    if let Some(anomaly) = detect_zip_bomb(content) {
        anomalies.push(anomaly);
    }
    if let Some(anomaly) = detect_path_traversal_filename(filename) {
        anomalies.push(anomaly);
    }

    if let Some(anomaly) = detect_double_extension(filename) {
        anomalies.push(anomaly);
    }
    if let Some(anomaly) = detect_null_byte_extension(filename) {
        anomalies.push(anomaly);
    }

    if is_eicar_test(content) {
        anomalies.push(FileAnomaly::new(
            "malware_test_signature",
            "EICAR test signature detected",
            70,
        ));
    }

    dedupe_anomalies(&mut anomalies);

    let risk_sum: u16 = anomalies.iter().map(|a| a.score as u16).sum();
    let risk_score = risk_sum.min(100) as u8;

    FileAnalysisResult {
        detected_type,
        claimed_type,
        type_mismatch,
        anomalies,
        risk_score,
    }
}

pub fn scan_file_content_with_metadata(
    filename: &str,
    content: &[u8],
    content_type_header: Option<&str>,
    x_content_type_options: Option<&str>,
) -> FileAnalysisResult {
    let mut result = scan_file_content(filename, content);
    result
        .anomalies
        .extend(detect_content_type_mismatch(content, content_type_header));
    result.anomalies.extend(detect_mime_sniffing_attack(
        content,
        content_type_header,
        x_content_type_options,
    ));
    dedupe_anomalies(&mut result.anomalies);
    let risk_sum: u16 = result.anomalies.iter().map(|a| a.score as u16).sum();
    result.risk_score = risk_sum.min(100) as u8;
    result
}

pub fn detect_double_extension(filename: &str) -> Option<FileAnomaly> {
    let base = filename
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(filename)
        .to_ascii_lowercase();

    let parts: Vec<&str> = base.split('.').filter(|p| !p.is_empty()).collect();
    if parts.len() < 3 {
        return None;
    }

    let dangerous = [
        "php", "phtml", "asp", "aspx", "jsp", "exe", "dll", "js", "sh", "bat", "py",
    ];
    let benign = [
        "jpg", "jpeg", "png", "gif", "bmp", "txt", "pdf", "doc", "docx", "xls", "xlsx", "csv",
    ];

    let second_last = parts[parts.len() - 2];
    let last = parts[parts.len() - 1];

    if dangerous.contains(&second_last) && benign.contains(&last) {
        return Some(FileAnomaly::new(
            "double_extension",
            "filename contains dangerous double extension",
            45,
        ));
    }

    if let Some((left, right)) = base.split_once(';') {
        let left_ext = left.rsplit('.').next().unwrap_or_default();
        let right_ext = right.rsplit('.').next().unwrap_or_default();
        if dangerous.contains(&left_ext) && benign.contains(&right_ext) {
            return Some(FileAnomaly::new(
                "double_extension",
                "filename contains semicolon-based extension bypass",
                50,
            ));
        }
    }

    if base.contains("%00") {
        let before_null = base.split("%00").next().unwrap_or_default();
        let after_null = base.split("%00").nth(1).unwrap_or_default();
        let before_ext = before_null.rsplit('.').next().unwrap_or_default();
        let after_ext = after_null.rsplit('.').next().unwrap_or_default();
        if dangerous.contains(&before_ext) && benign.contains(&after_ext) {
            return Some(FileAnomaly::new(
                "double_extension",
                "filename contains null-byte-assisted extension bypass",
                50,
            ));
        }
    }

    None
}

pub fn detect_null_byte_extension(filename: &str) -> Option<FileAnomaly> {
    let lower = filename.to_ascii_lowercase();
    if lower.contains('\0') || lower.contains("%00") {
        return Some(FileAnomaly::new(
            "null_byte",
            "filename contains a null-byte extension bypass pattern",
            50,
        ));
    }
    None
}

fn file_type_from_filename(filename: &str) -> FileType {
    let ext = filename
        .rsplit('.')
        .next()
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_default();

    match ext.as_str() {
        "jpg" | "jpeg" => FileType::Jpeg,
        "png" => FileType::Png,
        "gif" => FileType::Gif,
        "bmp" => FileType::Bmp,
        "pdf" => FileType::Pdf,
        "zip" => FileType::Zip,
        "gz" | "gzip" => FileType::Gzip,
        "rar" => FileType::Rar,
        "exe" => FileType::Exe,
        "dll" => FileType::Dll,
        "elf" => FileType::Elf,
        "jar" => FileType::Jar,
        "apk" => FileType::Apk,
        "svg" => FileType::Svg,
        "xml" => FileType::Xml,
        "html" | "htm" => FileType::Html,
        "js" => FileType::Js,
        "php" => FileType::Php,
        "py" => FileType::Py,
        "sh" => FileType::Sh,
        "bat" | "cmd" => FileType::Bat,
        "doc" => FileType::Doc,
        "docx" => FileType::Docx,
        "xls" => FileType::Xls,
        "xlsx" => FileType::Xlsx,
        "csv" => FileType::Csv,
        _ => FileType::Unknown,
    }
}

fn are_compatible_types(claimed: FileType, detected: FileType) -> bool {
    if claimed == detected {
        return true;
    }

    let zip_family = [
        FileType::Zip,
        FileType::Jar,
        FileType::Apk,
        FileType::Docx,
        FileType::Xlsx,
    ];

    if zip_family.contains(&claimed) && zip_family.contains(&detected) {
        return true;
    }

    if claimed == FileType::Xml && detected == FileType::Svg {
        return true;
    }

    false
}

fn file_type_name(file_type: FileType) -> &'static str {
    match file_type {
        FileType::Jpeg => "jpeg",
        FileType::Png => "png",
        FileType::Gif => "gif",
        FileType::Bmp => "bmp",
        FileType::Pdf => "pdf",
        FileType::Zip => "zip",
        FileType::Gzip => "gzip",
        FileType::Rar => "rar",
        FileType::Exe => "exe",
        FileType::Dll => "dll",
        FileType::Elf => "elf",
        FileType::Mach => "mach-o",
        FileType::Jar => "jar",
        FileType::Apk => "apk",
        FileType::Svg => "svg",
        FileType::Xml => "xml",
        FileType::Html => "html",
        FileType::Js => "js",
        FileType::Php => "php",
        FileType::Py => "python",
        FileType::Sh => "shell",
        FileType::Bat => "batch",
        FileType::Doc => "doc",
        FileType::Docx => "docx",
        FileType::Xls => "xls",
        FileType::Xlsx => "xlsx",
        FileType::Csv => "csv",
        FileType::Unknown => "unknown",
    }
}

fn to_lower_ascii(content: &[u8]) -> String {
    let scan_len = content.len().min(1_000_000);
    String::from_utf8_lossy(&content[..scan_len]).to_ascii_lowercase()
}

fn is_jpeg(content: &[u8]) -> bool {
    content.len() >= 3 && content[0] == 0xFF && content[1] == 0xD8 && content[2] == 0xFF
}

fn is_png(content: &[u8]) -> bool {
    content.starts_with(b"\x89PNG\r\n\x1a\n")
}

fn is_gif(content: &[u8]) -> bool {
    content.starts_with(b"GIF87a") || content.starts_with(b"GIF89a")
}

fn is_bmp(content: &[u8]) -> bool {
    content.starts_with(b"BM")
}

fn is_pdf(content: &[u8]) -> bool {
    content.starts_with(b"%PDF-")
}

fn is_pe(content: &[u8]) -> bool {
    if content.len() < 0x40 || !content.starts_with(b"MZ") {
        return false;
    }

    let pe_offset = u32::from_le_bytes([content[0x3c], content[0x3d], content[0x3e], content[0x3f]]) as usize;
    content.len() >= pe_offset + 4 && &content[pe_offset..pe_offset + 4] == b"PE\0\0"
}

fn is_pe_dll(content: &[u8]) -> bool {
    if !is_pe(content) {
        return false;
    }

    let pe_offset = u32::from_le_bytes([content[0x3c], content[0x3d], content[0x3e], content[0x3f]]) as usize;
    if content.len() < pe_offset + 24 {
        return false;
    }

    let characteristics = u16::from_le_bytes([content[pe_offset + 22], content[pe_offset + 23]]);
    (characteristics & 0x2000) != 0
}

fn is_elf(content: &[u8]) -> bool {
    content.starts_with(b"\x7FELF")
}

fn is_mach(content: &[u8]) -> bool {
    if content.len() < 4 {
        return false;
    }

    matches!(
        &content[..4],
        [0xFE, 0xED, 0xFA, 0xCE]
            | [0xFE, 0xED, 0xFA, 0xCF]
            | [0xCE, 0xFA, 0xED, 0xFE]
            | [0xCF, 0xFA, 0xED, 0xFE]
            | [0xCA, 0xFE, 0xBA, 0xBE]
            | [0xBE, 0xBA, 0xFE, 0xCA]
    )
}

fn is_zip_like(content: &[u8]) -> bool {
    content.starts_with(b"PK\x03\x04") || content.starts_with(b"PK\x05\x06") || content.starts_with(b"PK\x07\x08")
}

fn contains_zip_signature(content: &[u8]) -> bool {
    content.windows(4).any(|w| w == b"PK\x03\x04" || w == b"PK\x05\x06" || w == b"PK\x07\x08")
}

fn contains_zip_signature_after_prefix(content: &[u8]) -> bool {
    content
        .windows(4)
        .enumerate()
        .any(|(idx, w)| idx > 0 && (w == b"PK\x03\x04" || w == b"PK\x05\x06" || w == b"PK\x07\x08"))
}

fn is_gzip(content: &[u8]) -> bool {
    content.starts_with(&[0x1f, 0x8b])
}

fn is_rar(content: &[u8]) -> bool {
    content.starts_with(b"Rar!\x1A\x07\x00") || content.starts_with(b"Rar!\x1A\x07\x01\x00")
}

fn is_ole(content: &[u8]) -> bool {
    content.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1])
}

fn looks_like_javascript(text: &str) -> bool {
    text.contains("function ")
        || text.contains("const ")
        || text.contains("let ")
        || text.contains("=>")
        || text.contains("document.")
}

fn looks_like_csv(text: &str) -> bool {
    let mut lines = text.lines();
    let first = match lines.next() {
        Some(line) if line.contains(',') => line,
        _ => return false,
    };

    let cols = first.split(',').count();
    if cols < 2 {
        return false;
    }

    match lines.next() {
        Some(line) => line.split(',').count() == cols,
        None => false,
    }
}

#[derive(Debug, Default)]
struct ZipStats {
    entry_count: usize,
    nested_archive_entries: usize,
    total_compressed: u64,
    total_uncompressed: u64,
}

fn parse_zip_local_headers(content: &[u8]) -> ZipStats {
    let mut stats = ZipStats::default();
    let mut i = 0usize;

    while i + 30 <= content.len() {
        if &content[i..i + 4] != b"PK\x03\x04" {
            i += 1;
            continue;
        }

        stats.entry_count += 1;

        let compressed = u32::from_le_bytes([content[i + 18], content[i + 19], content[i + 20], content[i + 21]]) as u64;
        let uncompressed = u32::from_le_bytes([content[i + 22], content[i + 23], content[i + 24], content[i + 25]]) as u64;
        let name_len = u16::from_le_bytes([content[i + 26], content[i + 27]]) as usize;
        let extra_len = u16::from_le_bytes([content[i + 28], content[i + 29]]) as usize;

        stats.total_compressed = stats.total_compressed.saturating_add(compressed);
        stats.total_uncompressed = stats.total_uncompressed.saturating_add(uncompressed);

        let name_start = i + 30;
        let name_end = name_start.saturating_add(name_len);
        if name_end <= content.len() {
            let name = String::from_utf8_lossy(&content[name_start..name_end]).to_ascii_lowercase();
            if name.ends_with(".zip")
                || name.ends_with(".jar")
                || name.ends_with(".apk")
                || name.ends_with(".gz")
                || name.ends_with(".rar")
            {
                stats.nested_archive_entries += 1;
            }
        }

        let next = name_end
            .saturating_add(extra_len)
            .saturating_add(compressed as usize);

        if next <= i {
            break;
        }
        i = next;
    }

    stats
}

fn parse_zip_entry_names(content: &[u8]) -> Vec<String> {
    if !is_zip_like(content) {
        return Vec::new();
    }

    let mut names = Vec::new();
    let mut i = 0usize;
    while i + 30 <= content.len() && names.len() < 4096 {
        if &content[i..i + 4] != b"PK\x03\x04" {
            i += 1;
            continue;
        }

        let compressed = u32::from_le_bytes([content[i + 18], content[i + 19], content[i + 20], content[i + 21]]) as usize;
        let name_len = u16::from_le_bytes([content[i + 26], content[i + 27]]) as usize;
        let extra_len = u16::from_le_bytes([content[i + 28], content[i + 29]]) as usize;

        let name_start = i + 30;
        let name_end = name_start.saturating_add(name_len);
        if name_end <= content.len() {
            names.push(String::from_utf8_lossy(&content[name_start..name_end]).to_string());
        }

        let next = name_end.saturating_add(extra_len).saturating_add(compressed);
        if next <= i {
            break;
        }
        i = next;
    }
    names
}

fn looks_like_archive_traversal_path(path: &str) -> bool {
    let normalized = path.to_ascii_lowercase().replace('\\', "/");
    normalized.starts_with('/')
        || normalized.starts_with("../")
        || normalized.contains("/../")
        || normalized.contains("..%2f")
        || normalized.contains("%2e%2e")
        || normalized.contains(":/")
}

fn file_type_from_content_type(content_type: &str) -> Option<FileType> {
    match content_type {
        "image/jpeg" | "image/jpg" => Some(FileType::Jpeg),
        "image/png" => Some(FileType::Png),
        "image/gif" => Some(FileType::Gif),
        "image/bmp" => Some(FileType::Bmp),
        "image/svg+xml" => Some(FileType::Svg),
        "application/pdf" => Some(FileType::Pdf),
        "text/html" => Some(FileType::Html),
        "application/xml" | "text/xml" => Some(FileType::Xml),
        "application/javascript" | "text/javascript" => Some(FileType::Js),
        "application/zip" => Some(FileType::Zip),
        "application/gzip" => Some(FileType::Gzip),
        "application/java-archive" => Some(FileType::Jar),
        "application/vnd.android.package-archive" => Some(FileType::Apk),
        "application/msword" => Some(FileType::Doc),
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document" => Some(FileType::Docx),
        "application/vnd.ms-excel" => Some(FileType::Xls),
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" => Some(FileType::Xlsx),
        "text/csv" => Some(FileType::Csv),
        _ => None,
    }
}

fn dedupe_anomalies(anomalies: &mut Vec<FileAnomaly>) {
    let mut seen = HashSet::new();
    anomalies.retain(|a| seen.insert((a.kind.clone(), a.description.clone())));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zip_local_entry(path: &str, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        out.extend_from_slice(&[0, 0, 0, 0]);
        let size = payload.len() as u32;
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&(path.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(path.as_bytes());
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn detect_jpeg_magic() {
        assert_eq!(detect_file_type(&[0xFF, 0xD8, 0xFF, 0xEE]), FileType::Jpeg);
    }

    #[test]
    fn detect_png_magic() {
        assert_eq!(detect_file_type(b"\x89PNG\r\n\x1a\nxyz"), FileType::Png);
    }

    #[test]
    fn detect_pdf_magic() {
        assert_eq!(detect_file_type(b"%PDF-1.7\n"), FileType::Pdf);
    }

    #[test]
    fn detect_docx_from_zip_markers() {
        let sample = b"PK\x03\x04aaaa[Content_Types].xmlword/document.xml";
        assert_eq!(detect_file_type(sample), FileType::Docx);
    }

    #[test]
    fn detect_html_text() {
        assert_eq!(detect_file_type(b"<!DOCTYPE html><html></html>"), FileType::Html);
    }

    #[test]
    fn extension_validation_match() {
        let ok = validate_extension_matches("photo.jpg", &[0xFF, 0xD8, 0xFF, 0xE0]);
        assert!(ok);
    }

    #[test]
    fn extension_validation_mismatch() {
        let ok = validate_extension_matches("photo.jpg", b"%PDF-1.7");
        assert!(!ok);
    }

    #[test]
    fn detects_embedded_php_in_jpeg() {
        let sample = b"\xFF\xD8\xFF\xE0...<?php system($_GET['x']); ?>";
        let anomalies = detect_embedded_scripts(sample, FileType::Jpeg);
        assert!(!anomalies.is_empty());
    }

    #[test]
    fn detects_polyglot_png_html() {
        let sample = b"\x89PNG\r\n\x1a\n....<html><script>alert(1)</script></html>";
        let anomalies = detect_polyglot_file(sample);
        assert_eq!(anomalies.len(), 1);
    }

    #[test]
    fn detects_gzip_bomb_by_ratio() {
        let mut sample = vec![0x1F, 0x8B, 0x08, 0x00, 0, 0, 0, 0, 0, 0];
        sample.extend_from_slice(&[0u8; 20]);
        sample.extend_from_slice(&(5_000_000u32.to_le_bytes()));
        assert!(detect_zip_bomb(&sample).is_some());
    }

    #[test]
    fn detects_path_traversal_filename() {
        let anomaly = detect_path_traversal_filename("../../etc/passwd");
        assert!(anomaly.is_some());
    }

    #[test]
    fn detects_double_extension() {
        let anomaly = detect_double_extension("avatar.php.jpg");
        assert!(anomaly.is_some());
    }

    #[test]
    fn detects_null_byte_extension() {
        let anomaly = detect_null_byte_extension("payload.php%00.jpg");
        assert!(anomaly.is_some());
    }

    #[test]
    fn detects_eicar_signature() {
        let sample = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        assert!(is_eicar_test(sample));
    }

    #[test]
    fn scan_file_aggregates_findings() {
        let sample = b"\xFF\xD8\xFF\xE0<?php echo 1; ?>";
        let result = scan_file_content("invoice.php.jpg", sample);

        assert_eq!(result.detected_type, FileType::Jpeg);
        assert!(result.anomalies.iter().any(|a| a.kind == "embedded_script"));
        assert!(result.anomalies.iter().any(|a| a.kind == "double_extension"));
        assert!(result.risk_score > 0);
    }

    #[test]
    fn detects_polyglot_gifar_signature() {
        let sample = b"GIF89a....PK\x03\x04META-INF/MANIFEST.MF";
        let anomalies = detect_polyglot_file(sample);
        assert!(anomalies.iter().any(|a| a.description.contains("GIFAR")));
    }

    #[test]
    fn detects_polyglot_pdf_js() {
        let sample = b"%PDF-1.7\n1 0 obj\n<< /JavaScript /JS (alert(1)) >>";
        let anomalies = detect_polyglot_file(sample);
        assert!(anomalies.iter().any(|a| a.description.contains("PDF")));
    }

    #[test]
    fn detects_polyglot_png_html_payload() {
        let sample = b"\x89PNG\r\n\x1a\n....<html><body>x</body></html>";
        let anomalies = detect_polyglot_file(sample);
        assert!(anomalies.iter().any(|a| a.description.contains("PNG+HTML")));
    }

    #[test]
    fn detects_content_type_mismatch_image_header_html_body() {
        let sample = b"<!doctype html><html><script>alert(1)</script></html>";
        let anomalies = detect_content_type_mismatch(sample, Some("image/png"));
        assert!(anomalies.iter().any(|a| a.kind == "content_type_mismatch"));
    }

    #[test]
    fn detects_content_type_mismatch_js_with_png_magic() {
        let sample = b"\x89PNG\r\n\x1a\n....";
        let anomalies = detect_content_type_mismatch(sample, Some("application/javascript"));
        assert!(anomalies.iter().any(|a| a.kind == "content_type_mismatch"));
    }

    #[test]
    fn no_content_type_mismatch_for_consistent_upload() {
        let sample = b"\x89PNG\r\n\x1a\n....";
        let anomalies = detect_content_type_mismatch(sample, Some("image/png"));
        assert!(anomalies.is_empty());
    }

    #[test]
    fn detects_magic_byte_spoofing_with_gif_script() {
        let sample = b"GIF89a....<script>alert(1)</script>";
        let anomalies = detect_magic_byte_spoofing(sample);
        assert!(anomalies.iter().any(|a| a.kind == "magic_byte_spoofing"));
    }

    #[test]
    fn detects_magic_byte_spoofing_with_png_html() {
        let sample = b"\x89PNG\r\n\x1a\n....<html>evil</html>";
        let anomalies = detect_magic_byte_spoofing(sample);
        assert!(anomalies.iter().any(|a| a.kind == "magic_byte_spoofing"));
    }

    #[test]
    fn no_magic_byte_spoofing_for_benign_png() {
        let sample = b"\x89PNG\r\n\x1a\n\x00\x00\x00\x0DIHDR";
        let anomalies = detect_magic_byte_spoofing(sample);
        assert!(anomalies.is_empty());
    }

    #[test]
    fn detects_double_extension_semicolon_bypass() {
        let anomaly = detect_double_extension("file.asp;.jpg");
        assert!(anomaly.is_some());
    }

    #[test]
    fn detects_double_extension_null_byte_bypass() {
        let anomaly = detect_double_extension("file.jsp%00.gif");
        assert!(anomaly.is_some());
    }

    #[test]
    fn detects_mime_sniffing_without_nosniff() {
        let sample = b"text payload <html><script>x</script></html>";
        let anomalies = detect_mime_sniffing_attack(sample, Some("text/plain"), None);
        assert!(anomalies.iter().any(|a| a.kind == "mime_sniffing"));
    }

    #[test]
    fn no_mime_sniffing_when_nosniff_present() {
        let sample = b"text payload <html><script>x</script></html>";
        let anomalies =
            detect_mime_sniffing_attack(sample, Some("text/plain"), Some("nosniff"));
        assert!(anomalies.is_empty());
    }

    #[test]
    fn detects_svg_with_embedded_script() {
        let sample = b"<svg><script>alert(1)</script></svg>";
        let anomalies = detect_svg_script_payload(sample);
        assert!(anomalies.iter().any(|a| a.kind == "svg_script"));
    }

    #[test]
    fn detects_svg_with_event_handler() {
        let sample = b"<svg><image onload=\"alert(1)\" /></svg>";
        let anomalies = detect_svg_script_payload(sample);
        assert!(anomalies.iter().any(|a| a.kind == "svg_script"));
    }

    #[test]
    fn benign_svg_without_script_is_clean() {
        let sample = b"<svg xmlns=\"http://www.w3.org/2000/svg\"><rect width=\"10\" height=\"10\"/></svg>";
        let anomalies = detect_svg_script_payload(sample);
        assert!(anomalies.is_empty());
    }

    #[test]
    fn detects_xml_entity_expansion_pattern() {
        let sample = br#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY x "aaaa">]><root>&x;</root>"#;
        let anomalies = detect_xml_xslt_injection(sample);
        assert!(anomalies.iter().any(|a| a.kind == "xml_entity_expansion"));
    }

    #[test]
    fn detects_xslt_execution_pattern() {
        let sample = br#"<xsl:stylesheet version="1.0"><xsl:value-of select="document('http://evil')"/></xsl:stylesheet>"#;
        let anomalies = detect_xml_xslt_injection(sample);
        assert!(anomalies.iter().any(|a| a.kind == "xslt_execution"));
    }

    #[test]
    fn detects_zip_slip_entry() {
        let zip = zip_local_entry("../../../etc/passwd", b"root:x");
        let anomalies = detect_archive_slip(&zip);
        assert!(anomalies.iter().any(|a| a.kind == "archive_slip"));
    }

    #[test]
    fn no_zip_slip_for_safe_entry() {
        let zip = zip_local_entry("safe/file.txt", b"hello");
        let anomalies = detect_archive_slip(&zip);
        assert!(anomalies.is_empty());
    }

    #[test]
    fn detects_tar_slip_pattern() {
        let tar_like = b"../etc/passwd.........................................ustar";
        let anomalies = detect_archive_slip(tar_like);
        assert!(anomalies.iter().any(|a| a.kind == "archive_slip"));
    }

    #[test]
    fn detects_office_macro_marker() {
        let sample = b"PK\x03\x04...[Content_Types].xmlword/vbaProject.bin";
        let anomalies = detect_embedded_macros_and_hta(sample, FileType::Docx);
        assert!(anomalies.iter().any(|a| a.kind == "macro"));
    }

    #[test]
    fn detects_hta_payload_marker() {
        let sample = b"<hta:application><script>new ActiveXObject('WScript.Shell')</script>";
        let anomalies = detect_embedded_macros_and_hta(sample, FileType::Html);
        assert!(anomalies.iter().any(|a| a.kind == "hta_payload"));
    }

    #[test]
    fn scan_with_metadata_detects_content_confusion_attacks() {
        let sample = b"GIF89a....<html><script>alert(1)</script></html>";
        let result = scan_file_content_with_metadata(
            "avatar.gif",
            sample,
            Some("image/png"),
            None,
        );

        assert!(result.anomalies.iter().any(|a| a.kind == "content_type_mismatch"));
        assert!(result.anomalies.iter().any(|a| a.kind == "mime_sniffing"));
        assert!(result.anomalies.iter().any(|a| a.kind == "magic_byte_spoofing"));
    }

    #[test]
    fn scan_with_metadata_benign_png_has_no_confusion_findings() {
        let sample = b"\x89PNG\r\n\x1a\n\x00\x00\x00\x0DIHDR";
        let result = scan_file_content_with_metadata(
            "avatar.png",
            sample,
            Some("image/png"),
            Some("nosniff"),
        );
        assert!(!result.anomalies.iter().any(|a| a.kind == "content_type_mismatch"));
        assert!(!result.anomalies.iter().any(|a| a.kind == "mime_sniffing"));
    }
}
