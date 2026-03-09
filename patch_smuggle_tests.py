import re

with open("packages/engine-rs/src/evaluators/http_smuggle.rs", "r") as f:
    content = f.read()

tests_to_add = """
    #[test]
    fn test_smuggle_chunk_size_overflow() {
        let eval = HttpSmuggleEvaluator;
        assert!(eval.detect("POST / HTTP/1.1
Transfer-Encoding: chunked

100000
").iter().any(|d| d.detection_type == "smuggle_chunk_size_overflow"));
        assert!(eval.detect("POST / HTTP/1.1
Transfer-Encoding: chunked

FFFFF
").iter().any(|d| d.detection_type == "smuggle_chunk_size_overflow"));
        assert!(!eval.detect("POST / HTTP/1.1
Transfer-Encoding: chunked

100
").iter().any(|d| d.detection_type == "smuggle_chunk_size_overflow"));
    }

    #[test]
    fn test_smuggle_te_priority_override() {
        let eval = HttpSmuggleEvaluator;
        assert!(eval.detect("POST / HTTP/1.1
Content-Length: 10
Transfer-Encoding: chunked

").iter().any(|d| d.detection_type == "smuggle_te_priority_override"));
        assert!(eval.detect("POST / HTTP/1.1
Content-Length: 5
Transfer-Encoding: gzip

").iter().any(|d| d.detection_type == "smuggle_te_priority_override"));
        assert!(!eval.detect("POST / HTTP/1.1
Transfer-Encoding: chunked
Content-Length: 10

").iter().any(|d| d.detection_type == "smuggle_te_priority_override"));
    }

    #[test]
    fn test_smuggle_h2_header_inject() {
        let eval = HttpSmuggleEvaluator;
        assert!(eval.detect("POST / HTTP/1.1
x-inject: :method GET

").iter().any(|d| d.detection_type == "smuggle_h2_header_inject"));
        assert!(eval.detect("POST / HTTP/1.1
x-inject: :path /admin

").iter().any(|d| d.detection_type == "smuggle_h2_header_inject"));
        assert!(!eval.detect("POST / HTTP/1.1
Host: example.com

").iter().any(|d| d.detection_type == "smuggle_h2_header_inject"));
    }

    #[test]
    fn test_smuggle_whitespace_before_colon() {
        let eval = HttpSmuggleEvaluator;
        assert!(eval.detect("POST / HTTP/1.1
Host : example.com

").iter().any(|d| d.detection_type == "smuggle_whitespace_before_colon"));
        assert!(eval.detect("POST / HTTP/1.1
Transfer-Encoding	: chunked

").iter().any(|d| d.detection_type == "smuggle_whitespace_before_colon"));
        assert!(!eval.detect("POST / HTTP/1.1
Host: example.com

").iter().any(|d| d.detection_type == "smuggle_whitespace_before_colon"));
    }

    #[test]
    fn test_smuggle_pipeline_bypass() {
        let eval = HttpSmuggleEvaluator;
        assert!(eval.detect("POST / HTTP/1.1
Content-Length: 100

GET /admin HTTP/1.1
Host: abc

").iter().any(|d| d.detection_type == "smuggle_pipeline_bypass"));
        assert!(eval.detect("POST / HTTP/1.1
Content-Length: 100

POST /admin HTTP/1.0
").iter().any(|d| d.detection_type == "smuggle_pipeline_bypass"));
        assert!(!eval.detect("POST / HTTP/1.1
Content-Length: 10

hello GET").iter().any(|d| d.detection_type == "smuggle_pipeline_bypass"));
    }
}
"""

content = re.sub(r'}\s*$', tests_to_add, content)

with open("packages/engine-rs/src/evaluators/http_smuggle.rs", "w") as f:
    f.write(content)
