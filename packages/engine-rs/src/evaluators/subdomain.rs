//! Subdomain Takeover Signal Evaluator — Level 2
//!
//! Detects signals of subdomain takeover attempts:
//!   - CNAME pointing to unclaimed service (S3, Azure, GitHub Pages, etc.)
//!   - Known service fingerprints in error responses
//!   - DNS dangling reference indicators

use crate::evaluators::{EvidenceOperation, L2Detection, L2Evaluator, ProofEvidence};
use crate::types::InvariantClass;

/// Service fingerprints that indicate a claimable (dangling) subdomain.
const TAKEOVER_FINGERPRINTS: &[(&str, &str)] = &[
    ("NoSuchBucket", "AWS S3"),
    ("The specified bucket does not exist", "AWS S3"),
    ("There isn't a GitHub Pages site here", "GitHub Pages"),
    ("Repository not found", "Bitbucket"),
    ("The thing you were looking for is no longer here", "Ghost CMS"),
    ("Fastly error: unknown domain", "Fastly CDN"),
    ("The feed has not been found", "Feedpress"),
    ("is not a registered InfinityFree", "InfinityFree"),
    ("Domain is not configured", "Netlify"),
    ("project not found", "Vercel/Surge"),
    ("NoSuchKey", "AWS S3 (key)"),
    ("NXDOMAIN", "DNS resolution failure"),
    ("Heroku | No such app", "Heroku"),
    ("404 Blog is not found", "Tumblr"),
    ("Whatever you were looking for doesn't currently exist at this address", "Tumblr (v2)"),
    ("<title>Squarespace - No Such Account</title>", "Squarespace"),
    ("The request could not be satisfied", "CloudFront"),
    ("Sorry, this shop is currently unavailable", "Shopify"),
    ("You're Almost There", "Pantheon"),
    ("Unrecognized domain", "Help Scout"),
    ("This UserVoice subdomain is currently available!", "UserVoice"),
    ("Company Not Found", "Tictail"),
    ("is not a custom namespace", "Wordpress.com"),
    ("Blog not found", "Wordpress.com"),
    ("No settings were found for this company", "Help Juice"),
    ("We could not find what you're looking for", "Helprace"),
    ("Uh oh. That page doesn't exist", "Intercom"),
    ("This page is reserved for", "Webflow"),
    ("The specified account does not exist", "Azure Blob"),
];

pub struct SubdomainEvaluator;

impl L2Evaluator for SubdomainEvaluator {
    fn id(&self) -> &'static str {
        "subdomain"
    }
    fn prefix(&self) -> &'static str {
        "L2 Subdomain"
    }

    fn detect(&self, input: &str) -> Vec<L2Detection> {
        let mut dets = Vec::new();
        let lower = input.to_ascii_lowercase();

        for &(fingerprint, service) in TAKEOVER_FINGERPRINTS {
            let fp_lower = fingerprint.to_ascii_lowercase();
            if lower.contains(&fp_lower) {
                let pos = lower.find(&fp_lower).unwrap_or(0);
                dets.push(L2Detection {
                    detection_type: "subdomain_takeover_fingerprint".into(),
                    confidence: 0.90,
                    detail: format!(
                        "{} service fingerprint detected — potential subdomain takeover via dangling CNAME to {}",
                        service, service
                    ),
                    position: pos,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::SemanticEval,
                        matched_input: fingerprint.to_string(),
                        interpretation: format!(
                            "Response contains the error fingerprint '{}' from {}. This indicates the subdomain's CNAME points to a {} resource that no longer exists or has been deleted. An attacker can claim this resource and serve arbitrary content on the victim's subdomain.",
                            fingerprint, service, service
                        ),
                        offset: pos,
                        property: format!("DNS CNAME records pointing to {} must be removed when the corresponding resource is deleted. Subdomain lifecycle must be monitored for dangling references.", service),
                    }],
                });
                break; // one fingerprint is sufficient
            }
        }

        // Also detect common CNAME targets that are often dangling
        let dangling_cname_targets = [
            (".s3.amazonaws.com", "AWS S3"),
            (".s3-website", "AWS S3 Website"),
            (".cloudfront.net", "AWS CloudFront"),
            (".elasticbeanstalk.com", "AWS Elastic Beanstalk"),
            (".azurewebsites.net", "Azure App Service"),
            (".cloudapp.azure.com", "Azure Cloud App"),
            (".blob.core.windows.net", "Azure Blob Storage"),
            (".trafficmanager.net", "Azure Traffic Manager"),
            (".github.io", "GitHub Pages"),
            (".herokuapp.com", "Heroku"),
            (".netlify.app", "Netlify"),
            (".vercel.app", "Vercel"),
            (".surge.sh", "Surge"),
            (".ghost.io", "Ghost"),
            (".pantheonsite.io", "Pantheon"),
            (".myshopify.com", "Shopify"),
            (".squarespace.com", "Squarespace"),
            (".tumblr.com", "Tumblr"),
            (".wordpress.com", "WordPress.com"),
            (".fly.dev", "Fly.io"),
        ];

        for &(target, service) in &dangling_cname_targets {
            if lower.contains(target) {
                // Only flag if there's also an error indicator
                if lower.contains("not found") || lower.contains("404") ||
                   lower.contains("does not exist") || lower.contains("no such") ||
                   lower.contains("unavailable") || lower.contains("nxdomain")
                {
                    let pos = lower.find(target).unwrap_or(0);
                    if !dets.iter().any(|d| d.detection_type == "subdomain_takeover_fingerprint") {
                        dets.push(L2Detection {
                            detection_type: "subdomain_takeover_dangling".into(),
                            confidence: 0.82,
                            detail: format!(
                                "CNAME target {} with error response — potential dangling reference to {}",
                                target, service
                            ),
                            position: pos,
                            evidence: vec![ProofEvidence {
                                operation: EvidenceOperation::SemanticEval,
                                matched_input: format!("{} + error response", target),
                                interpretation: format!(
                                    "The response references a {} CNAME target ({}) combined with an error message. This pattern indicates the subdomain's DNS points to {} but the resource has been removed, creating a takeover opportunity.",
                                    service, target, service
                                ),
                                offset: pos,
                                property: format!("DNS records pointing to {} must be audited regularly. CNAME targets must reference active, owned resources.", service),
                            }],
                        });
                    }
                    break;
                }
            }
        }

        dets
    }

    fn map_class(&self, detection_type: &str) -> Option<InvariantClass> {
        match detection_type {
            "subdomain_takeover_fingerprint" | "subdomain_takeover_dangling" => {
                Some(InvariantClass::SubdomainTakeover)
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_s3_fingerprint() {
        let eval = SubdomainEvaluator;
        let dets = eval.detect("<Error><Code>NoSuchBucket</Code></Error>");
        assert!(dets.iter().any(|d| d.detection_type == "subdomain_takeover_fingerprint"));
    }

    #[test]
    fn detects_github_pages_fingerprint() {
        let eval = SubdomainEvaluator;
        let dets = eval.detect("<title>There isn't a GitHub Pages site here.</title>");
        assert!(dets.iter().any(|d| d.detection_type == "subdomain_takeover_fingerprint"));
    }

    #[test]
    fn detects_heroku_fingerprint() {
        let eval = SubdomainEvaluator;
        let dets = eval.detect("Heroku | No such app");
        assert!(dets.iter().any(|d| d.detection_type == "subdomain_takeover_fingerprint"));
    }

    #[test]
    fn detects_dangling_cname() {
        let eval = SubdomainEvaluator;
        let dets = eval.detect("CNAME target: subdomain.s3.amazonaws.com - Error: NoSuchBucket not found");
        assert!(!dets.is_empty());
    }

    #[test]
    fn no_detection_for_normal_page() {
        let eval = SubdomainEvaluator;
        let dets = eval.detect("<html><body>Welcome to our website</body></html>");
        assert!(dets.is_empty());
    }

    #[test]
    fn maps_to_correct_class() {
        let eval = SubdomainEvaluator;
        assert_eq!(
            eval.map_class("subdomain_takeover_fingerprint"),
            Some(InvariantClass::SubdomainTakeover)
        );
    }
}
