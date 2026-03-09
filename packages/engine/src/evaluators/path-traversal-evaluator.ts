/**
 * Path Traversal Evaluator — Level 2 Invariant Detection
 *
 * The invariant property for path traversal is:
 *   resolve(normalize(decode(input))) ESCAPES webroot
 *   ∨ input contains null-terminating byte and path context
 *   ∨ obfuscation is required to expose traversal segments
 *
 * This evaluator is structural:
 *   1. Decodes encoding layers
 *   2. Normalizes separators and resolves path segments
 *   3. Applies explicit detectors for null-byte truncation, UNC, and double encoding
 */

// ── Result Type ──────────────────────────────────────────────────

export interface PathTraversalDetection {
    type: 'dotdot_escape' | 'null_terminate' | 'encoding_bypass' | 'normalization_bypass' | 'windows_traversal'
    detail: string
    resolvedPath: string
    escapeDepth: number
    confidence: number
}


// ── Sensitive Target Files ───────────────────────────────────────

const SENSITIVE_TARGETS = new Set([
    'etc/passwd', 'etc/shadow', 'etc/hosts', 'etc/hostname',
    'etc/ssh/sshd_config', 'etc/nginx/nginx.conf', 'etc/apache2/apache2.conf',
    'proc/self/environ', 'proc/self/cmdline', 'proc/self/status',
    'proc/self/maps', 'proc/self/fd/0',
    'var/log/auth.log', 'var/log/syslog', 'var/log/apache2/error.log',
    'root/.ssh/authorized_keys', 'root/.ssh/id_rsa', 'root/.bash_history',
    'windows/system32/config/sam', 'windows/system.ini', 'windows/win.ini',
    'boot.ini', 'inetpub/wwwroot/web.config',
    '.env', '.git/config', '.git/HEAD', '.htaccess', '.htpasswd',
    'wp-config.php', 'config.php', 'configuration.php',
    'web.config', 'appsettings.json', 'application.properties',
])

const WINDOWS_TARGETS = new Set([
    'windows/system32',
    'windows/system32/drivers/etc/hosts',
    'windows/win.ini',
    'windows/system.ini',
    'windows/config/sam',
])


// ── Multi-layer Decoder ────────────────────────────────────────

function deepDecode(input: string, maxIterations = 5): { decoded: string; layers: number } {
    let current = input
    let layers = 0

    for (let i = 0; i < maxIterations; i++) {
        let next = current

        // URL decode (`%XX`) with tolerant fallback.
        try {
            next = decodeURIComponent(next)
        } catch {
            next = next.replace(/%([0-9a-fA-F]{2})/g, (_, hex) =>
                String.fromCharCode(parseInt(hex, 16)))
        }

        // JavaScript-style `%uXXXX` escapes (`%u002e`).
        next = next.replace(/%u([0-9a-fA-F]{4})/gi, (_, hex) => {
            return String.fromCharCode(parseInt(hex, 16))
        })

        // HTML entities that can hide separators.
        next = next.replace(/&#(\d+);/g, (_, dec) => String.fromCharCode(parseInt(dec, 10)))
        next = next.replace(/&#x([0-9a-fA-F]+);/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
        next = next.replace(/&period;/gi, '.')
        next = next.replace(/&sol;/gi, '/')
        next = next.replace(/&bsol;/gi, '\\')

        if (next === current) break
        current = next
        layers++
    }

    return { decoded: current, layers }
}


// ── Path Resolver ───────────────────────────────────────────────

interface PathResolution {
    escapeDepth: number
    resolvedPath: string
    targetsSensitiveFile: boolean
    sensitiveFile: string | null
}

function resolvePath(decoded: string): PathResolution {
    const normalized = decoded.replace(/\\/g, '/')
    const segments = normalized.split('/')
        .filter(segment => segment.length > 0)

    const resolved: string[] = []
    let escapeDepth = 0

    for (const segment of segments) {
        if (segment === '.' || segment === '') {
            continue
        }

        if (segment === '..') {
            if (resolved.length > 0) {
                resolved.pop()
            } else {
                escapeDepth++
            }
            continue
        }

        resolved.push(segment)
    }

    const resolvedPath = resolved.join('/')
    const normalizedLower = resolvedPath.toLowerCase()

    let sensitiveFile: string | null = null
    for (const target of SENSITIVE_TARGETS) {
        if (normalizedLower === target || normalizedLower.endsWith(`/${target}`)) {
            sensitiveFile = target
            break
        }
    }

    return {
        escapeDepth,
        resolvedPath,
        targetsSensitiveFile: sensitiveFile !== null,
        sensitiveFile,
    }
}


// ── Detection Functions ────────────────────────────────────────

function buildDotdotTraversalDetection(decoded: string, resolution: PathResolution): PathTraversalDetection | null {
    if (resolution.escapeDepth <= 0) return null

    const targetContext = resolution.targetsSensitiveFile
        ? ` → resolves to ${resolution.sensitiveFile}`
        : ''

    return {
        type: 'dotdot_escape',
        detail: `Traversal escapes directory depth by ${resolution.escapeDepth}.${targetContext}`,
        resolvedPath: resolution.resolvedPath,
        escapeDepth: resolution.escapeDepth,
        confidence: resolution.targetsSensitiveFile ? 0.95 : 0.87,
    }
}

function buildNullByteDetection(input: string, decoded: string): PathTraversalDetection | null {
    const hasRawNull = /%00|%2500|\\x00/i.test(input) || /\0/.test(input)
    const nullIndex = decoded.indexOf('\0')

    if (!hasRawNull && nullIndex < 0) return null

    const beforeNull = nullIndex >= 0 ? decoded.slice(0, nullIndex) : decoded
    const afterNull = nullIndex >= 0 ? decoded.slice(nullIndex + 1) : ''

    const hasTraversalContext = beforeNull.includes('..') || /[\\/]/.test(beforeNull)
    const hasExtensionContext = /\.[a-z0-9]{1,10}$/i.test(beforeNull) || /\.(php|jsp|aspx|asp|html?)\b/i.test(afterNull)

    if (!hasTraversalContext && !hasExtensionContext) return null

    return {
        type: 'null_terminate',
        detail: `Null byte detected in path payload (${hasTraversalContext ? 'truncation' : 'extension-bypass'})`,
        resolvedPath: beforeNull,
        escapeDepth: 0,
        confidence: hasTraversalContext ? 0.90 : 0.80,
    }
}

function buildEncodingBypassDetection(input: string, decoded: string, layers: number, resolution: PathResolution): PathTraversalDetection | null {
    const hasTraversal = resolution.escapeDepth > 0 || /(?:^|[\\/])\.{2}(?:[\\/]|$)|\.{3,}(?:[\\/]|$)/.test(decoded)
    if (!hasTraversal) return null

    const hasEncodedDot = /%2e|%c0%ae|%u002e|&#46;|&period;/i.test(input)
    const hasEncodedSlash = /%2f|%5c|%u002f|&sol;|&#47;/i.test(input)
    const hasDoubleEncoded = layers >= 2 && /%25/i.test(input)

    if (layers >= 2 && (hasEncodedDot || hasEncodedSlash || hasDoubleEncoded)) {
        return {
            type: 'encoding_bypass',
            detail: `Double-encoded traversal sequence decoded to: ${decoded.slice(0, 80)}`,
            resolvedPath: resolution.resolvedPath,
            escapeDepth: resolution.escapeDepth,
            confidence: 0.92,
        }
    }

    if (hasEncodedDot || hasEncodedSlash) {
        return {
            type: 'encoding_bypass',
            detail: `Encoded traversal separators (dot:${hasEncodedDot ? 'yes' : 'no'}, slash:${hasEncodedSlash ? 'yes' : 'no'})`,
            resolvedPath: resolution.resolvedPath,
            escapeDepth: resolution.escapeDepth,
            confidence: hasTraversal ? 0.88 : 0.76,
        }
    }

    return null
}

function buildNormalizationDetection(input: string, decoded: string, resolution: PathResolution): PathTraversalDetection | null {
    if (resolution.escapeDepth === 0) return null

    const hasMixedSlashes = /\//.test(input) && /\\/.test(input)
    const hasBackslashTraversal = /\.\\\.\./.test(decoded) || /\.{2}\\[^\\\n\r\s]+/.test(decoded)
    const hasDotPathChain = /\.\.(?:\\|\/|\.%2e)/i.test(input)
    const hasTripleDot = /\.{3,}(?:\\|\/)/.test(decoded)

    if (!hasMixedSlashes && !hasBackslashTraversal && !hasDotPathChain && !hasTripleDot) return null

    const evidence = [
        hasMixedSlashes ? 'mixed slashes' : null,
        hasBackslashTraversal ? 'backslash traversal segment' : null,
        hasDotPathChain ? 'dot-chain variant' : null,
        hasTripleDot ? 'triple-dot normalization' : null,
    ].filter(Boolean).join(', ')

    return {
        type: 'normalization_bypass',
        detail: `Path normalization variants detected: ${evidence}`,
        resolvedPath: resolution.resolvedPath,
        escapeDepth: resolution.escapeDepth,
        confidence: 0.84,
    }
}

function buildUncDetection(input: string): PathTraversalDetection | null {
    const decoded = (() => {
        try {
            return decodeURIComponent(input)
        } catch {
            return input
        }
    })()

    // UNC path such as `\\server\\share\\..\\secret`
    const uncPattern = /(?:^|[\s"'=:(])\\\\([A-Za-z0-9][A-Za-z0-9.-]{0,252})\\([A-Za-z0-9._$-]{1,252})(?:\\[^\s"'<>|&?]*)?/i

    const match = uncPattern.exec(decoded) ?? uncPattern.exec(input)
    if (!match) return null

    const raw = match[0].replace(/^[\s"'=:(]+/, '')
    const normalized = raw.replace(/^\\\\/, '').replace(/\\/g, '/')

    const hasWindowsSensitive = /(?:^|[/\\])(?:system32|win\.ini|sam|shadow|hosts|config|secrets?)/i.test(decoded)
    const hasWindowsDrive = /(?:[A-Za-z]:\\)/i.test(decoded)

    if (!hasWindowsSensitive && !hasWindowsDrive && !/\\\s*share/i.test(decoded)) {
        return {
            type: 'windows_traversal',
            detail: `UNC path candidate detected: ${normalized.slice(0, 100)}`,
            resolvedPath: normalized,
            escapeDepth: 0,
            confidence: 0.80,
        }
    }

    return {
        type: 'windows_traversal',
        detail: `UNC network/share traversal candidate: ${normalized.slice(0, 100)}`,
        resolvedPath: normalized,
        escapeDepth: 0,
        confidence: 0.94,
    }
}

function buildSymlinkChainDetection(decoded: string, resolution: PathResolution): PathTraversalDetection | null {
    if (decoded.includes('..') && /\.\.\\?\/symlink\\?\/\.\.\\?\/etc/i.test(decoded.replace(/%2e/gi, '.'))) {
        return {
            type: 'encoding_bypass',
            detail: 'Symlink chain abuse pattern: ../symlink/../etc',
            resolvedPath: resolution.resolvedPath,
            escapeDepth: Math.max(resolution.escapeDepth, 1),
            confidence: 0.88,
        }
    }
    return null
}

function buildFileUrlDetection(decoded: string): PathTraversalDetection | null {
    const fileTraversal = /^file:\/\/[\w.+-]*\/(?:\.\.)/i.test(decoded) || /file:\/\/[^\s]*[\\/]+\.\.[\\/]/i.test(decoded)
    if (!fileTraversal) return null

    const filePath = decoded.replace(/^file:\/\//i, '')
    const resolution = resolvePath(filePath)

    return {
        type: 'dotdot_escape',
        detail: 'file:// traversal style detected',
        resolvedPath: resolution.resolvedPath,
        escapeDepth: resolution.escapeDepth,
        confidence: resolution.targetsSensitiveFile ? 0.95 : 0.86,
    }
}

function uniqueDetections(detections: PathTraversalDetection[]): PathTraversalDetection[] {
    const seen = new Set<string>()
    const output: PathTraversalDetection[] = []
    for (const d of detections) {
        const key = `${d.type}|${d.resolvedPath}|${d.detail}|${d.escapeDepth}`
        if (seen.has(key)) continue
        seen.add(key)
        output.push(d)
    }
    return output
}


// ── Exported helpers (requested) ───────────────────────────────

export function detectNullBytePathTruncation(input: string): PathTraversalDetection[] {
    const { decoded } = deepDecode(input)
    const result = buildNullByteDetection(input, decoded)
    return result ? [result] : []
}

export function detectUNCPath(input: string): PathTraversalDetection[] {
    const result = buildUncDetection(input)
    return result ? [result] : []
}

export function detectDoubleEncoded(input: string): PathTraversalDetection[] {
    const { decoded, layers } = deepDecode(input)
    const resolution = resolvePath(decoded)
    if (layers < 2) return []

    const result = buildEncodingBypassDetection(input, decoded, layers, resolution)
    return result ? [result] : []
}


// ── Public API ───────────────────────────────────────────────────

export function detectPathTraversal(input: string): PathTraversalDetection[] {
    if (input.length < 3) return []

    const lowerInput = input.toLowerCase()
    const hasTraversalSignals =
        input.includes('..') ||
        lowerInput.includes('%2e') ||
        lowerInput.includes('%2f') ||
        lowerInput.includes('%5c') ||
        lowerInput.includes('%252') ||   // double URL-encoded (%25 = %)
        lowerInput.includes('%c0%ae') || // overlong UTF-8 dot
        lowerInput.includes('%u002') ||  // unicode escape for dot or slash
        input.includes('\\') ||
        lowerInput.startsWith('file://') ||
        lowerInput.includes('%2500')

    if (!hasTraversalSignals) return []

    if (lowerInput.startsWith('http://') || lowerInput.startsWith('https://') || lowerInput.startsWith('ftp://')) {
        return []
    }

    const { decoded, layers } = deepDecode(input)
    const resolution = resolvePath(decoded)
    const detections: PathTraversalDetection[] = []

    const candidates = [
        buildFileUrlDetection(decoded),
        buildDotdotTraversalDetection(decoded, resolution),
        buildNullByteDetection(input, decoded),
        buildEncodingBypassDetection(input, decoded, layers, resolution),
        buildNormalizationDetection(input, decoded, resolution),
        buildUncDetection(input),
        buildSymlinkChainDetection(decoded, resolution),
    ]
    for (const c of candidates) { if (c !== null) detections.push(c) }

    if (/\bwindows\b/i.test(resolution.resolvedPath) && resolution.escapeDepth > 0) {
        // Windows path traversal variants reaching known targets should stay separate.
        detections.push({
            type: 'windows_traversal',
            detail: `Windows-sensitive path candidate: ${resolution.resolvedPath || 'rooted windows target'}`,
            resolvedPath: resolution.resolvedPath,
            escapeDepth: resolution.escapeDepth,
            confidence: 0.92,
        })
    }

    for (const sensitiveTarget of WINDOWS_TARGETS) {
        if (resolution.resolvedPath.toLowerCase().endsWith(`/${sensitiveTarget}`)) {
            detections.push({
                type: 'windows_traversal',
                detail: `Windows sensitive target matched: ${sensitiveTarget}`,
                resolvedPath: resolution.resolvedPath,
                escapeDepth: resolution.escapeDepth,
                confidence: 0.95,
            })
            break
        }
    }

    return uniqueDetections(detections.filter(Boolean) as PathTraversalDetection[])
}
