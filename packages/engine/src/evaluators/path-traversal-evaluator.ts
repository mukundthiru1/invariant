/**
 * Path Traversal Evaluator — Level 2 Invariant Detection
 *
 * The invariant property for path traversal is:
 *   resolve(normalize(decode(input))) ESCAPES webroot
 *   ∨ input CONTAINS null_byte ∧ input CONTAINS file_extension
 *   ∨ encoding_layers(input) > 1 ∧ resolved_path ∈ SENSITIVE_FILES
 *
 * This module evaluates the actual path resolution instead of
 * matching "../" patterns with regex. Key advantage: it handles
 * ALL encoding combinations (double URL, Unicode, overlong UTF-8,
 * mixed slash) by fully decoding first, then resolving the path.
 *
 * Covers:
 *   - path_dotdot_escape:        resolved path escapes root directory
 *   - path_null_terminate:       null byte truncates file extension
 *   - path_encoding_bypass:      multi-layer encoding hides traversal
 *   - path_normalization_bypass: mixed slashes / dot sequences bypass checks
 */


// ── Result Type ──────────────────────────────────────────────────

export interface PathTraversalDetection {
    type: 'dotdot_escape' | 'null_terminate' | 'encoding_bypass' | 'normalization_bypass'
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


// ── Multi-layer Decoder ──────────────────────────────────────────
//
// Attackers use multiple encoding layers to bypass WAF decoders:
//   - URL encoding:     %2e%2e%2f  → ../
//   - Double URL:       %252e%252e → %2e%2e → ..
//   - Unicode:          %u002e     → .
//   - Overlong UTF-8:   %c0%ae     → .
//   - HTML entities:    &#46;      → .
//
// We decode iteratively until stable (no more decoding changes).

function deepDecode(input: string, maxIterations: number = 5): { decoded: string; layers: number } {
    let current = input
    let layers = 0

    for (let i = 0; i < maxIterations; i++) {
        let next = current

        // URL decode (%XX)
        try {
            next = decodeURIComponent(next)
        } catch {
            // Handle partial encoding: decode only valid sequences
            next = next.replace(/%([0-9a-fA-F]{2})/g, (_, hex) => {
                return String.fromCharCode(parseInt(hex, 16))
            })
        }

        // Overlong UTF-8 dot: %c0%ae → . (U+002E)
        next = next.replace(/\xc0\xae/g, '.')

        // Unicode encoding: %u002e
        next = next.replace(/%u([0-9a-fA-F]{4})/gi, (_, hex) => {
            return String.fromCharCode(parseInt(hex, 16))
        })

        // HTML entities
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


// ── Path Resolver ────────────────────────────────────────────────
//
// The core invariant evaluation: resolve the path and determine
// whether it escapes the root directory.
//
// We don't need to know the actual webroot. The property is:
//   "Does the path contain enough '..' segments to escape
//    whatever root directory it starts in?"
//
// Resolution algorithm:
//   1. Normalize all slashes (\ → /)
//   2. Split into segments
//   3. Walk segments: '.' stays, '..' pops, else push
//   4. Count how many '..' segments escape above index 0

interface PathResolution {
    /** Number of '..' segments that escape above the starting directory */
    escapeDepth: number
    /** The normalized resolved path */
    resolvedPath: string
    /** Whether the resolved path targets a known sensitive file */
    targetsSensitiveFile: boolean
    /** The sensitive file matched (if any) */
    sensitiveFile: string | null
}

function resolvePath(decoded: string): PathResolution {
    // Normalize slashes
    const normalized = decoded.replace(/\\/g, '/')

    // Split into segments, ignoring empty segments (consecutive slashes)
    const segments = normalized.split('/').filter(s => s.length > 0)
    const resolved: string[] = []
    let escapeDepth = 0

    for (const segment of segments) {
        if (segment === '.' || segment === '') {
            continue
        } else if (segment === '..') {
            if (resolved.length > 0) {
                resolved.pop()
            } else {
                escapeDepth++
            }
        } else {
            resolved.push(segment)
        }
    }

    const resolvedPath = resolved.join('/')
    const resolvedLower = resolvedPath.toLowerCase()

    // Check if final path matches a sensitive file
    let sensitiveFile: string | null = null
    for (const target of SENSITIVE_TARGETS) {
        if (resolvedLower === target || resolvedLower.endsWith('/' + target)) {
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


// ── Detection Functions ──────────────────────────────────────────

function detectDotdotEscape(input: string, decoded: string, resolution: PathResolution): PathTraversalDetection | null {
    if (resolution.escapeDepth > 0) {
        const targetInfo = resolution.targetsSensitiveFile
            ? ` → targets ${resolution.sensitiveFile}`
            : ''

        return {
            type: 'dotdot_escape',
            detail: `Path escapes root by ${resolution.escapeDepth} level(s)${targetInfo}`,
            resolvedPath: resolution.resolvedPath,
            escapeDepth: resolution.escapeDepth,
            confidence: resolution.targetsSensitiveFile ? 0.95 : 0.85,
        }
    }
    return null
}

function detectNullTerminate(input: string, decoded: string): PathTraversalDetection | null {
    // Null byte terminates C-string path handling, allowing extension bypass
    // Input: ../../../etc/passwd%00.png → server reads etc/passwd
    const nullIndex = decoded.indexOf('\0')
    // Also check for literal %00 in original input (some servers don't decode)
    const hasRawNullEncoding = input.includes('%00')

    if (nullIndex === -1 && !hasRawNullEncoding) {
        return null
    }

    // Check if there's path content before the null and an extension after
    const beforeNull = decoded.substring(0, nullIndex >= 0 ? nullIndex : decoded.length)
    const hasTraversalBefore = beforeNull.includes('..')
    const hasExtensionAfter = nullIndex >= 0 && /\.[a-z]{1,10}$/i.test(decoded.substring(nullIndex))

    if (hasTraversalBefore || (nullIndex >= 0 && hasExtensionAfter)) {
        return {
            type: 'null_terminate',
            detail: `Null byte in path — truncates file extension validation`,
            resolvedPath: beforeNull,
            escapeDepth: 0,
            confidence: 0.90,
        }
    }
    return null
}

function detectEncodingBypass(input: string, decoded: string, layers: number, resolution: PathResolution): PathTraversalDetection | null {
    // Multi-layer encoding used to hide traversal sequences
    if (layers > 1 && resolution.escapeDepth > 0) {
        return {
            type: 'encoding_bypass',
            detail: `${layers}-layer encoding hides traversal (decoded: ${decoded.slice(0, 80)})`,
            resolvedPath: resolution.resolvedPath,
            escapeDepth: resolution.escapeDepth,
            confidence: 0.92,
        }
    }

    // Single layer but uses non-standard encoding for dots/slashes
    if (layers >= 1 && resolution.escapeDepth > 0) {
        const hasObfuscatedDot = /(%2e|%u002e|%c0%ae|&#46;|&period;)/i.test(input)
        const hasObfuscatedSlash = /(%2f|%5c|%u002f|&#47;|&sol;)/i.test(input)

        if (hasObfuscatedDot || hasObfuscatedSlash) {
            return {
                type: 'encoding_bypass',
                detail: `Encoded traversal chars (dot: ${hasObfuscatedDot}, slash: ${hasObfuscatedSlash})`,
                resolvedPath: resolution.resolvedPath,
                escapeDepth: resolution.escapeDepth,
                confidence: 0.88,
            }
        }
    }

    return null
}

function detectNormalizationBypass(input: string, decoded: string, resolution: PathResolution): PathTraversalDetection | null {
    if (resolution.escapeDepth === 0) return null

    // Mixed slash types: using \ and / together
    const hasMixedSlashes = /[/]/.test(input) && /[\\]/.test(input)

    // Dot-dot-backslash: ..\..\ (Windows-style traversal on Linux)
    const hasBackslashTraversal = /\.\.\\/.test(input)

    // Dot-slash sequences: ./ repeated
    const hasDotSlash = /\.\/\.\./.test(decoded) || /\.\\\.\./.test(decoded)

    // Triple-dot: .../ is sometimes interpreted as ../
    const hasTripleDot = /\.{3,}[/\\]/.test(input)

    if (hasMixedSlashes || hasBackslashTraversal || hasDotSlash || hasTripleDot) {
        const techniques: string[] = []
        if (hasMixedSlashes) techniques.push('mixed slashes')
        if (hasBackslashTraversal) techniques.push('backslash traversal')
        if (hasTripleDot) techniques.push('triple-dot')

        return {
            type: 'normalization_bypass',
            detail: `Path normalization evasion: ${techniques.join(', ')}`,
            resolvedPath: resolution.resolvedPath,
            escapeDepth: resolution.escapeDepth,
            confidence: 0.85,
        }
    }

    return null
}


// ── Public API ───────────────────────────────────────────────────

/**
 * Detect path traversal vectors by resolving the actual path
 * and checking the invariant properties.
 */
export function detectPathTraversal(input: string): PathTraversalDetection[] {
    const detections: PathTraversalDetection[] = []

    // Don't waste time on short inputs or inputs without path-like chars
    if (input.length < 3) return detections
    if (!input.includes('.') && !input.includes('%') && !input.includes('\\')) {
        return detections
    }

    // Bail on URL-like inputs — these are SSRF territory, not path traversal.
    // Without this, http://example.com/../../etc/passwd would match as path traversal.
    const trimmed = input.trimStart().toLowerCase()
    if (trimmed.startsWith('http://') || trimmed.startsWith('https://') || trimmed.startsWith('ftp://')) {
        return detections
    }

    const { decoded, layers } = deepDecode(input)
    const resolution = resolvePath(decoded)

    const detectors: Array<() => PathTraversalDetection | null> = [
        () => detectDotdotEscape(input, decoded, resolution),
        () => detectNullTerminate(input, decoded),
        () => detectEncodingBypass(input, decoded, layers, resolution),
        () => detectNormalizationBypass(input, decoded, resolution),
    ]

    for (const detector of detectors) {
        try {
            const result = detector()
            if (result) detections.push(result)
        } catch { /* never crash the pipeline */ }
    }

    return detections
}
