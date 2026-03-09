import { describe, it, expect } from 'vitest'
import { l2WindowsPathTraversal } from './l2-adapters.js'

describe('l2WindowsPathTraversal', () => {
    it('detects Windows backslash traversal', () => {
        const payload = '..\\..\\Windows\\System32'
        const result = l2WindowsPathTraversal(payload, payload)
        expect(result).not.toBeNull()
        expect(result!.detected).toBe(true)
    })

    it('detects UNC path injection', () => {
        const payload = '\\\\evil.com\\share'
        const result = l2WindowsPathTraversal(payload, payload)
        expect(result).not.toBeNull()
        expect(result!.detected).toBe(true)
        expect(result!.confidence).toBe(0.92)
    })

    it('detects zip slip traversal entries', () => {
        const payload = 'archive.zip/../../../etc/passwd'
        const result = l2WindowsPathTraversal(payload, payload)
        expect(result).not.toBeNull()
        expect(result!.detected).toBe(true)
    })

    it('detects NTFS ADS path injection', () => {
        const payload = 'file.txt::DATA'
        const result = l2WindowsPathTraversal(payload, payload)
        expect(result).not.toBeNull()
        expect(result!.detected).toBe(true)
        expect(result!.confidence).toBe(0.85)
    })

    it('detects null-byte extension bypass', () => {
        const payload = 'file.txt%00.php'
        const result = l2WindowsPathTraversal(payload, payload)
        expect(result).not.toBeNull()
        expect(result!.detected).toBe(true)
        expect(result!.confidence).toBe(0.85)
    })

    it('does not flag normal Windows file paths', () => {
        const payload = 'C:\\Users\\file.txt'
        expect(l2WindowsPathTraversal(payload, payload)).toBeNull()
    })
})
