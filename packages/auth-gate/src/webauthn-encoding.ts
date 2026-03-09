export function encodeBase64(buffer: ArrayBuffer | Uint8Array): string {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer)
    let text = ''
    for (let i = 0; i < bytes.length; i += 1) {
        text += String.fromCharCode(bytes[i])
    }

    return btoa(text)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/g, '')
}

export function decodeBase64Url(value: string): Uint8Array {
    const normalized = value.replace(/-/g, '+').replace(/_/g, '/')
    const padLength = (4 - (normalized.length % 4)) % 4
    const padded = normalized + '===='.slice(0, padLength)
    return Uint8Array.from(atob(padded), character => character.charCodeAt(0))
}
