import { describe, expect, it } from 'vitest'
import {
    detectSecondOrderPayloadStore,
    detectSecondOrderTriggerPattern,
} from './second-order.js'

describe('second-order SQLi helper detectors', () => {
    it('detects second-order stored payload in INSERT value using SELECT', () => {
        const detection = detectSecondOrderPayloadStore("INSERT INTO audit_events (payload) VALUES ('SELECT id, role FROM users')")
        expect(detection).not.toBeNull()
        expect(detection?.type).toBe('second_order_payload_store')
        expect(detection?.confidence).toBe(0.88)
    })

    it('detects second-order stored payload in UPDATE value using UNION', () => {
        const detection = detectSecondOrderPayloadStore("UPDATE users SET profile='bio UNION SELECT password FROM users WHERE id=1' WHERE id=1")
        expect(detection).not.toBeNull()
        expect(detection?.type).toBe('second_order_payload_store')
    })

    it('detects second-order stored payload in INSERT value using EXEC', () => {
        const detection = detectSecondOrderPayloadStore("INSERT INTO comments (body) VALUES ('EXEC xp_cmdshell ''whoami''')")
        expect(detection).not.toBeNull()
        expect(detection?.type).toBe('second_order_payload_store')
        expect(detection?.evidence.toLowerCase()).toContain('insert into comments')
    })

    it('detects concatenated trigger execution chain', () => {
        const detection = detectSecondOrderTriggerPattern("CREATE PROCEDURE rotate_user_pwd AS DECLARE @sql VARCHAR(200); SET @sql = 'UPDATE users ' + 'SET role=' + 'admin'; EXEC(@sql)")
        expect(detection).not.toBeNull()
        expect(detection?.type).toBe('second_order_trigger_pattern')
        expect(detection?.confidence).toBe(0.9)
    })

    it('detects trigger concatenation with double bar operator', () => {
        const detection = detectSecondOrderTriggerPattern("CREATE FUNCTION dbo.bad_fn() RETURNS INT AS BEGIN DECLARE @q VARCHAR(100); SET @q = 'SELECT ' || @payload; EXECUTE @q; END")
        expect(detection).not.toBeNull()
        expect(detection?.type).toBe('second_order_trigger_pattern')
        expect(detection?.evidence.toLowerCase()).toContain('create function')
    })

    it('does not flag non-concatenated create procedure execution', () => {
        const detection = detectSecondOrderTriggerPattern("CREATE PROCEDURE safe_cleanup AS EXEC archive_old_rows")
        expect(detection).toBeNull()
    })
})
