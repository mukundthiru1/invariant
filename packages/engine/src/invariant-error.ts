export type InvariantErrorPhase = 'l1' | 'l2' | 'l3' | 'registry'

export interface InvariantErrorOptions {
    code: string
    classId?: string
    phase: InvariantErrorPhase
    cause?: unknown
}

export class InvariantError extends Error {
    readonly code: string
    readonly classId?: string
    readonly phase: InvariantErrorPhase

    constructor(message: string, options: InvariantErrorOptions) {
        super(message, options.cause !== undefined ? { cause: options.cause } : undefined)
        this.name = 'InvariantError'
        this.code = options.code
        this.classId = options.classId
        this.phase = options.phase
    }
}
