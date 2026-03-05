/**
 * SQL Injection Invariant Classes — Barrel Export
 *
 * 7 classes covering the complete SQL injection attack surface:
 *   1. String termination (context escape)
 *   2. Tautology (WHERE bypass)
 *   3. UNION extraction (data exfiltration)
 *   4. Stacked execution (arbitrary statements)
 *   5. Time oracle (blind detection)
 *   6. Error oracle (error-based extraction)
 *   7. Comment truncation (query tail removal)
 */

import type { InvariantClassModule } from '../types.js'
import { sqlStringTermination } from './string-termination.js'
import { sqlTautology } from './tautology.js'
import { sqlUnionExtraction } from './union-extraction.js'
import { sqlStackedExecution } from './stacked-execution.js'
import { sqlTimeOracle } from './time-oracle.js'
import { sqlErrorOracle } from './error-oracle.js'
import { sqlCommentTruncation } from './comment-truncation.js'

export const SQL_CLASSES: InvariantClassModule[] = [
    sqlStringTermination,
    sqlTautology,
    sqlUnionExtraction,
    sqlStackedExecution,
    sqlTimeOracle,
    sqlErrorOracle,
    sqlCommentTruncation,
]

export {
    sqlStringTermination,
    sqlTautology,
    sqlUnionExtraction,
    sqlStackedExecution,
    sqlTimeOracle,
    sqlErrorOracle,
    sqlCommentTruncation,
}
