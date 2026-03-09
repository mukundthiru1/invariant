import {
  ALL_CLASS_MODULES,
  InvariantEngine,
  type InvariantMatch,
  type InvariantClassModule,
} from '@santh/invariant-engine'

export interface ScanResult {
  line: string
  lineNumber: number
  file: string
  matches: InvariantMatch[]
}

function createEngineOrNull(): InvariantEngine | null {
  try {
    return new InvariantEngine()
  } catch (error) {
    console.warn('[deploy-gate] InvariantEngine initialization failed, using resilient class detection fallback', error)
    return null
  }
}

const engine = createEngineOrNull()

function getModuleBaseConfidence(module: InvariantClassModule): number {
  const raw =
    module.calibration && typeof module.calibration === 'object' && 'baseConfidence' in module.calibration
      ? module.calibration.baseConfidence
      : 0.85

  return typeof raw === 'number' && Number.isFinite(raw)
    ? Math.max(0, Math.min(1, raw))
    : 0.85
}

function scanWithModuleFallback(line: string): InvariantMatch[] {
  const matches: InvariantMatch[] = []

  for (const module of ALL_CLASS_MODULES as InvariantClassModule[]) {
    try {
      if (!module.detect(line)) continue

      matches.push({
        class: module.id,
        confidence: getModuleBaseConfidence(module),
        category: module.category,
        severity: module.severity,
        isNovelVariant: true,
        description: module.description,
        detectionLevels: {
          l1: true,
          l2: false,
          convergent: false,
        },
      })
    } catch {
      // Ignore individual class runtime errors and continue scanning.
    }
  }

  return matches
}

export function scanDiff(lines: string[]): ScanResult[] {
  return lines.map((line, index) => ({
    line,
    lineNumber: index + 1,
    file: 'unknown',
    matches: engine ? engine.detect(line, [], 'deploy-gate') : scanWithModuleFallback(line),
  }))
}
