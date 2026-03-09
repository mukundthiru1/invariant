export interface SbomComponent {
  name: string
  version: string
  purl: string
  license: string
}

export interface SbomVersionChange {
  from: SbomComponent
  to: SbomComponent
}

export interface SbomLicenseChange {
  from: SbomComponent
  to: SbomComponent
}

export interface SbomDiff {
  added: SbomComponent[]
  removed: SbomComponent[]
  versionChanged: SbomVersionChange[]
  licenseChanged: SbomLicenseChange[]
}

function byPackageIdentity(component: SbomComponent): string {
  const trimmedPurl = component.purl.trim()
  if (trimmedPurl) {
    const atIdx = trimmedPurl.lastIndexOf('@')
    if (atIdx > 0) return trimmedPurl.slice(0, atIdx)
    return trimmedPurl
  }
  return component.name.trim().toLowerCase()
}

function sortComponents(components: SbomComponent[]): SbomComponent[] {
  return [...components].sort((a, b) => {
    const nameCompare = a.name.localeCompare(b.name)
    if (nameCompare !== 0) return nameCompare
    return a.version.localeCompare(b.version)
  })
}

export async function diffSbom(previous: SbomComponent[], current: SbomComponent[]): Promise<SbomDiff> {
  const previousMap = new Map<string, SbomComponent>()
  for (const component of previous) {
    previousMap.set(byPackageIdentity(component), component)
  }

  const currentMap = new Map<string, SbomComponent>()
  for (const component of current) {
    currentMap.set(byPackageIdentity(component), component)
  }

  const added: SbomComponent[] = []
  const removed: SbomComponent[] = []
  const versionChanged: SbomVersionChange[] = []
  const licenseChanged: SbomLicenseChange[] = []

  for (const [key, currentComponent] of currentMap) {
    const previousComponent = previousMap.get(key)
    if (!previousComponent) {
      added.push(currentComponent)
      continue
    }

    if (previousComponent.version !== currentComponent.version) {
      versionChanged.push({ from: previousComponent, to: currentComponent })
    }

    if (previousComponent.license !== currentComponent.license) {
      licenseChanged.push({ from: previousComponent, to: currentComponent })
    }
  }

  for (const [key, previousComponent] of previousMap) {
    if (!currentMap.has(key)) {
      removed.push(previousComponent)
    }
  }

  return {
    added: sortComponents(added),
    removed: sortComponents(removed),
    versionChanged,
    licenseChanged,
  }
}
