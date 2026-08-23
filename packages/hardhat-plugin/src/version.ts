/**
 * Profile version matching for FHE5003.
 *
 * A profile pin of the form `X.Y.x` means `>=X.Y.0 <X.(Y+1).0`.
 * Anything else is compared as an exact string (or as a prefix followed by `.`).
 */

export interface ParsedSemver {
  major: number;
  minor: number;
  patch: number;
}

/**
 * Parses a leading `X.Y.Z` from an npm version string. Returns `undefined`
 * when the string is not a recognizable semver.
 */
export function parseSemver(version: string): ParsedSemver | undefined {
  const match = /^v?(\d+)\.(\d+)\.(\d+)/.exec(version.trim());
  if (match === null) {
    return undefined;
  }
  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
  };
}

/**
 * Whether `installed` satisfies the pinned profile version.
 *
 * `0.2.x` accepts `0.2.0` and rejects `0.1.5`.
 */
export function versionSatisfies(profileVersion: string, installed: string): boolean {
  const pin = profileVersion.trim();
  const wildcard = /^(\d+)\.(\d+)\.x$/.exec(pin);
  if (wildcard !== null) {
    const parsed = parseSemver(installed);
    if (parsed === undefined) {
      return false;
    }
    return parsed.major === Number(wildcard[1]) && parsed.minor === Number(wildcard[2]);
  }
  const installedTrimmed = installed.trim();
  return installedTrimmed === pin || installedTrimmed.startsWith(`${pin}.`);
}

/**
 * Reads `@fhenixprotocol/cofhe-contracts/package.json` from `projectRoot`.
 * Returns `undefined` when the package is not installed (solc will fail on
 * the import; we do not hard-fail here).
 */
export function readInstalledCofheVersion(
  projectRoot: string,
  resolver: (request: string, paths: string[]) => string = defaultResolve,
  readJson: (filePath: string) => { version?: unknown } = defaultReadJson,
): string | undefined {
  let pkgJsonPath: string;
  try {
    pkgJsonPath = resolver("@fhenixprotocol/cofhe-contracts/package.json", [projectRoot]);
  } catch {
    return undefined;
  }
  const version = readJson(pkgJsonPath).version;
  return typeof version === "string" && version.length > 0 ? version : undefined;
}

function defaultResolve(request: string, paths: string[]): string {
  return require.resolve(request, { paths });
}

function defaultReadJson(filePath: string): { version?: unknown } {
  return require(filePath) as { version?: unknown };
}
