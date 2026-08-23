/** Platform package name keyed by `${process.platform}-${process.arch}`. */
export const PLATFORM_PACKAGES: Record<string, string>;

/** `fhec.exe` on win32, otherwise `fhec`. */
export const BINARY_NAME: string;

/**
 * Builds the "could not find the native binary" error text, including every
 * location that was tried and the same fix hints the CLI wrapper prints.
 */
export function formatResolveFailure(tried: string[]): string;

/**
 * Attempts every resolution strategy in order.
 * Returns `{ binaryPath }` on success, or throws with a message listing every
 * location that was tried.
 */
export function resolveBinary(): { binaryPath: string };
