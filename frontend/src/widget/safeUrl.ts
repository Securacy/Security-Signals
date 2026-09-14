/**
 * Validate a backend-supplied URL is safe to render as a clickable link.
 * Evidence source_url values are external, backend-stored strings - never
 * trust them as link-safe without checking the scheme first, since a
 * "javascript:" or other non-http(s) scheme could otherwise execute on
 * click.
 */
export function isSafeExternalUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "https:" || url.protocol === "http:";
  } catch {
    return false;
  }
}
