/**
 * 
 * @param value Any value can be passed to check whether the value is valid or invalid
 * @returns 
 */

export function isInvalid(value: unknown): boolean {
    return (
      value === null || 
      value === undefined || 
      (typeof value === "string" && value.trim() === "") || 
      (Array.isArray(value) && value.length === 0) || 
      (typeof value === "object" && Object.keys(value || {}).length === 0) ||
      (typeof value === "number" && isNaN(value))
    );
}