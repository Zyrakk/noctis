export async function request(path, options = {}) {
  const response = await fetch(`/api/v2${path}`, { credentials: 'same-origin', ...options,
    headers: { 'Accept': 'application/json', ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...options.headers } })
  if (response.status === 401) window.dispatchEvent(new Event('noctis:unauthorized'))
  let body
  try { body = await response.json() } catch { const error = new Error('The server returned an invalid response'); error.status = response.status; throw error }
  if (!response.ok) { const error = new Error(body.error?.message || body.error?.code || 'Unable to complete the request'); error.status = response.status; error.currentRevision=body.error?.current_revision; throw error }
  return body
}

export function validEvidenceRef(ref) {
  return ref !== null && typeof ref === 'object' && !Array.isArray(ref) &&
    ['observation_id','revision','hash','representation'].every(key => typeof ref[key] === 'string' && ref[key].trim().length > 0) &&
    Number.isSafeInteger(ref.start) && Number.isSafeInteger(ref.end) && ref.start >= 0 && ref.end >= ref.start
}

// Offsets are UTF-8 bytes, never JavaScript UTF-16 indices. Invalid boundaries fail closed.
export function evidenceParts(text, start, end) {
  const bytes = new TextEncoder().encode(text)
  if (typeof text !== 'string' || !Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start < 0 || end < start || end > bytes.length) throw new Error('Invalid citation range')
  const decoder = new TextDecoder('utf-8', { fatal: true })
  return [decoder.decode(bytes.slice(0, start)), decoder.decode(bytes.slice(start, end)), decoder.decode(bytes.slice(end))]
}
