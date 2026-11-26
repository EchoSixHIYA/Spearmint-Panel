import { memberPanelOrigin } from './grove-directory.ts'

export type GroveRealm = { version: 1; id: string; name: string; public_key: string; issuer_node: string; issuer_origin: string }
export type GroveInvitation = GroveRealm & { verification_origins?: string[] }

const basePrefix = 'grove1.'
const memberPrefix = 'grove2.'
export const MAX_GROVE_INVITATION_LENGTH = 128 * 1024
const pendingJoinKey = 'spearmint-quorum-invitation'
const pendingJoinAge = 15 * 60 * 1000

export function isQuorumInvitation(value: string) {
  const code = value.trim()
  return isAutomaticQuorumInvitation(code) || (code.length <= 8192 && /^grove4\.[A-Za-z0-9_-]+$/.test(code))
}

export function isAutomaticQuorumInvitation(value: string) {
  const code = value.trim()
  return code.length <= MAX_GROVE_INVITATION_LENGTH && /^grove5\.[A-Za-z0-9_-]+$/.test(code)
}

export function rememberQuorumInvitation(code: string) {
  try { sessionStorage.setItem(pendingJoinKey, JSON.stringify({ code: code.trim(), expires: Date.now() + pendingJoinAge })) } catch { /* The code can be pasted again after setup. */ }
}

export function takeQuorumInvitation() {
  try {
    const raw = sessionStorage.getItem(pendingJoinKey)
    sessionStorage.removeItem(pendingJoinKey)
    if (!raw) return ''
    const { code, expires } = JSON.parse(raw)
    return typeof code === 'string' && Date.now() < expires && isQuorumInvitation(code) ? code : ''
  } catch { return '' }
}

export function isSignedGroveInvitation(value: string) {
  const code = value.trim()
  return code.length <= 8192 && /^grove3\.[A-Za-z0-9_-]+$/.test(code)
}

export function groveVerificationOrigins(values: readonly string[], localOrigin?: string) {
  return [...new Set(values.map(memberPanelOrigin).filter((origin): origin is string => {
    if (!origin || origin === localOrigin || origin.length > 512) return false
    const host = new URL(origin).hostname.replace(/\.$/, '')
    return host !== 'localhost' && !host.endsWith('.localhost') && !host.startsWith('127.')
      && host !== '[::1]' && host !== '[::]' && host !== '0.0.0.0'
  }))].slice(0, 8)
}

export function invitationRealm(realm: GroveInvitation): GroveRealm {
  const { version, id, name, public_key, issuer_node, issuer_origin } = realm
  return { version, id, name, public_key, issuer_node, issuer_origin }
}

export function encodeGroveInvitation(realm: GroveRealm, origins: readonly string[] = []) {
  const verification_origins = groveVerificationOrigins(origins)
  const record = invitationRealm(realm)
  const bytes = new TextEncoder().encode(JSON.stringify(verification_origins.length ? { ...record, verification_origins } : record))
  return (verification_origins.length ? memberPrefix : basePrefix)
    + btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '')
}

export function parseGroveInvitation(value: string): GroveInvitation | undefined {
  const code = value.trim()
  const withMembers = code.startsWith(memberPrefix)
  if (code.length > 8192 || (!withMembers && !code.startsWith(basePrefix))) return
  const encoded = code.slice(basePrefix.length)
  if (!/^[A-Za-z0-9_-]+$/.test(encoded)) return
  try {
    const bytes = Uint8Array.from(atob(encoded.replaceAll('-', '+').replaceAll('_', '/')), (char) => char.charCodeAt(0))
    const realm: Partial<GroveInvitation> | null = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
    if (realm?.version === 1 && Object.keys(realm).length === (withMembers ? 7 : 6)
        && typeof realm.id === 'string' && /^grv1-[a-f0-9]{32}$/.test(realm.id)
        && typeof realm.name === 'string' && realm.name.trim() && [...realm.name].length <= 40
        && typeof realm.public_key === 'string' && /^[A-Za-z0-9_-]{43}$/.test(realm.public_key)
        && typeof realm.issuer_node === 'string' && /^spm1-[a-f0-9]{64}$/.test(realm.issuer_node)
        && typeof realm.issuer_origin === 'string' && memberPanelOrigin(realm.issuer_origin) === realm.issuer_origin) {
      if (withMembers) {
        const origins = realm.verification_origins
        if (!Array.isArray(origins) || !origins.length || origins.length > 8
            || origins.some(origin => typeof origin !== 'string' || origin.length > 512 || memberPanelOrigin(origin) !== origin)) return
      }
      return realm as GroveInvitation
    }
  } catch {
    return
  }
}
