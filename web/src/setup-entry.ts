import type { GroveRealm } from './grove-invitation'

export function parseSetupEntry(hash: string): { token: string; realm?: GroveRealm } {
  const match = /^#\/setup\/([A-Za-z0-9_-]{43})(?:\?(.*))?$/.exec(hash)
  if (!match) return { token: '' }
  const entry = { token: match[1] }
  const encoded = new URLSearchParams(match[2]).get('grove')
  if (!encoded || encoded.length > 8192) return entry
  try {
    const realm = JSON.parse(encoded)
    if (realm?.version === 1 && typeof realm.id === 'string' && typeof realm.name === 'string'
        && typeof realm.issuer_origin === 'string' && typeof realm.issuer_node === 'string'
        && typeof realm.public_key === 'string') return { ...entry, realm }
  } catch { return entry }
  return entry
}
