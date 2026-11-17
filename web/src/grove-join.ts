import { ApiError, api } from './api'
import { groveVerificationOrigins, invitationRealm, isSignedGroveInvitation, type GroveRealm } from './grove-invitation'

async function readyVerifier(origins: string[], realm: GroveRealm) {
  const controller = new AbortController()
  const timeout = AbortSignal.timeout(4000)
  const signal = AbortSignal.any([controller.signal, timeout])
  const query = new URLSearchParams({ realm_id: realm.id, public_key: realm.public_key })
  try {
    return await Promise.any(origins.map(async origin => {
      const response = await fetch(`${origin}/api/v1/auth/grove/verification-status?${query}`, {
        credentials: 'omit', cache: 'no-store', redirect: 'error', signal,
      })
      if (!response.ok) throw new Error('Verifier unavailable')
      const result = await response.json()
      if (result.ready !== true || result.realm_id !== realm.id || result.public_key !== realm.public_key || result.origin !== origin)
        throw new Error('Verifier belongs to another panel or Grove')
      return origin
    }))
  } catch {
    throw new ApiError(503, 'No ready Grove verifier', 'GROVE_NO_VERIFIER')
  } finally {
    controller.abort()
  }
}

export async function startBrowserJoin(code: string, legacyRealm: GroveRealm | undefined, {
  headers, setupToken,
}: { headers: Record<string, string>; setupToken?: string | null }) {
  const signed = isSignedGroveInvitation(code)
  const invitation = signed ? await api<{ realm: GroveRealm; origins: string[] }>('/auth/grove/invitation/candidates', {
    method: 'POST', headers, body: JSON.stringify({ code: code.trim() }),
  }) : legacyRealm ? { realm: invitationRealm(legacyRealm),
    origins: groveVerificationOrigins([legacyRealm.issuer_origin], location.origin) } : undefined
  if (!invitation?.origins.length) throw new ApiError(400, 'Copy a new Grove invitation', 'GROVE_INVITATION_NEEDS_REFRESH')
  const verification_origin = await readyVerifier(invitation.origins, invitation.realm)
  return api<{ authorize_url: string }>('/auth/grove/start', {
    method: 'POST', headers,
    body: JSON.stringify({ kind: 'join', realm: invitation.realm, verification_origin, setup_token: setupToken,
      invitation_code: signed ? code.trim() : undefined }),
  })
}
