import { ApiError, api } from './api'
import { groveVerificationOrigins, invitationRealm, isSignedGroveInvitation, type GroveRealm } from './grove-invitation'

export async function startBrowserJoin(code: string, legacyRealm: GroveRealm | undefined, {
  headers, setupToken,
}: { headers: Record<string, string>; setupToken?: string | null }) {
  const signed = isSignedGroveInvitation(code)
  const invitation = signed ? await api<{ realm: GroveRealm; origins: string[] }>('/auth/grove/invitation/candidates', {
    method: 'POST', headers, body: JSON.stringify({ code: code.trim() }),
  }) : legacyRealm ? { realm: invitationRealm(legacyRealm),
    origins: groveVerificationOrigins([legacyRealm.issuer_origin], location.origin) } : undefined
  if (!invitation?.origins.length) throw new ApiError(400, 'Copy a new Grove invitation', 'GROVE_INVITATION_NEEDS_REFRESH')
  const verification_origin = invitation.origins.find(origin => origin === invitation.realm.issuer_origin)
  if (!verification_origin) throw new ApiError(400, 'Copy a new Grove invitation', 'GROVE_INVITATION_NEEDS_REFRESH')
  return api<{ authorize_url: string }>('/auth/grove/start', {
    method: 'POST', headers,
    body: JSON.stringify({ kind: 'join', realm: invitation.realm, verification_origin, setup_token: setupToken,
      invitation_code: signed ? code.trim() : undefined }),
  })
}
