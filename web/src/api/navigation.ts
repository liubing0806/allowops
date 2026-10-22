// OIDC start is a gateway HTTP endpoint, so it requires document navigation.
export function redirectToLogin(authorizationUrl: string) {
  window.location.assign(authorizationUrl)
}
