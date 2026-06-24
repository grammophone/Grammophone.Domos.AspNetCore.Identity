# Grammophone.Domos.AspNetCore.Identity

`Grammophone.Domos.AspNetCore.Identity` adapts Domos users to ASP.NET Core Identity.

The package lets an ASP.NET Core application use users stored in an `IUsersDomainContainer<U>` as Identity users while preserving Domos roles, registrations, browser sessions, WebAuthn credentials and security claims.

## Main Features

- `UserStore<UB, U, D>` implements ASP.NET Core Identity user, login, password, role, email, lockout, two-factor and security-stamp store interfaces.
- `RoleStore<UB, U, D>` exposes Domos roles to ASP.NET Core Identity.
- `WebAuthnCredentialsStore` stores passkey/WebAuthn credentials in the Domos domain model.
- `BrowserSessionUserStore`, `BrowserSessionSignInManager`, `BrowserSessionClaimsPrincipalFactory` and `BrowserSessionSecurityStampValidator` add browser-session-aware identity behavior.
- `EncryptedCookieManager` supports encrypted cookie payloads where applications need them.
- API controllers provide reusable account and management endpoints.

## Documentation

- [Identity flow](documentation/identity-flow.md)
- [Browser sessions, WebAuthn and impersonation](documentation/browser-sessions-webauthn-impersonation.md)
