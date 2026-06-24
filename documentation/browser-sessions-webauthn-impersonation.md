# Browser Sessions, WebAuthn And Impersonation

The ASP.NET Core integration includes identity components that use Domos security entities beyond the base user record.

## Browser Sessions

Browser-session-aware stores and sign-in managers track browser sessions against users. A session can record first sign-in, last seen timestamps, fingerprint and client IP addresses.

This supports security screens and audit logging in applications such as a music catalog portal where a `MusicUser` manages albums for record labels.

## WebAuthn

`WebAuthnCredentialsStore` persists WebAuthn credentials associated with Domos users. This lets ASP.NET Core identity flows use passkeys while keeping credentials in the same domain container as roles, registrations and browser sessions.

## Claims And Impersonation

`IdentityClaimNames` and `ImpersonationFunctions` define conventions for carrying Domos user and impersonation data through ASP.NET Core claims.

Impersonation is not an authorization bypass. It changes the acting user used by a Domos logic session or impersonation scope. Entity, manager and workflow checks are still applied to the acting user.

## API Controllers

The package contains reusable account and management API controllers. Applications can derive from or compose them when building identity endpoints, while still routing business operations through Domos logic sessions.
