# ASP.NET Core Identity Flow

`Grammophone.Domos.AspNetCore.Identity` connects ASP.NET Core Identity to users stored in a Domos domain container.

The core store type is generic over the base user, concrete user and domain container:

```csharp
UserStore<MusicUser, MusicUser, IMusicDomainContainer>
```

Applications can specialize this shape when the publicly exposed identity user type differs from the base Domos user type.

## Store Responsibilities

The user store implements the standard ASP.NET Core Identity interfaces for account creation, updates, login providers, passwords, roles, email, lockout, two-factor settings and security stamps.

The role store exposes Domos `Role` entities to Identity. Registrations map external logins. WebAuthn credentials map passkeys.

## Relationship To Logic Sessions

Identity stores authenticate and manage user accounts. Business operations should still go through a Domos `LogicSession` such as `MusicSession`.

For example, after ASP.NET Core authenticates a `MusicUser`, a controller can create a `MusicSession` for that user and obtain a `RecordLabelCatalogManager`. Manager access, entity access and workflow access are then enforced by Domos.

## Listeners And Overrides

The store invokes virtual hooks and registered `IUserListener` implementations for user lifecycle events. Applications can use these hooks for audit records, notifications or domain-specific validation.
