# Grammophone.Domos.AspNetCore.Identity
This dual-target .NET Framework and .NET Standard 2.1 library provides an
ASP.NET Core Identity implementation for the users of the
Domos integrated session system.

It is part of the 3rd generation of the Domos integrated session
system which supporst SaaS, security, workflow and accounting scenarios.

The class `UserStore<U>` implements the following interfaces,
where the template argument `U` must be derived from Domos `User`:

* `IUserStore<U>`
* `IUserLoginStore<U>`
* `IUserPasswordStore<U>`
* `IUserRoleStore<U>`
* `IUserEmailStore<U>`
* `IUserLockoutStore<U>`
* `IUserTwoFactorStore<U>`
* `IUserSecurityStampStore<U>`

Allmost all methods are virtual to allow specialization or change of
behavior. The `UserStore<U>` class also offers the
following events to subscribe:
* `CreatingUser`
* `UpdatingUser`
* `DeletingUser`
* `AddingLogin`
* `RemovingLogin`
* `ChangingPassword`
* `SettingEmail`
* `ConfirmingEmail`
* `GettingSecurityStamp`
* `SettingSecurityStamp`

For asynchronous versions of the above events, there are two options:
* Create any number of
`IUserListener<U>` implementations
and register them in the dependency injection configuration specified in
the constructor of `UserStore<U>`.
* All the above functionality is triggered by the following virtual
methods. Override to add any custom requirements. Call the base
implementation to fire the events and notify `IUserListener<U>` listeners.
    * `OnCreatingUser`
    * `OnUpdatingUser`
    * `OnDeletingUser`
    * `OnAddingLogin`
    * `OnRemovingLogin`
    * `OnChangingPassword`
    * `OnSettingEmail`
    * `OnConfirmingEmail`
    * `OnGettingSecurityStamp`
    * `OnSettingSecurityStamp`

## Dependencies

This library depends on the following libraries being in
sibling directories:

* [Grammophone.Caching](https://github.com/grammophone/Grammophone.Caching)
* [Grammophone.DataAccess](https://github.com/grammophone/Grammophone.DataAccess)
* [Grammophone.Domos.DataAccess](https://github.com/grammophone/Grammophone.Domos.DataAccess)
* [Grammophone.Domos.Domain](https://github.com/grammophone/Grammophone.Domos.Domain)
* [Grammophone.Setup](https://github.com/grammophone/Grammophone.Setup)