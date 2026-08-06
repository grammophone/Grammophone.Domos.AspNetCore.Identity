using System;
using System.Collections.Generic;
using Grammophone.Domos.Domain;

namespace Grammophone.Domos.AspNetCore.Identity
{
	/// <summary>
	/// Maps an authenticator's AAGUID to a human-readable model name and platform type.
	/// </summary>
	/// <remarks>
	/// <para>
	/// The AAGUID is standard: WebAuthn defines it, the authenticator reports it in the attested
	/// credential data, and every unit of a model reports the same value.
	/// </para>
	/// <para>
	/// Note this affects <em>new</em> registrations only. The name is resolved once and persisted to
	/// <c>CredentialFriendlyName</c>, so credentials registered before this catalogue existed keep
	/// whatever label they were given, even though their AAGUID has always been stored and would
	/// resolve here. Relabelling them takes a deliberate backfill, or a change to resolve the name on
	/// read and treat the stored value as an override.
	/// </para>
	/// <para>
	/// The AAGUID-to-name <em>mapping</em> is not standardised, and neither published source covers a
	/// typical deployment on its own. FIDO's Metadata Service is authoritative but lists certified
	/// hardware authenticators, not software passkey providers; the community list is the inverse,
	/// carrying passkey providers and no hardware keys at all. This table is therefore written by
	/// hand from published product identifiers, which avoids a network dependency at sign-in, keeps
	/// third-party assets out of the build, and needs no storage of its own.
	/// </para>
	/// <para>
	/// It is deliberately incomplete for hardware keys. Naming every model in the Metadata Service
	/// would mean hundreds of per-firmware entries that go stale and describe keys an organisation
	/// does not own; add the models actually issued instead. An unrecognised AAGUID is not a failure
	/// — the caller falls back to the platform type, which for a roaming key is derived from the
	/// authenticator attachment and is therefore reliable.
	/// </para>
	/// <para>
	/// Some authenticators deliberately report an all-zero AAGUID for privacy. That is treated as
	/// unknown.
	/// </para>
	/// </remarks>
	public static class AuthenticatorCatalogue
	{
		#region Private fields

		/// <summary>
		/// Known AAGUIDs. A provider may use several — Windows Hello alone has three in circulation,
		/// so matching on any single one would misname the others.
		/// </summary>
		private static readonly Dictionary<Guid, AuthenticatorDescription> descriptionsByAaGuid = new()
		{
			// --- Platform authenticators and software passkey providers ---
			[new Guid("08987058-cadc-4b81-b6e1-30de50dcbe96")] = new("Windows Hello", AuthenticatorPlatformType.WindowsHello, "ri-windows-line"),
			[new Guid("9ddd1817-af5a-4672-a2b9-3e3dd95000a9")] = new("Windows Hello", AuthenticatorPlatformType.WindowsHello, "ri-windows-line"),
			[new Guid("6028b017-b1d4-4c02-b4b3-afcdafc96bb2")] = new("Windows Hello", AuthenticatorPlatformType.WindowsHello, "ri-windows-line"),
			[new Guid("fbfc3007-154e-4ecc-8c0b-6e020557d7bd")] = new("Apple Passwords", AuthenticatorPlatformType.ICloudKeychain, "ri-apple-line"),
			[new Guid("dd4ec289-e01d-41c9-bb89-70fa845d4bf2")] = new("iCloud Keychain (Managed)", AuthenticatorPlatformType.ICloudKeychain, "ri-apple-line"),
			[new Guid("adce0002-35bc-c60a-648b-0b25f1f05503")] = new("Chrome on Mac", AuthenticatorPlatformType.ICloudKeychain, "ri-chrome-line"),
			[new Guid("771b48fd-d3d4-4f74-9232-fc157ab0507a")] = new("Edge on Mac", AuthenticatorPlatformType.ICloudKeychain, "ri-edge-line"),
			[new Guid("ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4")] = new("Google Password Manager", AuthenticatorPlatformType.Android, "ri-google-line"),
			[new Guid("53414d53-554e-4700-0000-000000000000")] = new("Samsung Pass", AuthenticatorPlatformType.Android, "ri-smartphone-line"),
			[new Guid("b5397666-4885-aa6b-cebf-e52262a439a2")] = new("Chromium Browser", AuthenticatorPlatformType.Unknown, "ri-chrome-line"),

			// --- Password managers acting as passkey providers ---
			[new Guid("bada5566-a7aa-401f-bd96-45619a55120d")] = new("1Password", AuthenticatorPlatformType.Unknown, "ri-safe-2-line"),
			[new Guid("d548826e-79b4-db40-a3d8-11116f7e8349")] = new("Bitwarden", AuthenticatorPlatformType.Unknown, "ri-safe-2-line"),
			[new Guid("531126d6-e717-415c-9320-3d9aa6981239")] = new("Dashlane", AuthenticatorPlatformType.Unknown, "ri-safe-2-line"),
			[new Guid("0ea242b4-43c4-4a1b-8b17-dd6d0b6baec6")] = new("Keeper", AuthenticatorPlatformType.Unknown, "ri-safe-2-line"),
			[new Guid("b84e4048-15dc-4dd0-8640-f4f60813c8af")] = new("NordPass", AuthenticatorPlatformType.Unknown, "ri-safe-2-line"),
			[new Guid("f3809540-7f14-49c1-a8b3-8f813b225541")] = new("Enpass", AuthenticatorPlatformType.Unknown, "ri-safe-2-line"),
			[new Guid("891494da-2c90-4d31-a9cd-4eab0aed1309")] = new("Sésame", AuthenticatorPlatformType.Unknown, "ri-safe-2-line"),
			[new Guid("39a5647e-1853-446c-a1f6-a79bae9f5bc7")] = new("IDmelon", AuthenticatorPlatformType.Unknown, "ri-safe-2-line"),
			[new Guid("a11a5faa-9f32-4b8c-8c5d-2f7d13e8c942")] = new("AliasVault", AuthenticatorPlatformType.Unknown, "ri-safe-2-line"),

			// --- Hardware security keys: only the models actually issued. Add as they are adopted. ---
			[new Guid("a4e9fc6d-4cbe-4758-b8ba-37598bb5bbaa")] = new("YubiKey 5 Series", AuthenticatorPlatformType.SecurityKey, "ri-usb-line"),
		};

		#endregion

		#region Public methods

		/// <summary>
		/// Looks up an authenticator by its AAGUID.
		/// </summary>
		/// <param name="aaGuid">The AAGUID reported by the authenticator.</param>
		/// <param name="description">The matched description, when the AAGUID is recognised.</param>
		/// <returns>
		/// True when the AAGUID is recognised. False for an unknown or all-zero AAGUID, in which case
		/// the caller should fall back to whatever it can infer.
		/// </returns>
		public static bool TryGetDescription(Guid aaGuid, out AuthenticatorDescription description)
		{
			if (aaGuid == Guid.Empty)
			{
				description = default;

				return false;
			}

			return descriptionsByAaGuid.TryGetValue(aaGuid, out description);
		}

		/// <summary>
		/// The icon to show for a credential, preferring what its AAGUID says over what was inferred.
		/// </summary>
		/// <param name="aaGuid">The AAGUID stored on the credential.</param>
		/// <param name="platformType">The stored platform type, used when the AAGUID is unrecognised.</param>
		/// <returns>A CSS class from the Remix icon set the theme bundles.</returns>
		/// <remarks>
		/// <para>
		/// Unlike the credential's name, this is resolved on <em>read</em>, so it also corrects
		/// credentials registered before the catalogue existed — their AAGUID has always been stored.
		/// </para>
		/// <para>
		/// An unrecognised authenticator falls back to the platform type, and an unknown platform gets
		/// a generic key rather than a question mark: an unfamiliar model is still a working passkey,
		/// and a security screen should not imply something went wrong with it.
		/// </para>
		/// </remarks>
		public static string GetIconClass(Guid aaGuid, AuthenticatorPlatformType platformType)
		{
			if (TryGetDescription(aaGuid, out var description)) return description.IconClass;

			return platformType switch
			{
				AuthenticatorPlatformType.WindowsHello => "ri-windows-line",
				AuthenticatorPlatformType.ICloudKeychain => "ri-apple-line",
				AuthenticatorPlatformType.Android => "ri-android-line",
				AuthenticatorPlatformType.SecurityKey => "ri-usb-line",
				_ => "ri-key-2-line",
			};
		}

		#endregion
	}

	/// <summary>
	/// What is known about an authenticator model, derived from its AAGUID.
	/// </summary>
	/// <param name="Name">The model or provider name to show the user, such as "YubiKey 5 Series".</param>
	/// <param name="PlatformType">
	/// The platform type implied by the model. This is read from the credential rather than guessed
	/// from the browser's User-Agent, so it stays correct for a cross-device registration — where an
	/// iCloud passkey created from a Windows PC would otherwise be recorded as Windows Hello.
	/// <see cref="AuthenticatorPlatformType.Unknown"/> means the model is recognised but implies no
	/// particular platform, as with a password manager available on several.
	/// </param>
	/// <param name="IconClass">
	/// The CSS class of the icon to show, from the Remix set the theme already bundles. Carried
	/// separately from <paramref name="PlatformType"/> because the two do not always agree: a password
	/// manager asserts no platform yet still deserves its own icon rather than inheriting the one
	/// guessed for the device it happened to be used on.
	/// </param>
	public readonly record struct AuthenticatorDescription(
		string Name,
		AuthenticatorPlatformType PlatformType,
		string IconClass);
}
