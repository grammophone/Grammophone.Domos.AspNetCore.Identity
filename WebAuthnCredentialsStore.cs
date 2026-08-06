using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Grammophone.DataAccess.QueryExtensions;
using Fido2NetLib;
using Fido2NetLib.Objects;
using Grammophone.Domos.DataAccess;
using Grammophone.Domos.Domain;
using Grammophone.Setup;

namespace Grammophone.Domos.AspNetCore.Identity
{
	/// <summary>
	/// A store of WebAuthnCredentials.
	/// </summary>
	/// <typeparam name="UB">The base type of the user, derived from <see cref="User"/>.</typeparam>
	/// <typeparam name="U">The type of the user, derived from <typeparamref name="UB"/>.</typeparam>
	/// <typeparam name="D">The type of the domain container, derived from <see cref="IUsersDomainContainer{U}"/>.</typeparam>
	public class WebAuthnCredentialsStore<UB, U, D>
		where UB : User
		where U : UB
		where D : IUsersDomainContainer<UB>
	{
		#region Construction

		/// <summary>
		/// The Constructor.
		/// </summary>
		/// <param name="configurationSectionName">
		/// The name of a unity configuration section, where
		/// a domain container of type <typeparamref name="D"/> is defined.
		/// </param>
		public WebAuthnCredentialsStore(string configurationSectionName)
		{
			if (configurationSectionName == null) throw new ArgumentNullException(nameof(configurationSectionName));

			var identitySettings = Settings.Load(configurationSectionName);

			this.Settings = identitySettings;

			this.DomainContainer = identitySettings.Resolve<D>();
		}

		#endregion

		#region Protected properties

		/// <summary>
		/// The configured settings.
		/// </summary>
		protected Settings Settings { get; }

		/// <summary>
		/// The domain container for accessing the store.
		/// </summary>
		protected D DomainContainer { get; }

		#endregion

		#region public methods

		/// <summary>
		/// Delete a user WebAuthn credential.
		/// </summary>
		/// <param name="credentialID">The id of the credential.</param>
		/// <param name="publicKey">The public key of the credential.</param>
		/// <returns>Returns tru if found and deleted, false otherwise.</returns>
		public async Task<bool> DeleteCredentialAsync(long credentialID, byte[] publicKey)
		{
			if (publicKey == null) throw new ArgumentNullException(nameof(publicKey));

			using (var transaction = this.DomainContainer.BeginTransaction())
			{
				var credential = await this.DomainContainer.WebAuthnCredentials
					.Where(wc => wc.ID == credentialID && wc.PublicKey == publicKey)
					.SingleOrDefaultAsync();

				if (credential == null)
				{
					transaction.Pass();
					return false;
				}

				try
				{
					this.DomainContainer.WebAuthnCredentials.Remove(credential);

					await transaction.CommitAsync();
				}
				catch (SystemException ex)
				{
					throw this.DomainContainer.TranslateException(ex);
				}
			}

			return true;
		}

		/// <summary>
		/// Renames a user's WebAuthn credential.
		/// </summary>
		/// <param name="credentialId">The credential ID in the database.</param>
		/// <param name="friendlyName">The new name.</param>
		/// <returns></returns>
		public async Task<bool> RenameCredentialAsync(long credentialId, string friendlyName)
		{
			using (var transaction = this.DomainContainer.BeginTransaction())
			{
				var credential = await this.DomainContainer.WebAuthnCredentials.Where(wc => wc.ID == credentialId).SingleOrDefaultAsync();

				credential.CredentialFriendlyName = friendlyName;

				await transaction.CommitAsync();
			}

			return true;
		}

		/// <summary>
		/// Get a collection of WebAuthn credentials associated with a logic user username.
		/// </summary>
		/// <param name="username">The username of the logic user.</param>
		/// <returns></returns>
		public async Task<ICollection<WebAuthnCredential>> GetCredentialsByLogicUserNameAsync(string username)
			=> await this.DomainContainer.WebAuthnCredentials.Where(c => c.Owner.UserName == username).ToListAsync();

		/// <summary>
		/// Get the collection of public key descriptors associated with a user name.
		/// </summary>
		public async Task<IEnumerable<PublicKeyCredentialDescriptor>> GetDescriptorsByLogicUserNameAsync(string userName)
		{
			var credentials = await GetCredentialsByLogicUserNameAsync(userName);

			return GetDescriptors(credentials);
		}

		/// <summary>
		/// Removes all the WebAuthn credentials associated with the given username.
		/// </summary>
		/// <param name="username"></param>
		/// <returns></returns>
		public async Task RemoveCredentialsByLogicUserNameAsync(string username)
		{
			var credentials = await this.DomainContainer.WebAuthnCredentials.Where(c => c.Owner.UserName == username).ToListAsync();

			if (credentials != null)
			{
				foreach (var credential in credentials)
				{
					this.DomainContainer.WebAuthnCredentials.Remove(credential);
				};

				await this.DomainContainer.SaveChangesAsync();
			}
		}

		/// <summary>
		/// Get the the first credential associated with the user id.
		/// </summary>
		/// <param name="id">The byte encoded user id.</param>
		/// <returns></returns>
		public async Task<WebAuthnCredential> TryGetCredentialByIdAsync(byte[] id)
		{
			var cred = await this.DomainContainer.WebAuthnCredentials
					.Where(c => c.CredentialId == id)
					.FirstOrDefaultAsync();

			return cred;
		}

		/// <summary>
		/// Get the credentials associated with the user handle.
		/// </summary>
		/// <param name="userHandle"></param>
		/// <returns></returns>
		public async Task<ICollection<WebAuthnCredential>> GetCredentialsByUserHandleAsync(byte[] userHandle)
		{
			return await
				this.DomainContainer
					.WebAuthnCredentials.Where(c => c.UserHandle != null && c.UserHandle == userHandle)
					.ToListAsync();
		}

		/// <summary>
		/// Get the collection of descriptors of a user by the user's handle.
		/// </summary>
		public async Task<IEnumerable<PublicKeyCredentialDescriptor>> GetDescriptorsByUserHandleAsync(byte[] userHandle)
		{
			var credentials = await GetCredentialsByUserHandleAsync(userHandle);

			return GetDescriptors(credentials);
		}

		/// <summary>
		/// Update the signature counter of the credential with a given id.
		/// </summary>
		/// <param name="credentialId">The credential id.</param>
		/// <param name="counter">The value to be updated.</param>
		/// <returns></returns>
		public async Task UpdateCounterAsync(byte[] credentialId, uint counter)
		{
			if (credentialId == null) throw new ArgumentNullException(nameof(credentialId));

			var cred = await this.DomainContainer.WebAuthnCredentials
					.Where(c => c.CredentialId == credentialId).FirstOrDefaultAsync();

			if (cred != null)
			{
				cred.SignatureCounter = counter;
				_ = await this.DomainContainer.SaveChangesAsync();
			}
		}

		/// <summary>
		///  Add credential to a user.
		/// </summary>
		/// <param name="userID">The ID of the database user.</param>
		/// <param name="user">The user.</param>
		/// <param name="attestationVerificationSuccess">The attestation verification success.</param>
		/// <param name="actionPerformingUserID">The id of the user performing the credential add.</param>
		/// <param name="platformType">The platform type of the authenticator that holds the key.</param>
		public async Task AddCredentialToUserAsync(long userID, Fido2User user, RegisteredPublicKeyCredential attestationVerificationSuccess, long actionPerformingUserID, AuthenticatorPlatformType platformType)
		{
			if (attestationVerificationSuccess == null) throw new ArgumentNullException(nameof(attestationVerificationSuccess));

			string friendlyName;

			// Prefer what the credential itself reports. The AAGUID identifies the authenticator model,
			// so it names the device precisely - "YubiKey 5 Series" rather than "Fido2 Security key" -
			// and it also corrects the platform type, which is otherwise guessed from the browser's
			// User-Agent and is wrong for a cross-device registration: an iCloud passkey created from
			// a Windows PC would be recorded as Windows Hello.
			//
			// The catalogue is deliberately partial, so the User-Agent-derived value stays as the
			// fallback for an unrecognised or all-zero AAGUID. A model that implies no single platform,
			// such as a password manager, keeps the inferred type and contributes only its name.
			// Either way this is just the default: the user can rename a credential afterwards.
			if (AuthenticatorCatalogue.TryGetDescription(attestationVerificationSuccess.AaGuid, out var authenticator))
			{
				friendlyName = authenticator.Name;

				if (authenticator.PlatformType != AuthenticatorPlatformType.Unknown)
				{
					platformType = authenticator.PlatformType;
				}
			}
			else
			{
				friendlyName = platformType switch
				{
					AuthenticatorPlatformType.WindowsHello => "Windows Hello",
					AuthenticatorPlatformType.ICloudKeychain => "ICloud Keychain",
					AuthenticatorPlatformType.Android => "Android",
					AuthenticatorPlatformType.SecurityKey => "Fido2 Security key",
					_ => "Passkey",
				};
			}

			var credential = new WebAuthnCredential
			{
				CredentialFriendlyName = friendlyName,
				UserName = user.Name,
				// Keep the transports the authenticator reported. Storing only the id, as this did,
				// discarded them: the client sends transports (FIDO2 4.x requires the field) and they
				// were then thrown away.
				//
				// GetDescriptors round-trips these into the credential lists, where a browser can use
				// them to tailor its prompt - offering "insert your security key" for a USB
				// authenticator rather than every option at once. Note that this only has an effect
				// where a list is actually sent: registration's excludeCredentials, and an assertion
				// for a KNOWN user such as the two-factor flow. A usernameless sign-in sends an empty
				// allowCredentials, and there the browser enumerates discoverable credentials on the
				// device itself, so the hint is irrelevant.
				// Serializing the extra field is safe in both directions - PublicKeyCredentialDescriptor
				// marks its three-argument constructor [JsonConstructor], so the values come back on
				// read, and rows written before this change simply deserialize with null transports.
				DescriptorJson = JsonSerializer.Serialize(
					new PublicKeyCredentialDescriptor(
						attestationVerificationSuccess.Type,
						attestationVerificationSuccess.Id,
						attestationVerificationSuccess.Transports)),
				PublicKey = attestationVerificationSuccess.PublicKey,
				UserHandle = user.Id,
				SignatureCounter = attestationVerificationSuccess.SignCount,
				CredType = attestationVerificationSuccess.Type.ToString(),// .CredType,
				OwnerID = userID,
				RegistrationDate = DateTime.UtcNow,
				AaGuid = attestationVerificationSuccess.AaGuid, //.Aaguid,
				PlatformType = platformType,
				CredentialId = attestationVerificationSuccess.Id, //.CredentialId,
				UserId = GetUserNameInBytes(user.Name)
			};

			this.DomainContainer.WebAuthnCredentials.Add(credential);

			await this.DomainContainer.SaveChangesAsync();
		}

		/// <summary>
		/// Get users by credential id.
		/// </summary>
		/// <param name="credentialId">The credential id.</param>
		/// <returns></returns>
		public async Task<ICollection<Fido2User>> GetUsersByCredentialIdAsync(byte[] credentialId)
		{
			if (credentialId == null) throw new ArgumentNullException(nameof(credentialId));

			var cred = await this.DomainContainer.WebAuthnCredentials
					.Where(c => c.CredentialId == credentialId).FirstOrDefaultAsync();

			if (cred == null || cred.UserId == null)
			{
				return new List<Fido2User>();
			}

			return await this.DomainContainer.Users
							 .Where(u => u.UserName != null && GetUserNameInBytes(u.UserName)
							 .SequenceEqual(cred.UserId))
							 .Select(u => new Fido2User
							 {
								 DisplayName = $"{u.FirstName} {u.LastName}",
								 Name = u.UserName,
								 Id = GetUserNameInBytes(u.UserName) // byte representation of userID is required
							 }).ToListAsync();
		}

		/// <summary>
		/// Get the username in bytes array.
		/// </summary>
		/// <param name="userName"></param>
		/// <returns></returns>
		public byte[] GetUserNameInBytes(string userName)
			=> userName != null ? Encoding.UTF8.GetBytes(userName) : throw new ArgumentNullException(nameof(userName));

		/// <summary>
		/// IDisposable interface implementation.
		/// </summary>
		public void Dispose() => this.DomainContainer.Dispose();

		#endregion

		#region Private methods

		private static IEnumerable<PublicKeyCredentialDescriptor> GetDescriptors(ICollection<WebAuthnCredential> credentials)
		{
			return from c in credentials
						 where c.DescriptorJson != null
						 select JsonSerializer.Deserialize<PublicKeyCredentialDescriptor>(c.DescriptorJson);
		}

		#endregion
	}

	/// <summary>
	/// A store of WebAuthnCredentials.
	/// </summary>
	/// <typeparam name="U">The type of the user, derived from <see cref="User"/>.</typeparam>
	/// <typeparam name="D">The type of the domain container, derived from <see cref="IUsersDomainContainer{U}"/>.</typeparam>
	public class WebAuthnCredentialsStore<U, D> : WebAuthnCredentialsStore<U, U, D>
		where U : User
		where D : IUsersDomainContainer<U>
	{
		/// <inheritdoc/>
		public WebAuthnCredentialsStore(string configurationSectionName) : base(configurationSectionName)
		{
		}
	}
}
