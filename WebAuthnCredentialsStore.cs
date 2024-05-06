using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
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
		public async Task AddCredentialToUserAsync(long userID, Fido2User user, AttestationVerificationSuccess attestationVerificationSuccess, long actionPerformingUserID, AuthenticatorPlatformType platformType)
		{
			if (attestationVerificationSuccess == null) throw new ArgumentNullException(nameof(attestationVerificationSuccess));

			string friendlyName = "";

			switch (platformType)
			{
				case AuthenticatorPlatformType.Unknown:
					friendlyName = "Passkey";
					break;
				case AuthenticatorPlatformType.WindowsHello:
					friendlyName = "Windows Hello";
					break;
				case AuthenticatorPlatformType.ICloudKeychain:
					friendlyName = "ICloud Keychain";
					break;
				case AuthenticatorPlatformType.Android:
					friendlyName = "Android";
					break;
				case AuthenticatorPlatformType.SecurityKey:
					friendlyName = "Fido2 Security key";
					break;
				default:
					break;
			}

			var credential = new WebAuthnCredential
			{
				CredentialFriendlyName = friendlyName,
				UserName = user.Name,
				DescriptorJson = JsonSerializer.Serialize(new PublicKeyCredentialDescriptor(attestationVerificationSuccess.CredentialId)), //JsonConvert.SerializeObject(new PublicKeyCredentialDescriptor(attestationVerificationSuccess.CredentialId)),
				PublicKey = attestationVerificationSuccess.PublicKey,
				UserHandle = user.Id,
				SignatureCounter = attestationVerificationSuccess.Counter,
				CredType = attestationVerificationSuccess.CredType,
				OwnerID = userID,
				RegistrationDate = DateTime.UtcNow,
				AaGuid = attestationVerificationSuccess.Aaguid,
				PlatformType = platformType,
				CredentialId = attestationVerificationSuccess.CredentialId,
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
