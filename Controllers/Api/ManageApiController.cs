using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Fido2NetLib.Objects;
using Fido2NetLib;
using Grammophone.Domos.Domain;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Net.Http.Headers;
using Grammophone.Domos.DataAccess;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using System.Threading;
using Microsoft.IdentityModel.Tokens;
using MyCSharp.HttpUserAgentParser;

namespace Grammophone.Domos.AspNetCore.Identity.Controllers.Api
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
	public class CredRequest
	{
		public string username { get; set; } = String.Empty;
		public string displayName { get; set; } = String.Empty;
		public string attType { get; set; } = String.Empty;
		public string authType { get; set; } = String.Empty;
		public bool requireResidentKey { get; set; }
		public string userVerification { get; set; } = String.Empty;
	}
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member

	/// <summary>
	/// An API controller for managing the user identity.
	/// </summary>
	[ApiController]
	[ApiExplorerSettings(IgnoreApi = true)]
	public class ManageApiController<UB, U, D> : Controller
		where UB : User
		where U : UB
		where D : IUsersDomainContainer<UB>
	{
		#region private readonly

		private readonly string cookieDomain = System.Configuration.ConfigurationManager.AppSettings["domain"]?.ToLower() ?? ".lifeaccount.ca";

		#endregion

		#region Private fields

		private readonly IFido2 fido2Library;

		#endregion

		#region Construction

		/// <summary>
		/// Create.
		/// </summary>
		public ManageApiController(
			SignInManager<U> signInManager,
			UserManager<U> userManager,
			WebAuthnCredentialsStore<UB, U, D> webAuthnCredentialsStore,
			IOptions<Fido2Configuration> optionsFido2Configuration,
			IEncryptedCookieManager encrypteCookieManager)
		{
			if (signInManager == null) throw new ArgumentNullException(nameof(signInManager));
			if (userManager == null) throw new ArgumentNullException(nameof(userManager));
			if (webAuthnCredentialsStore == null) throw new ArgumentNullException(nameof(webAuthnCredentialsStore));
			if (encrypteCookieManager == null) throw new ArgumentNullException(nameof(encrypteCookieManager));

			this.SignInManager = signInManager;
			this.UserManager = userManager;
			this.EncryptedCookieManager = encrypteCookieManager;
			this.WebAuthnCredentialsStore = webAuthnCredentialsStore;

#pragma warning disable CS0618 // Type or member is obsolete
			this.fido2Library = new Fido2(new Fido2Configuration()
			{
				ServerDomain = optionsFido2Configuration.Value.ServerDomain,
				ServerName = optionsFido2Configuration.Value.ServerName,
				//Origin = originHashset.(), //optionsFido2Configuration.Value.Origin,
				Origins = optionsFido2Configuration.Value.Origins,
				TimestampDriftTolerance = optionsFido2Configuration.Value.TimestampDriftTolerance
			});
#pragma warning restore CS0618 // Type or member is obsolete
		}

		#endregion

		#region Operations

		/// <summary>
		/// When adding a security key create the key attestation.
		/// </summary>
		/// <param name="request">The new credential request.</param>
		/// <returns>The <see cref="CredentialCreateOptions"/> as Json.</returns>
		[HttpPost]
		[Route("MakeCredentialOptions")]
		[Authorize]
		public async Task<JsonResult> MakeCredentialOptions(CredRequest request)
		{
			if (System.Configuration.ConfigurationManager.AppSettings["enableWebAuthn"]?.ToLower() == "true")
			{
				//find lifeaccount user.
				var user = await this.UserManager.FindByNameAsync(request.username);

				if (user == null) throw new InvalidOperationException($"The user '{request.username}' was not found.");

				var username = user.UserName; //the actual user name keep as userid.
				var userHandle = user.Guid.ToString();
				var displayName = $"{user.FirstName} {user.LastName}";//request.displayName;
				var attType = request.attType;
				var authType = request.authType;
				var requireResidentKey = request.requireResidentKey;
				var userVerification = request.userVerification;

				try
				{
					if (string.IsNullOrEmpty(username))
					{
						username = $"{displayName} (Usernameless user created at {DateTime.UtcNow})";
					}

					var fidoUser = new Fido2User
					{
						DisplayName = displayName, //the display name shown to the authenticator.
						Name = username, //the username shown at the authenticator when multiple 
						Id = WebAuthnCredentialsStore.GetUserNameInBytes(userHandle) // the user handle used to specify the creadential at the authenticator. (we use the user.guid).
					};

					// 2. Get user existing keys by username

					var existingDescriptors = (await this.WebAuthnCredentialsStore.GetDescriptorsByLogicUserNameAsync(user.UserName)).ToList();

					// 3. Create options
					var authenticatorSelection = new AuthenticatorSelection
					{
						//RequireResidentKey = requireResidentKey,
						ResidentKey = ResidentKeyRequirement.Required,
						UserVerification = userVerification.ToEnum<UserVerificationRequirement>()
					};

					if (!string.IsNullOrEmpty(authType))
						authenticatorSelection.AuthenticatorAttachment = authType.ToEnum<AuthenticatorAttachment>();

					var exts = new AuthenticationExtensionsClientInputs
					{
						Extensions = true,
						UserVerificationMethod = true,
						DevicePubKey = new AuthenticationExtensionsDevicePublicKeyInputs() { Attestation = attType },
						CredProps = true
					};

					var options = fido2Library.RequestNewCredential(
						fidoUser,
						existingDescriptors,
						authenticatorSelection,
						attType.ToEnum<AttestationConveyancePreference>(),
						exts);

					// 4. Temporarily store options in an encrypted cookie
					var encryptedOptions = this.EncryptedCookieManager.CreateEncryptedToken(options.ToJson());

					var fido2cookieOptions = new CookieOptions();
					fido2cookieOptions.Expires = DateTime.Now.AddMinutes(1);
					fido2cookieOptions.Domain = cookieDomain;
					fido2cookieOptions.Path = "/";
					fido2cookieOptions.IsEssential = true;
					Response.Cookies.Append("fido2.attestationOptions", Convert.ToBase64String(encryptedOptions), fido2cookieOptions);

					return Json(options);

				}
				catch (Exception e)
				{
					return Json(new VerifyAssertionResult { Status = "error", ErrorMessage = FormatException(e) });
				}
			}
			return Json(new VerifyAssertionResult { Status = "error", ErrorMessage = "WebAuthn is not available." });
		}

		/// <summary>
		/// Add the new security key to a user.
		/// </summary>
		/// <param name="attestationResponse">The attestation responce created by the authenticator.</param>
		/// <returns>Returns the <see cref="CredentialCreateOptions"/> result.</returns>
		[HttpPost]
		[Authorize]
		[Route("MakeCredential")]
		public async Task<JsonResult> MakeCredential(AuthenticatorAttestationRawResponse attestationResponse)
		{
			try
			{
				// 1. get the options we sent the client
				var cookieOptions = Request.Cookies["fido2.attestationOptions"]!;

				if (cookieOptions.IsNullOrEmpty())
				{
					return Json(new MakeNewCredentialResult("error", "fido2.assertOptions is empty.", null));// CredentialMakeResult { Status = "error", ErrorMessage = "fido2.assertOptions is empty." });
				}
			
				var options = CredentialCreateOptions.FromJson(this.EncryptedCookieManager.DecryptAndValidateEncryptedToken(Convert.FromBase64String(cookieOptions)));

				// 1b. find User
				var user = await UserManager.FindByNameAsync(this.User?.Identity?.Name ?? String.Empty);

				if (user == null)
				{
					return Json(new MakeNewCredentialResult(
						status:"error",
						errorMessage: $"Unable to load user with username: '{options.User.Name}'.",
						result: null
					));
				}

				// 2. Create callback so that lib can verify credential id is unique to this user
				//IsCredentialIdUniqueToUserAsyncDelegate callback = async (IsCredentialIdUniqueToUserParams args, CancellationToken cancellationToken) =>
				//{
				//	var users = await this.WebAuthnCredentialsStore.GetUsersByCredentialIdAsync(args.CredentialId);
				//	if (users.Count > 0) return false;

				//	return true;
				//};

				// 2. Verify and make the credentials
				var success = await fido2Library.MakeNewCredentialAsync(attestationResponse, options, IsCredentialIdUniqueToUserAsync);
				if (success.Result != null)
				{
					//2.1 find the user agent.
					var useragentInfo = HttpUserAgentParser.Parse(this.Request.Headers.UserAgent.ToString());
					AuthenticatorPlatformType platformType = AuthenticatorPlatformType.Unknown;
					var platformAuthenticator = options.AuthenticatorSelection.AuthenticatorAttachment == AuthenticatorAttachment.Platform ? true : false;
					if (useragentInfo.Platform.HasValue && platformAuthenticator)
					{
						switch (useragentInfo.Platform.Value.PlatformType)
						{
							case MyCSharp.HttpUserAgentParser.HttpUserAgentPlatformType.Unknown:
							case MyCSharp.HttpUserAgentParser.HttpUserAgentPlatformType.Generic:
							case MyCSharp.HttpUserAgentParser.HttpUserAgentPlatformType.BlackBerry:
							case MyCSharp.HttpUserAgentParser.HttpUserAgentPlatformType.Symbian:
							case MyCSharp.HttpUserAgentParser.HttpUserAgentPlatformType.Linux:
							case MyCSharp.HttpUserAgentParser.HttpUserAgentPlatformType.Unix:
								platformType = AuthenticatorPlatformType.Unknown;
								break;
							case MyCSharp.HttpUserAgentParser.HttpUserAgentPlatformType.Windows:
								platformType = AuthenticatorPlatformType.WindowsHello;
								break;
							case MyCSharp.HttpUserAgentParser.HttpUserAgentPlatformType.IOS:
							case MyCSharp.HttpUserAgentParser.HttpUserAgentPlatformType.MacOS:
								platformType = AuthenticatorPlatformType.ICloudKeychain;
								break;
							case MyCSharp.HttpUserAgentParser.HttpUserAgentPlatformType.Android:
								platformType = AuthenticatorPlatformType.Android;
								break;
							default:
								break;
						}
					}

					if (!platformAuthenticator)
					{
						platformType = AuthenticatorPlatformType.SecurityKey;
					}

					// 3. Store the credentials in db
					await WebAuthnCredentialsStore.AddCredentialToUserAsync(
						user.ID, options.User, 
						success.Result, 
						user.ID ,
						platformType);
				}

				//can the action when registration succeeds, (e.g. log).
				await OnFidoCredentialsRegisteredSucceededdAsync(user);

				return Json(success);
			}
			catch (Exception e)
			{
				
				
				return Json(new MakeNewCredentialResult(
					status: "error",
					errorMessage: FormatException(e),
					result: null
				));
			}
		}

		#endregion

		#region Protected properties

		/// <summary>
		/// The sign-in manager.
		/// </summary>
		protected SignInManager<U> SignInManager { get; }

		/// <summary>
		/// The user manager.
		/// </summary>
		protected UserManager<U> UserManager { get; }

		/// <summary>
		/// The manager for handling encrypted cookies.
		/// </summary>
		protected IEncryptedCookieManager EncryptedCookieManager { get; }

		/// <summary>
		/// The WebAuthnCreadential store.
		/// </summary>
		protected WebAuthnCredentialsStore<UB, U, D> WebAuthnCredentialsStore { get; }

		#endregion

		#region Protected methods

		/// <summary>
		/// Called when the user is validated and registers his fido2 credentials successfully.
		/// </summary>
		protected virtual Task OnFidoCredentialsRegisteredSucceededdAsync(U user) => Task.CompletedTask;

		#endregion

		#region Private methods

		//private async Task<bool> IsUserHandleOwnerOfCredentialIdAsync(IsUserHandleOwnerOfCredentialIdParams args, CancellationToken cancellationChangeToken)
		//{
		//	var foundStoredCredentials = from d in await this.WebAuthnCredentialsStore.GetDescriptorsByUserHandleAsync(args.UserHandle)
		//															 where d.Id.SequenceEqual(args.CredentialId)
		//															 select d;

		//	return foundStoredCredentials.Any();
		//}

		//Method passed to the so that the  fido2lib can verify credential id is unique to this user
		private async Task<bool> IsCredentialIdUniqueToUserAsync(IsCredentialIdUniqueToUserParams args, CancellationToken cancellationToken)
		{
			var users = await this.WebAuthnCredentialsStore.GetUsersByCredentialIdAsync(args.CredentialId);
			if (users.Count > 0) return false;

			return true;
		}

		private static string FormatException(Exception e)
		{
			return string.Format("{0}{1}", e.Message, e.InnerException != null ? " (" + e.InnerException.Message + ")" : "");
		}


		#endregion
	}

	/// <summary>
	/// An API controller for allowing users to register their WebAuthn credentials.
	/// </summary>
	/// <typeparam name="U">The type of the user, derived from <see cref="User"/>.</typeparam>
	/// <typeparam name="D">The type of the domain container, derived from <see cref="IUsersDomainContainer{U}"/>.</typeparam>
	public class ManageApiController<U, D> : ManageApiController<U, U, D>
		where U : User
		where D : IUsersDomainContainer<U>
	{
		#region Construction

		/// <inheritdoc/>
		public ManageApiController(
			SignInManager<U> signInManager,
			UserManager<U> userManager,
			WebAuthnCredentialsStore<U, D> webAuthnCredentialsStore,
			IOptions<Fido2Configuration> optionsFido2Configuration,
			IEncryptedCookieManager encrypteCookieManager)
			: base(signInManager, userManager, webAuthnCredentialsStore, optionsFido2Configuration, encrypteCookieManager)
		{
		}

		#endregion
	}


}
