using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Fido2NetLib;
using Fido2NetLib.Objects;
using Grammophone.Domos.DataAccess;
using Grammophone.Domos.Domain;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;
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

		/// <summary>
		/// The domain to scope a handshake cookie to, or null to leave it host-only.
		/// </summary>
		/// <remarks>
		/// <para>
		/// The configured domain is used whenever the request is actually inside it, which is every
		/// deployment where one host serves the page and another the passkey API - the case the setting
		/// exists for. It cannot be used otherwise: a server may only set a cookie for a domain it
		/// belongs to, so returning ".lifeaccount.ca" while answering on another domain makes the browser
		/// silently discard the cookie, and the next request in the ceremony fails with
		/// "fido2.assertOptions is empty" - after the authenticator has already signed.
		/// </para>
		/// <para>
		/// That is not hypothetical: Related Origin Requests let one passkey span lifeaccount.ca and
		/// workaccount.ca, so a single process now answers on both. ROR makes the credential portable;
		/// it does nothing for this application own cookies.
		/// </para>
		/// <para>
		/// A host-only cookie is returned rather than one scoped to the request host, which would also
		/// cover that host subdomains. Note <c>Request.Host.Host</c>, not <c>.Value</c>: the latter
		/// carries the port, and a Domain attribute containing a port is invalid, so the browser drops
		/// the cookie entirely.
		/// </para>
		/// </remarks>
		private string? GetCookieDomain()
		{
			if (String.IsNullOrEmpty(cookieDomain)) return null;

			string host = this.Request.Host.Host;
			string bareDomain = cookieDomain.TrimStart('.');

			bool isInsideConfiguredDomain =
				String.Equals(host, bareDomain, StringComparison.OrdinalIgnoreCase)
				|| host.EndsWith("." + bareDomain, StringComparison.OrdinalIgnoreCase);

			return isInsideConfiguredDomain ? cookieDomain : null;
		}

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

					// The devicePubKey and uvm extensions were dropped by the FIDO2 library in 4.x.
					// Neither was ever consumed here: no device public key was stored (the assertion
					// call passed an empty set), and the uvm output was not read.
					var exts = new AuthenticationExtensionsClientInputs
					{
						Extensions = true,
						CredProps = true
					};

					var options = fido2Library.RequestNewCredential(new RequestNewCredentialParams
					{
						User = fidoUser,
						ExcludeCredentials = existingDescriptors,
						AuthenticatorSelection = authenticatorSelection,
						AttestationPreference = attType.ToEnum<AttestationConveyancePreference>(),
						Extensions = exts
					});

					// 4. Temporarily store options in an encrypted cookie
					var encryptedOptions = this.EncryptedCookieManager.CreateEncryptedToken(options.ToJson());

					var fido2cookieOptions = new CookieOptions();
					fido2cookieOptions.Expires = DateTime.Now.AddMinutes(1);
					fido2cookieOptions.Domain = GetCookieDomain();
					fido2cookieOptions.Path = "/";
					fido2cookieOptions.IsEssential = true;
					Response.Cookies.Append("fido2.attestationOptions", Convert.ToBase64String(encryptedOptions), fido2cookieOptions);

					return Json(options);

				}
				catch (Exception e)
				{
					return Json(ErrorResponse(FormatException(e)));
				}
			}
			return Json(ErrorResponse("WebAuthn is not available."));
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

				if (string.IsNullOrEmpty(cookieOptions))
				{
					return Json(ErrorResponse("fido2.assertOptions is empty."));
				}
			
				var options = CredentialCreateOptions.FromJson(this.EncryptedCookieManager.DecryptAndValidateEncryptedToken(Convert.FromBase64String(cookieOptions)));

				// 1b. find User
				var user = await UserManager.FindByNameAsync(this.User?.Identity?.Name ?? String.Empty);

				if (user == null)
				{
					return Json(ErrorResponse($"Unable to load user with username: '{options.User.Name}'."));
				}

				// 2. Create callback so that lib can verify credential id is unique to this user
				//IsCredentialIdUniqueToUserAsyncDelegate callback = async (IsCredentialIdUniqueToUserParams args, CancellationToken cancellationToken) =>
				//{
				//	var users = await this.WebAuthnCredentialsStore.GetUsersByCredentialIdAsync(args.CredentialId);
				//	if (users.Count > 0) return false;

				//	return true;
				//};

				// 2. Verify and make the credentials.
				// 4.x returns the registered credential directly and throws on failure, where the
				// previous release wrapped it in a result object whose Result could be null.
				var credential = await fido2Library.MakeNewCredentialAsync(new MakeNewCredentialParams
				{
					AttestationResponse = attestationResponse,
					OriginalOptions = options,
					IsCredentialIdUniqueToUserCallback = IsCredentialIdUniqueToUserAsync
				});

				if (credential != null)
				{
					//2.1 find the user agent.
					string userAgentHeader = this.Request?.Headers?.UserAgent.ToString() ?? String.Empty;

					HttpUserAgentInformation userAgentInfo = new HttpUserAgentInformation();

					try
					{
						userAgentInfo = HttpUserAgentParser.Parse(userAgentHeader);
					}
					catch (Exception ex)
					{
						Trace.TraceWarning($"Could not parse the HTTP header 'User-Agent': \"{userAgentHeader}\". Reason: {ex.Message}");
					}

					AuthenticatorPlatformType platformType = AuthenticatorPlatformType.Unknown;
					var platformAuthenticator = options.AuthenticatorSelection.AuthenticatorAttachment == AuthenticatorAttachment.Platform ? true : false;
					if (userAgentInfo.Platform.HasValue && platformAuthenticator)
					{
						switch (userAgentInfo.Platform.Value.PlatformType)
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
						credential,
						user.ID ,
						platformType);
				}

				//can the action when registration succeeds, (e.g. log).
				await OnFidoCredentialsRegisteredSucceededdAsync(user);

				return Json(credential);
			}
			catch (Exception e)
			{


				return Json(ErrorResponse(FormatException(e)));
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

		/// <summary>
		/// Builds the failure payload the browser scripts expect: <c>{ status, errorMessage }</c>.
		/// </summary>
		/// <param name="errorMessage">The message to show the user.</param>
		/// <remarks>
		/// <para>
		/// Until FIDO2 4.x these fields came from <c>Fido2ResponseBase</c>, which every response model
		/// inherited, so an error could be reported by newing up any of them. 4.x deleted that base
		/// class: the success path now returns the bare model with no status field at all, and only
		/// failures are tagged. The library's own demo does exactly this.
		/// </para>
		/// <para>
		/// The property names are deliberately lower-case rather than PascalCase. This type is
		/// anonymous, so it is outside the FIDO2 namespace that
		/// <c>IgnoreDataMemberOverrideResolver</c> camel-cases in the Attendance host, and Newtonsoft
		/// would otherwise emit <c>"Status"</c> — which the scripts do not read. Naming the members
		/// this way serializes correctly under both Newtonsoft and System.Text.Json, so the two
		/// hosting applications agree.
		/// </para>
		/// </remarks>
		private static object ErrorResponse(string errorMessage) => new { status = "error", errorMessage };

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
