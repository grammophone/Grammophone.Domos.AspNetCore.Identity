using System;
using System.Collections.Generic;
using System.Linq;
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

namespace Grammophone.Domos.AspNetCore.Identity.Controllers.Api
{
	/// <summary>
	/// Payload for Fido2 assertion operations.
	/// </summary>
	public class AssertOptionsRequest
	{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
		public string username { get; set; } = String.Empty;

		public string userVerification { get; set; } = String.Empty;

		public string rememberBrowser { get; set; } = "false";

		public string returnUrl { get; set; } = String.Empty;
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
	}

	/// <summary>
	/// An API controller for signing in users with WebAuthn.
	/// </summary>
	/// <typeparam name="UB">The base type of the user, derived from <see cref="User"/>.</typeparam>
	/// <typeparam name="U">The type of the user, derived from <typeparamref name="UB"/>.</typeparam>
	/// <typeparam name="D">The type of the domain container, derived from <see cref="IUsersDomainContainer{U}"/>.</typeparam>
	[ApiController]
	[ApiExplorerSettings(IgnoreApi = true)]
	public class AccountApiController<UB, U, D> : Controller
			where UB : User
			where U : UB
			where D : IUsersDomainContainer<UB>
	{
		#region Private Readonly

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
		public AccountApiController(
			SignInManager<U> signInManager,
			UserManager<U> userManager,
			WebAuthnCredentialsStore<UB, U, D> webAuthnCredentialsStore,
			IOptions<Fido2Configuration> optionsFido2Configuration,
			IEncryptedCookieManager encrypteCookieManager
			)
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

		#region webAuthn

		#region login

		/// <summary>
		/// Get Assertation options for login with WebAuthn (passwordless).
		/// </summary>
		[AllowAnonymous]
		[HttpPost]
		[Route("AssertionOptionsPost")]
		//[ValidateAntiForgeryToken]
		public async Task<JsonResult> AssertionOptionsPost(AssertOptionsRequest request)
		{
			if (System.Configuration.ConfigurationManager.AppSettings["enableWebAuthn"]?.ToLower() == "true")
			{
				var username = request.username;
				var userVerification = request.userVerification;

				try
				{
					var existingCredentials = new List<PublicKeyCredentialDescriptor>();

					if (!string.IsNullOrEmpty(username))
					{
						var identityUser = await this.UserManager.FindByNameAsync(username);
						if (identityUser == null) throw new ArgumentException("Username not found");

						var user = new Fido2User
						{
							DisplayName = identityUser.UserName,
							Name = identityUser.UserName,
							Id = this.WebAuthnCredentialsStore.GetUserNameInBytes(identityUser.UserName) // byte representation of userID is required
						};

						if (user == null) throw new ArgumentException("Username was not registered");

						// 2. Get registered credentials from database
						existingCredentials = (await this.WebAuthnCredentialsStore.GetDescriptorsByLogicUserNameAsync(identityUser.UserName)).ToList();
					}

					// The uvm extension was dropped by the FIDO2 library in 4.x. Its output was never
					// read here; user verification is requested through UserVerification below, which
					// is the part that actually governs whether the authenticator verifies the user.
					var exts = new AuthenticationExtensionsClientInputs();

					// 3. Create options
					var uv = string.IsNullOrEmpty(userVerification) ? UserVerificationRequirement.Discouraged : userVerification.ToEnum<UserVerificationRequirement>();
					var options = this.fido2Library.GetAssertionOptions(new GetAssertionOptionsParams
					{
						AllowedCredentials = existingCredentials,
						UserVerification = uv,
						Extensions = exts
					});

					// 4. Temporarily store options in an encrypted cookie.
					var encryptedOptions = this.EncryptedCookieManager.CreateEncryptedToken(options.ToJson()); //SignInManager.CreateEncryptedToken(options.ToJson());

					//var cookie = new ("fido2.assertionOptions", Convert.ToBase64String(encryptedOptions));
					var fido2CookieOptions = new CookieOptions();
					fido2CookieOptions.Expires = DateTimeOffset.Now.AddMinutes(4);
					fido2CookieOptions.Domain = GetCookieDomain();
					fido2CookieOptions.Path = "/";
					fido2CookieOptions.IsEssential = true;
					Response.Cookies.Append("fido2.assertionOptions", Convert.ToBase64String(encryptedOptions), fido2CookieOptions);

					//5. add the returnUrl as a cookie
					var returnUrlCookieOptions = new CookieOptions();
					returnUrlCookieOptions.Expires = DateTimeOffset.Now.AddMinutes(4);

					//var returnUrlCookie = new Microsoft.Net.Http.Headers.CookieHeaderValue("returnUrl", request.returnUrl);
					returnUrlCookieOptions.Domain = GetCookieDomain();
					returnUrlCookieOptions.Path = "/";
					Response.Cookies.Append("returnUrl", request.returnUrl, returnUrlCookieOptions);

					// 6. Return options to client
					//return response;
					return Json(options);
				}

				catch (Exception e)
				{
					return Json(ErrorResponse(FormatException(e)));
				}
			}
			else
			{
				return Json(ErrorResponse("WebAuthn is not available."));
			}
		}

		/// <summary>
		/// Login using WebAuthn.
		/// </summary>
		/// <param name="clientResponse"></param>
		/// <returns></returns>
		[AllowAnonymous]
		[HttpPost]
		[Route("MakeAssertion")]
		//[ValidateAntiForgeryToken]
		public async Task<JsonResult> MakeAssertion(AuthenticatorAssertionRawResponse clientResponse)
		{
			try
			{
				// 1. Get the assertion options we sent the client by decrypting the cookie.
				var cookieOptions = Request.Cookies["fido2.assertionOptions"]!;
				if (string.IsNullOrEmpty(cookieOptions))
				{
					return Json(ErrorResponse("fido2.assertOptions is empty."));
				}

				var options = AssertionOptions.FromJson(this.EncryptedCookieManager.DecryptAndValidateEncryptedToken(Convert.FromBase64String(cookieOptions))); //SignInManager.DecryptAndValidateEncryptedToken(Convert.FromBase64String(cookieOptions))); ;

				// 2. Get registered credential from database.
				// RawId, not Id: 4.x redefined Id as the base64url string the browser sent and left
				// RawId holding the decoded bytes that Id used to carry, which is what is stored.
				var creds = await this.WebAuthnCredentialsStore.TryGetCredentialByIdAsync(clientResponse.RawId);

				if (creds == null)
				{
					throw new IdentityException("Unknown credentials");
				}

				// 3. Get credential counter from database
				var storedCounter = creds.SignatureCounter;

				if (creds.PublicKey == null)
				{
					throw new InvalidOperationException($"No public key");
				}

				// 4. Make the assertion
				var res = await this.fido2Library.MakeAssertionAsync(new MakeAssertionParams
				{
					AssertionResponse = clientResponse,
					OriginalOptions = options,
					StoredPublicKey = creds.PublicKey,
					StoredSignatureCounter = storedCounter,
					IsUserHandleOwnerOfCredentialIdCallback = IsUserHandleOwnerOfCredentialIdAsync
				});

				// 5. Store the updated counter
				await this.WebAuthnCredentialsStore.UpdateCounterAsync(
					res.CredentialId, res.SignCount);

				var identityUser = await UserManager.FindByIdAsync(creds.OwnerID.ToString());

				if (identityUser == null)
				{
					throw new InvalidOperationException($"Unable to load user.");
				}

				await this.SignInManager.SignInAsync(identityUser, isPersistent: true);

				await OnLoginSucceededdAsync(identityUser);

				return Json(res);
			}
			catch (Exception e)
			{
				if (e.Message.Contains("Security Timestamp has expired"))
				{
					return Json(ErrorResponse("You login session expired. You did not manage to provide your passkey or your security key in the given time (30 sec). Please try again."));
				}
				else
				{
					return Json(ErrorResponse("We couldn't verify you or the key you used. If you are using a security key, make sure this is your key and try again."));
				}
			}
		}

    #endregion

    #region mfa

    /// <summary>
    /// Get Assertation options for Mfa with WebAuthn.
    /// </summary>
    [AllowAnonymous]
    [HttpPost]
		[Route("AssertionMFAOptionsPost")]
		//[ValidateAntiForgeryToken]
		public async Task<JsonResult> AssertionMFAOptionsPost(AssertOptionsRequest request)
		{
			if (System.Configuration.ConfigurationManager.AppSettings["enableWebAuthn"]!.ToLower() == "true")
			{
				try
				{
					var identityUser = await SignInManager.GetTwoFactorAuthenticationUserAsync(); //GetVerifiedUserIdAsync();

					if (identityUser == null)
					{
						return Json(StatusResponse("sessionExpired", "Security Session Expired due to inactivity."));
					}

					var existingCredentials = new List<PublicKeyCredentialDescriptor>();

					if (!string.IsNullOrEmpty(identityUser.UserName))
					{
						var user = new Fido2User
						{
							DisplayName = identityUser.UserName,
							Name = identityUser.UserName,
							Id = this.WebAuthnCredentialsStore.GetUserNameInBytes(identityUser.UserName) // byte representation of userID is required
						};

						if (user == null) throw new ArgumentException("User is not registered");

						// 2. Get registered credentials from database
						existingCredentials = (await this.WebAuthnCredentialsStore.GetDescriptorsByLogicUserNameAsync(identityUser.UserName)).ToList();
					}

					// The uvm extension was dropped by the FIDO2 library in 4.x; see the note on the
					// equivalent call in AssertionOptionsPost.
					var exts = new AuthenticationExtensionsClientInputs();

					// 3. Create options
					var uv = string.IsNullOrEmpty(request.userVerification) ? UserVerificationRequirement.Discouraged : request.userVerification.ToEnum<UserVerificationRequirement>();
					var options = this.fido2Library.GetAssertionOptions(new GetAssertionOptionsParams
					{
						AllowedCredentials = existingCredentials,
						UserVerification = uv,
						Extensions = exts
					});

					// 4. Temporarily store options in an encrypted cookie.
					var encryptedOptions = this.EncryptedCookieManager.CreateEncryptedToken(options.ToJson());

					var cookieOptions = new CookieOptions();


					//var cookie = new CookieHeaderValue("fido2.assertionOptionsMFA", Convert.ToBase64String(encryptedOptions));
					cookieOptions.Expires = DateTimeOffset.Now.AddMinutes(1); //should take it from configuration
					cookieOptions.Domain = GetCookieDomain();
					cookieOptions.Path = "/";
					Response.Cookies.Append("fido2.assertionOptionsMFA", Convert.ToBase64String(encryptedOptions), cookieOptions);
					//var response = this.Request.CreateResponse<AssertionOptions>(options);

					// 5. add a cookie with the remeberbrowser value
					//var rememberBrowserCookie = new CookieHeaderValue("rememberBrowser", request.rememberBrowser.ToString());
					//rememberBrowserCookie.Expires = DateTimeOffset.Now.AddMinutes(1);
					//rememberBrowserCookie.Domain = ".lifeaccount.ca";
					//rememberBrowserCookie.Path = "/";
					Response.Cookies.Append("rememberBrowser", request.rememberBrowser, cookieOptions);

					//response.Headers.AddCookies(new CookieHeaderValue[] { cookie, rememberBrowserCookie });

					// 6. Return options to client
					return Json(options);
				}

				catch (Exception e)
				{
					return Json(ErrorResponse(FormatException(e)));
				}
			}
			else
			{
				return Json(ErrorResponse("WebAuthn is not available."));
			}
		}

		/// <summary>
		/// Login using WebAuthn.
		/// </summary>
		/// <param name="clientResponse"></param>
		/// <returns></returns>
		[AllowAnonymous]
		[HttpPost]
		[Route("ValidateAccessMFA")]
		//[ValidateAntiForgeryToken]
		public async Task<JsonResult> ValidateAccessMFA(AuthenticatorAssertionRawResponse clientResponse)
		{
			try
			{
				// 1. Get the assertion options we sent the client by decrypting the cookie.
				var cookieOptions = Request.Cookies["fido2.assertionOptionsMFA"];

				if (cookieOptions == null) throw new ApplicationException("The cookie 'fido2.assertionOptionsMFA' is not present.");

				var rememberBrowser = Request.Cookies["rememberBrowser"] ?? "false";

				//var encryptedCookie = cookieOptions["fido2.assertionOptionsMFA"].Value;
				var options = AssertionOptions.FromJson(this.EncryptedCookieManager.DecryptAndValidateEncryptedToken(Convert.FromBase64String(cookieOptions)));

				// 2. Get registered credential from database.
				// RawId, not Id — see the note on the equivalent lookup in MakeAssertion.
				var creds = await this.WebAuthnCredentialsStore.TryGetCredentialByIdAsync(clientResponse.RawId);

				if (creds == null)
				{
					throw new Exception("Unknown credentials");
				}

				// 3. Get credential counter from database
				var storedCounter = creds.SignatureCounter;

				if (creds.PublicKey == null)
				{
					throw new InvalidOperationException($"No public key");
				}

				// 4. Make the assertion
				var res = await this.fido2Library.MakeAssertionAsync(new MakeAssertionParams
				{
					AssertionResponse = clientResponse,
					OriginalOptions = options,
					StoredPublicKey = creds.PublicKey,
					StoredSignatureCounter = storedCounter,
					IsUserHandleOwnerOfCredentialIdCallback = IsUserHandleOwnerOfCredentialIdAsync
				});

				// 6. Store the updated counter
				await this.WebAuthnCredentialsStore.UpdateCounterAsync(res.CredentialId, res.SignCount);

				//complete sign-in
				var identityUser = await UserManager.FindByIdAsync(creds.OwnerID.ToString());
				if (identityUser == null)
				{
					throw new InvalidOperationException($"Unable to load user.");
				}

				//var result = await SignInManager.TwoFactorSignInAsync(ApplicationUserManager.SecurityKey, string.Empty, false, rememberBrowser: rememberBrowser.ToLower() == "true");
				var result = await SignInManager.TwoFactorSignInAsync("FIDO2", string.Empty, false, rememberBrowser.ToLower() == "true");

				if (result == Microsoft.AspNetCore.Identity.SignInResult.Success)
				{
					await On2faLoginSucceededAsync(identityUser);
				}
				else
				{
					await OnUserVerificationFailedAsync(identityUser);
				}

				return Json(res);
			}
			catch (Exception e)
			{
				return Json(ErrorResponse(FormatException(e)));
			}
		}

		#endregion

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
		/// Called when the user is validated and logged in successfully.
		/// </summary>
		protected virtual Task OnLoginSucceededdAsync(U user) => Task.CompletedTask;

		/// <summary>
		/// Called when the user is validated and logged in successfully during a two-factor authentication.
		/// </summary>
		protected virtual Task On2faLoginSucceededAsync(U user) => Task.CompletedTask;

		/// <summary>
		/// Called when the verification of the user failed.
		/// </summary>
		protected virtual Task OnUserVerificationFailedAsync(U user) => Task.CompletedTask;

		#endregion

		#region Private methods

		private async Task<bool> IsUserHandleOwnerOfCredentialIdAsync(IsUserHandleOwnerOfCredentialIdParams args, CancellationToken cancellationChangeToken)
		{
			var foundStoredCredentials = from d in await this.WebAuthnCredentialsStore.GetDescriptorsByUserHandleAsync(args.UserHandle)
																	 where d.Id.SequenceEqual(args.CredentialId)
																	 select d;

			return foundStoredCredentials.Any();
		}


		private static string FormatException(Exception e)
		{
			return string.Format("{0}{1}", e.Message, e.InnerException != null ? " (" + e.InnerException.Message + ")" : "");
		}

		/// <summary>
		/// Builds a non-success payload in the shape the browser scripts expect:
		/// <c>{ status, errorMessage }</c>.
		/// </summary>
		/// <param name="status">The status to report — <c>"error"</c>, or <c>"sessionExpired"</c>,
		/// which the MFA scripts handle separately by redirecting rather than alerting.</param>
		/// <param name="errorMessage">The message to show the user.</param>
		/// <remarks>
		/// <para>
		/// Until FIDO2 4.x these fields came from <c>Fido2ResponseBase</c>, which every response model
		/// inherited, so a status could be reported by newing up any of them. 4.x deleted that base
		/// class: the success path now returns the bare model with no status field at all, and only
		/// non-success responses are tagged. The library's own demo does exactly this.
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
		private static object StatusResponse(string status, string errorMessage) => new { status, errorMessage };

		/// <summary>
		/// Builds the failure payload the browser scripts expect. See <see cref="StatusResponse"/>.
		/// </summary>
		/// <param name="errorMessage">The message to show the user.</param>
		private static object ErrorResponse(string errorMessage) => StatusResponse("error", errorMessage);

		#endregion
	}

	/// <summary>
	/// An API controller for signing in users with WebAuthn.
	/// </summary>
	/// <typeparam name="U">The type of the user, derived from <see cref="User"/>.</typeparam>
	/// <typeparam name="D">The type of the domain container, derived from <see cref="IUsersDomainContainer{U}"/>.</typeparam>
	public class AccountApiController<U, D> : AccountApiController<U, U, D>
		where U : User
		where D : IUsersDomainContainer<U>
	{
		#region Construction

		/// <inheritdoc/>
		public AccountApiController(
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
