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

					var exts = new AuthenticationExtensionsClientInputs
					{
						UserVerificationMethod = true, //request for the authenticator to verify the user, so we do not need to use 2fa.
					};

					// 3. Create options
					var uv = string.IsNullOrEmpty(userVerification) ? UserVerificationRequirement.Discouraged : userVerification.ToEnum<UserVerificationRequirement>();
					var options = this.fido2Library.GetAssertionOptions(
							existingCredentials,
							uv,
							exts
					);

					// 4. Temporarily store options in an encrypted cookie.
					var encryptedOptions = this.EncryptedCookieManager.CreateEncryptedToken(options.ToJson()); //SignInManager.CreateEncryptedToken(options.ToJson());

					//var cookie = new ("fido2.assertionOptions", Convert.ToBase64String(encryptedOptions));
					var fido2CookieOptions = new CookieOptions();
					fido2CookieOptions.Expires = DateTimeOffset.Now.AddMinutes(4);
					fido2CookieOptions.Domain = cookieDomain;
					fido2CookieOptions.Path = "/";
					fido2CookieOptions.IsEssential = true;
					Response.Cookies.Append("fido2.assertionOptions", Convert.ToBase64String(encryptedOptions), fido2CookieOptions);

					//5. add the returnUrl as a cookie
					var returnUrlCookieOptions = new CookieOptions();
					returnUrlCookieOptions.Expires = DateTimeOffset.Now.AddMinutes(4);

					//var returnUrlCookie = new Microsoft.Net.Http.Headers.CookieHeaderValue("returnUrl", request.returnUrl);
					returnUrlCookieOptions.Domain = cookieDomain;
					returnUrlCookieOptions.Path = "/";
					Response.Cookies.Append("returnUrl", request.returnUrl, returnUrlCookieOptions);

					// 6. Return options to client
					//return response;
					return Json(options);
				}

				catch (Exception e)
				{
					return Json(new AssertionOptions { Status = "error", ErrorMessage = FormatException(e) });
				}
			}
			else
			{
				return Json(new AssertionOptions { Status = "error", ErrorMessage = "WebAuthn is not available." });
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
				if (cookieOptions.IsNullOrEmpty())
				{
					return Json(new VerifyAssertionResult { Status = "error", ErrorMessage = "fido2.assertOptions is empty." });
				}

				var options = AssertionOptions.FromJson(this.EncryptedCookieManager.DecryptAndValidateEncryptedToken(Convert.FromBase64String(cookieOptions))); //SignInManager.DecryptAndValidateEncryptedToken(Convert.FromBase64String(cookieOptions))); ;

				// 2. Get registered credential from database
				var creds = await this.WebAuthnCredentialsStore.TryGetCredentialByIdAsync(clientResponse.Id);

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
				var res = await this.fido2Library.MakeAssertionAsync(
						clientResponse, 
						options, creds.PublicKey, null
						,storedCounter, IsUserHandleOwnerOfCredentialIdAsync);

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
					return Json(new VerifyAssertionResult { Status = "error", ErrorMessage = "You login session expired. You did not manage to provide your passkey or your security key in the given time (30 sec). Please try again." });
				}
				else
				{
					return Json(new VerifyAssertionResult { Status = "error", ErrorMessage = "We couldn't verify you or the key you used. If you are using a security key, make sure this is your key and try again." });
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
						return Json(new AssertionOptions { Status = "sessionExpired", ErrorMessage = "Security Session Expired due to inactivity." });
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

					var exts = new AuthenticationExtensionsClientInputs
					{
						UserVerificationMethod = true,
					};

					// 3. Create options
					var uv = string.IsNullOrEmpty(request.userVerification) ? UserVerificationRequirement.Discouraged : request.userVerification.ToEnum<UserVerificationRequirement>();
					var options = this.fido2Library.GetAssertionOptions(
							existingCredentials,
							uv,
							exts
					);

					// 4. Temporarily store options in an encrypted cookie.
					var encryptedOptions = this.EncryptedCookieManager.CreateEncryptedToken(options.ToJson());

					var cookieOptions = new CookieOptions();


					//var cookie = new CookieHeaderValue("fido2.assertionOptionsMFA", Convert.ToBase64String(encryptedOptions));
					cookieOptions.Expires = DateTimeOffset.Now.AddMinutes(1); //should take it from configuration
					cookieOptions.Domain = cookieDomain;
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
					return Json(new AssertionOptions { Status = "error", ErrorMessage = FormatException(e) });
				}
			}
			else
			{
				return Json(new AssertionOptions { Status = "error", ErrorMessage = "WebAuthn is not available." });
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

				// 2. Get registered credential from database
				var creds = await this.WebAuthnCredentialsStore.TryGetCredentialByIdAsync(clientResponse.Id);

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
				var res = await this.fido2Library.MakeAssertionAsync(
						clientResponse, options, creds.PublicKey,null ,storedCounter, IsUserHandleOwnerOfCredentialIdAsync);

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
				return Json(new VerifyAssertionResult { Status = "error", ErrorMessage = FormatException(e) });
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
