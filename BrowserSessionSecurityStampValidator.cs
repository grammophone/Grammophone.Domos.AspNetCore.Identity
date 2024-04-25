using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Grammophone.Domos.Domain;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Identity.Core;
using Microsoft.Extensions.Options;

namespace Grammophone.Domos.AspNetCore.Identity
{
	/// <summary>
	/// A security stamp validator to be used in combination with <see cref="BrowserSessionUserStore{UB, U, D}"/>
	/// to take into account the user's browser sessions.
	/// </summary>
	/// <typeparam name="U">The type of the user, derived from <see cref="User"/>.</typeparam>
	public class BrowserSessionSecurityStampValidator<U> : SecurityStampValidator<U>
		where U : User
	{
		#region Privat efields

		private readonly IHttpContextAccessor httpContextAccessor;

		#endregion

		#region Construction

		/// <summary>
		/// Create.
		/// </summary>
		/// <param name="options">Used to access the <see cref="SecurityStampValidatorOptions"/>.</param>
		/// <param name="signInManager">The sign-in manager.</param>
		/// <param name="logger">The logger.</param>
		/// <param name="httpContextAccessor">The accessor to <see cref="HttpContext"/>.</param>
		public BrowserSessionSecurityStampValidator(
			IOptions<SecurityStampValidatorOptions> options, SignInManager<U> signInManager, ILoggerFactory logger, IHttpContextAccessor httpContextAccessor)
			: base(options, signInManager, logger)
		{
			if (httpContextAccessor == null) throw new ArgumentNullException(nameof(httpContextAccessor));

			this.httpContextAccessor = httpContextAccessor;
		}

		/// <summary>
		/// Create.
		/// </summary>
		/// <param name="options">Used to access the <see cref="SecurityStampValidatorOptions"/>.</param>
		/// <param name="signInManager">The sign-in manager.</param>
		/// <param name="clock">The system clock.</param>
		/// <param name="logger">The logger.</param>
		/// <param name="httpContextAccessor">The accessor to <see cref="HttpContext"/>.</param>
		[Obsolete]
		public BrowserSessionSecurityStampValidator(
			IOptions<SecurityStampValidatorOptions> options, SignInManager<U> signInManager, ISystemClock clock, ILoggerFactory logger, IHttpContextAccessor httpContextAccessor)
			: base(options, signInManager, clock, logger)
		{
			if (httpContextAccessor == null) throw new ArgumentNullException(nameof(httpContextAccessor));

			this.httpContextAccessor = httpContextAccessor;
		}

		#endregion

		#region Protected methods

		/// <summary>
		/// Set the <paramref name="principal"/> into the current <see cref="HttpContext.Items"/>
		/// under the key "ValidatedIdentity" before proceeding with standard security stamp validation.
		/// </summary>
		/// <param name="principal">The principal whose security stamp tp validate.</param>
		/// <returns>Returns the verified user or null if the verification fails.</returns>
		protected override async Task<U?> VerifySecurityStamp(ClaimsPrincipal? principal)
		{
			if (principal?.Identity != null && httpContextAccessor.HttpContext != null)
			{
				httpContextAccessor.HttpContext.Items["ValidatedIdentity"] = principal.Identity;
			}

			return await base.VerifySecurityStamp(principal);
		}

		public override async Task ValidateAsync(CookieValidatePrincipalContext context)
		{
			bool addedFingerprintClaim = false;

			ClaimsIdentity? claimsIdentity = context.Principal?.Identity as ClaimsIdentity;

			U? user = null;

			if (claimsIdentity != null)
			{
				httpContextAccessor.HttpContext?.Items.Add("ValidatedIdentity", claimsIdentity);

				string? fingerprint = claimsIdentity.Claims.FirstOrDefault(c => c.Type == "fingerprint")?.Value;

				if (String.IsNullOrEmpty(fingerprint))
				{
					claimsIdentity.AddClaim(new Claim("fingerprint", Guid.NewGuid().ToString()));

					addedFingerprintClaim = true;

					var userManager = this.SignInManager.UserManager; //context.OwinContext.GetUserManager<US>();

					if (userManager != null)
					{
						string? userID = claimsIdentity.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;

						if (userID != null)
						{
							user = await userManager.FindByIdAsync(userID);

							if (user != null)
							{
								// If the IUserStore descends from BrowserSessionUserStore, force creating a browser session and adding of the fingerprint claim.
								await userManager.GetSecurityStampAsync(user);
							}
						}
					}
				}
			}

			await base.ValidateAsync(context);

			if (addedFingerprintClaim && user != null) // If not rejected and added fingerprint, update sign-on.
			{
				context.ReplacePrincipal(context.Principal!);

				//await this.SignInManager.SignInAsync(user, context.Properties);
			}

		}

		#endregion
	}
}
