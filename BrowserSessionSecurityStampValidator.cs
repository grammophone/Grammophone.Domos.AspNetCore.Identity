using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Grammophone.Domos.DataAccess;
using Grammophone.Domos.Domain;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Grammophone.Domos.AspNetCore.Identity
{
	/// <summary>
	/// A security stamp validator to be used in combination with <see cref="BrowserSessionUserStore{UB, U, D}"/>
	/// to take into account the user's browser sessions.
	/// </summary>
	/// <typeparam name="UB">The base type of the user, derived from <see cref="User"/>.</typeparam>
	/// <typeparam name="U">The type of the user, derived from <typeparamref name="UB"/>.</typeparam>
	/// <typeparam name="D">The type of the domain container, derived from <see cref="IUsersDomainContainer{U}"/>.</typeparam>
	public class BrowserSessionSecurityStampValidator<UB, U, D> : SecurityStampValidator<U>
		where UB : User
		where U : UB
		where D : IUsersDomainContainer<UB>
	{
		#region Construction

		/// <summary>
		/// Create.
		/// </summary>
		/// <param name="options">Used to access the <see cref="SecurityStampValidatorOptions"/>.</param>
		/// <param name="signInManager">The sign-in manager.</param>
		/// <param name="logger">The logger.</param>
		/// <param name="userManager">The user manager.</param>
		public BrowserSessionSecurityStampValidator(
			IOptions<SecurityStampValidatorOptions> options, SignInManager<U> signInManager, ILoggerFactory logger, UserManager<U> userManager)
			: base(options, signInManager, logger)
		{
			if (userManager == null) throw new ArgumentNullException(nameof(userManager));

			this.UserManager = userManager as BrowserSessionUserManager<UB, U, D> ?? throw new IdentityException("The user manager does not derive from .");
		}

		/// <summary>
		/// Create.
		/// </summary>
		/// <param name="options">Used to access the <see cref="SecurityStampValidatorOptions"/>.</param>
		/// <param name="signInManager">The sign-in manager.</param>
		/// <param name="clock">The system clock.</param>
		/// <param name="logger">The logger.</param>
		/// <param name="userManager">The user manager.</param>
		[Obsolete]
		public BrowserSessionSecurityStampValidator(
			IOptions<SecurityStampValidatorOptions> options, SignInManager<U> signInManager, ISystemClock clock, ILoggerFactory logger, UserManager<U> userManager)
			: base(options, signInManager, clock, logger)
		{
			if (userManager == null) throw new ArgumentNullException(nameof(userManager));

			this.UserManager = userManager as BrowserSessionUserManager<UB, U, D> ?? throw new IdentityException("The user manager does not derive from .");
		}

		#endregion

		#region Public properties

		/// <summary>
		/// The user manager.
		/// </summary>
		public BrowserSessionUserManager<UB, U, D> UserManager { get; }

		#endregion

		#region Protected methods

		/// <summary>
		/// Find or create the browser session by fingerprint to validate the security stamp.
		/// </summary>
		protected override async Task<U?> VerifySecurityStamp(ClaimsPrincipal? principal)
		{
			if (principal != null)
			{
				string? fingerPrint = principal.FindFirstValue(IdentityClaimNames.Fingerprint);

				var user = await this.UserManager.GetUserAsync(principal);

				if (user != null)
				{
					string? securityStamp = (await this.UserManager.TryGetOrCreateBrowserSessionAsync(user, fingerPrint))?.SecurityStamp;

					string? securityStampClaim = principal.FindFirstValue("AspNet.Identity.SecurityStamp");

					if (securityStamp != null && securityStampClaim == securityStamp)
					{
						return user;
					}
				}
			}

			return null;
		}

		/// <inheritdoc/>
		protected override Task SecurityStampVerified(U user, CookieValidatePrincipalContext context)
		{
			//do not update principal as I need to pass the fingerprint to the SignInManager.Create....
			//var newPrincipal = await SignInManager.CreateUserPrincipalAsync(user); //await claimsPrincipalFactory.CreateAsync(user, context.Principal.FindFirstValue(IdentityClaimNames.Fingerprint));//await SignInManager.CreateUserPrincipalAsync(user);

			//if (Options.OnRefreshingPrincipal != null)
			//{
			//	var replaceContext = new SecurityStampRefreshingPrincipalContext
			//	{
			//		CurrentPrincipal = context.Principal,
			//		NewPrincipal = newPrincipal
			//	};

			//	// Note: a null principal is allowed and results in a failed authentication.
			//	await Options.OnRefreshingPrincipal(replaceContext);
			//	newPrincipal = replaceContext.NewPrincipal;
			//}

			// REVIEW: note we lost login authentication method

			if (context.Principal != null)
			{
				context.ReplacePrincipal(context.Principal); // newPrincipal);
				context.ShouldRenew = true;

				if (!context.Options.SlidingExpiration)
				{
					// On renewal calculate the new ticket length relative to now to avoid
					// extending the expiration.
					context.Properties.IssuedUtc = TimeProvider.GetUtcNow();
				}
			}

			return Task.CompletedTask;
		}

		#endregion
	}

	/// <summary>
	/// A security stamp validator to be used in combination with <see cref="BrowserSessionUserStore{UB, U, D}"/>
	/// to take into account the user's browser sessions.
	/// </summary>
	/// <typeparam name="U">The type of the user, derived from <see cref="User"/>.</typeparam>
	/// <typeparam name="D">The type of the domain container, derived from <see cref="IUsersDomainContainer{U}"/>.</typeparam>
	public class BrowserSessionSecurityStampValidator<U, D> : BrowserSessionSecurityStampValidator<U, U, D>
		where U : User
		where D : IUsersDomainContainer<U>
	{
		/// <inheritdoc/>
		public BrowserSessionSecurityStampValidator(
			IOptions<SecurityStampValidatorOptions> options,
			SignInManager<U> signInManager,
			ILoggerFactory logger,
			UserManager<U> userManager) : base(options, signInManager, logger, userManager)
		{
		}
	}
}
