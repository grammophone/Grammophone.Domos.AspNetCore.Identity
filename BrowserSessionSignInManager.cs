using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Grammophone.Domos.DataAccess;
using Grammophone.Domos.Domain;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Grammophone.Domos.AspNetCore.Identity
{
	/// <summary>
	/// A sign-in manager that is able to handle browser sessions. The user manager must be a <see cref="BrowserSessionUserManager{UB, U, D}"/>.
	/// </summary>
	/// <typeparam name="UB">The base type of the user, derived from <see cref="User"/>.</typeparam>
	/// <typeparam name="U">The type of the user, derived from <typeparamref name="UB"/>.</typeparam>
	/// <typeparam name="D">The type of the domain container, derived from <see cref="IUsersDomainContainer{U}"/>.</typeparam>
	public class BrowserSessionSignInManager<UB, U, D> : SignInManager<U>
		where UB : User
		where U : UB
		where D : IUsersDomainContainer<UB>
	{
		#region Construction

		/// <inheritdoc/>
		public BrowserSessionSignInManager(
			UserManager<U> userManager,
			IHttpContextAccessor contextAccessor,
			IUserClaimsPrincipalFactory<U> claimsFactory,
			IOptions<IdentityOptions> optionsAccessor,
			ILogger<SignInManager<U>> logger,
			IAuthenticationSchemeProvider schemes,
			IUserConfirmation<U> confirmation) : base(userManager, contextAccessor, claimsFactory, optionsAccessor, logger, schemes, confirmation)
		{
			this.UserManager = userManager as BrowserSessionUserManager<UB, U, D> ?? throw new IdentityException("The user manager does not derive from BrowserSessionUserManager.");
		}

		#endregion

		#region Public properties

		/// <summary>
		/// The user manager.
		/// </summary>
		public new BrowserSessionUserManager<UB, U, D> UserManager { get; }

		#endregion

		#region Public methods

		/// <inheritdoc/>
		public override async Task SignOutAsync()
		{
			var user = this.Context.User;

			if (user != null)
			{
				var identity = user.Identity as ClaimsIdentity;

				if (identity != null)
				{
					string? fingerprint = identity.FindFirst("fingerprint")?.Value;

					if (!String.IsNullOrWhiteSpace(fingerprint))
					{
						await this.UserManager.LogOffBrowserSessionAsync(identity.Name!, fingerprint);
					}
				}
			}

			await base.SignOutAsync();
		}

		#endregion
	}

	/// <summary>
	/// A sign-in manager that is able to handle browser sessions. The user manager must be a <see cref="BrowserSessionUserManager{U, U, D}"/>.
	/// </summary>
	/// <typeparam name="U">The type of the user, derived from <see cref="User"/>.</typeparam>
	/// <typeparam name="D">The type of the domain container, derived from <see cref="IUsersDomainContainer{U}"/>.</typeparam>
	public class BrowserSessionSignInManager<U, D> : BrowserSessionSignInManager<U, U, D>
		where U : User
		where D : IUsersDomainContainer<U>
	{
		/// <inheritdoc/>
		public BrowserSessionSignInManager(
			UserManager<U> userManager,
			IHttpContextAccessor contextAccessor,
			IUserClaimsPrincipalFactory<U> claimsFactory,
			IOptions<IdentityOptions> optionsAccessor, ILogger<SignInManager<U>> logger,
			IAuthenticationSchemeProvider schemes,
			IUserConfirmation<U> confirmation)
			: base(userManager, contextAccessor, claimsFactory, optionsAccessor, logger, schemes, confirmation)
		{
		}
	}
}
