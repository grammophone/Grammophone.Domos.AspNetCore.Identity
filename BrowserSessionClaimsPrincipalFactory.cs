using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Grammophone.Domos.DataAccess;
using Grammophone.Domos.Domain;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace Grammophone.Domos.AspNetCore.Identity
{
	/// <summary>
	/// An specialization of <see cref="UserClaimsPrincipalFactory{U}"/> that adds the fingerprint claim
	/// to a user principal, if possible.
	/// </summary>
	/// <typeparam name="UB">The base type of the user, derived from <see cref="User"/>.</typeparam>
	/// <typeparam name="U">The type of the user, derived from <typeparamref name="UB"/>.</typeparam>
	/// <typeparam name="D">The type of the domain container, derived from <see cref="IUsersDomainContainer{U}"/>.</typeparam>
	public class BrowserSessionClaimsPrincipalFactory<UB, U, D> : UserClaimsPrincipalFactory<U, Role>
		where UB : User
		where U : UB
		where D : IUsersDomainContainer<UB>
	{
		#region Private fields

		private readonly IHttpContextAccessor httpContextAccessor;

		#endregion

		#region Construction

		/// <summary>
		/// Create.
		/// </summary>
		/// <param name="userManager">The user manager to retrive information from. Must be derived from <see cref="BrowserSessionUserManager{UB, U, D}"/>.</param>
		/// <param name="roleManager">The role manager.</param>
		/// <param name="optionsAccessor">The configured <see cref="IdentityOptions"/>.</param>
		/// <param name="httpContextAccessor">The accessor to <see cref="HttpContext"/>.</param>
		/// <exception cref="ArgumentNullException"></exception>
		public BrowserSessionClaimsPrincipalFactory(
			UserManager<U> userManager,
			RoleManager<Role> roleManager,
			IOptions<IdentityOptions> optionsAccessor,
			IHttpContextAccessor httpContextAccessor)
			: base(userManager, roleManager, optionsAccessor)
		{
			if (httpContextAccessor == null) throw new ArgumentNullException(nameof(httpContextAccessor));

			this.httpContextAccessor = httpContextAccessor;

			this.UserManager = userManager as BrowserSessionUserManager<UB, U, D> ?? throw new IdentityException("The user manager does not derive from BrowserSessionUserManager");
		}

		#endregion

		#region Public properties

		/// <summary>
		/// The user manager, capable of handling browser sessions.
		/// </summary>
		public new BrowserSessionUserManager<UB, U, D> UserManager { get; }

		#endregion

		#region Public methods

		/// <summary>
		/// If the current user has a 'fingerprint' claim, add it to the new identity.
		/// </summary>
		protected override async Task<ClaimsIdentity> GenerateClaimsAsync(U user)
		{
			var identity = await base.GenerateClaimsAsync(user);

			var currentUser = httpContextAccessor.HttpContext?.User;

			string? fingerprint = null;

			if (currentUser != null)
			{
				var fingerprintClaim = currentUser.Claims.Where(c => c.Type == IdentityClaimNames.Fingerprint).FirstOrDefault();

				fingerprint = fingerprintClaim?.Value;
			}

			var browserSession = await this.UserManager.TryGetOrCreateBrowserSessionAsync(user, fingerprint);

			if (browserSession != null)
			{
				identity.AddClaim(new Claim(Options.ClaimsIdentity.SecurityStampClaimType, browserSession.SecurityStamp));
				identity.AddClaim(new Claim(IdentityClaimNames.Fingerprint, browserSession.FingerPrint));
			}

			return identity;
		}

		#endregion
	}

	/// <summary>
	/// An specialization of <see cref="UserClaimsPrincipalFactory{U}"/> that adds the fingerprint claim
	/// to a user principal, if possible.
	/// </summary>
	/// <typeparam name="U">The type of the user, derived from <see cref="User"/>.</typeparam>
	/// <typeparam name="D">The type of the domain container, derived from <see cref="IUsersDomainContainer{U}"/>.</typeparam>
	public class BrowserSessionClaimsPrincipalFactory<U, D> : BrowserSessionClaimsPrincipalFactory<U, U, D>
		where U : User
		where D : IUsersDomainContainer<U>
	{
		/// <inheritdoc/>
		public BrowserSessionClaimsPrincipalFactory(
			UserManager<U> userManager,
			RoleManager<Role> roleManager, 
			IOptions<IdentityOptions> optionsAccessor,
			IHttpContextAccessor httpContextAccessor)
			: base(userManager, roleManager, optionsAccessor, httpContextAccessor)
		{
		}
	}
}
