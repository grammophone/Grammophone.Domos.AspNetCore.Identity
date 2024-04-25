using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
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
	/// <typeparam name="U">The type of the user, derived from <see cref="User"/>.</typeparam>
	public class BrowserSessionClaimsPrincipalFactory<U> : UserClaimsPrincipalFactory<U>
		where U : User
	{
		#region Private fields

		private readonly IHttpContextAccessor httpContextAccessor;

		#endregion

		#region Construction

		/// <summary>
		/// Create.
		/// </summary>
		/// <param name="userManager">The user manager to retrive information from.</param>
		/// <param name="optionsAccessor">The configured <see cref="IdentityOptions"/>.</param>
		/// <param name="httpContextAccessor">The accessor to <see cref="HttpContext"/>.</param>
		/// <exception cref="ArgumentNullException"></exception>
		public BrowserSessionClaimsPrincipalFactory(
			UserManager<U> userManager,
			IOptions<IdentityOptions> optionsAccessor,
			IHttpContextAccessor httpContextAccessor)
			: base(userManager, optionsAccessor)
		{
			if (httpContextAccessor == null) throw new ArgumentNullException(nameof(httpContextAccessor));

			this.httpContextAccessor = httpContextAccessor;
		}

		#endregion

		#region Public methods

		/// <summary>
		/// If the current user has a 'fingerprint' claim, add it to the new identity.
		/// </summary>
		protected override async Task<ClaimsIdentity> GenerateClaimsAsync(U user)
		{
			var identity = await base.GenerateClaimsAsync(user);

			var currentUser = httpContextAccessor.HttpContext?.User;

			if (currentUser != null)
			{
				var fingerprintClaim = currentUser.Claims.Where(c => c.Type == "fingerprint").FirstOrDefault();

				string fingerprint = fingerprintClaim?.Value;

				if (fingerprint != null)
				{
					identity.AddClaim(new Claim("fingerprint", fingerprint));
				}
			}

			return identity;
		}

		#endregion
	}
}
