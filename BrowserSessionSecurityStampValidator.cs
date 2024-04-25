using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Grammophone.Domos.Domain;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
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
		/// <param name="clock">The system clock.</param>
		/// <param name="httpContextAccessor">The accessor to <see cref="HttpContext"/>.</param>
		public BrowserSessionSecurityStampValidator(
			IOptions<SecurityStampValidatorOptions> options, SignInManager<U> signInManager, ISystemClock clock, IHttpContextAccessor httpContextAccessor)
			: base(options, signInManager, clock)
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
		protected override async Task<U> VerifySecurityStamp(ClaimsPrincipal principal)
		{
			if (principal?.Identity != null)
			{
				httpContextAccessor.HttpContext.Items["ValidatedIdentity"] = principal.Identity;
			}

			return await base.VerifySecurityStamp(principal);
		}

		#endregion
	}
}
