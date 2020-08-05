using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Grammophone.Domos.Environment;
using Microsoft.AspNetCore.Http;

namespace Grammophone.Domos.AspNetCore.Identity
{
	/// <summary>
	/// Retrieves the environment of the currently logged-in user from the ASP.NET Core system.
	/// </summary>
	public class AspNetCoreUserContext : IUserContext
	{
		private readonly IHttpContextAccessor httpContextAccessor;

		/// <summary>
		/// Create.
		/// </summary>
		/// <param name="httpContextAccessor">The <see cref="IHttpContextAccessor"/> provided by the ASP.NET Core runtime.</param>
		public AspNetCoreUserContext(IHttpContextAccessor httpContextAccessor)
		{
			if (httpContextAccessor == null) throw new ArgumentNullException(nameof(httpContextAccessor));

			this.httpContextAccessor = httpContextAccessor;
		}

		/// <inheritdoc/>
		public long? UserID
		{
			get
			{
				string userIdString = httpContextAccessor.HttpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);

				if (String.IsNullOrEmpty(userIdString))
				{
					return null;
				}
				else if (long.TryParse(userIdString, out long userID))
				{
					return userID;
				}
				else
				{
					return null;
				}
			}
		}
	}
}
