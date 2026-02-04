using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Grammophone.Domos.Domain;

namespace Grammophone.Domos.AspNetCore.Identity
{
	/// <summary>
	/// Methods to manage impersonation claims.
	/// </summary>
	public static class ImpersonationFunctions
	{
		/// <summary>
		/// Create an impersonatino claim from a user.
		/// </summary>
		/// <param name="user">the user.</param>
		/// <returns>Returns an impersonatin claim.</returns>
		public static Claim CreateImpersonationClaim(this User user)
		{
			if (user == null) throw new ArgumentNullException(nameof(user));

			return new Claim(IdentityClaimNames.ImpersonatedBy, $"{user.UserName}|{user.Guid}");
		}

		/// <summary>
		/// Parse an impersonation claim to the contained user name and GUID.
		/// </summary>
		/// <param name="claim">The claim to parse.</param>
		/// <returns>Returns the user name and GUID tuple.</returns>
		/// <exception cref="ArgumentException">Thrown when the <paramref name="claim"/> has not the <see cref="IdentityClaimNames.ImpersonatedBy"/> type.</exception>
		/// <exception cref="IdentityException">Thrown when the value of the <paramref name="claim"/> is malformed.</exception>
		public static (string userName, Guid guid) ParseImpersonationClaim(this Claim claim)
		{
			if (claim == null) throw new ArgumentNullException(nameof(claim));
			if (claim.Type != IdentityClaimNames.ImpersonatedBy) throw new ArgumentException("The claim is not of impersonation type.", nameof(claim));

			string impersonatedBy = claim.Value;

			int pipeIndex = impersonatedBy.IndexOf('|');

			if (pipeIndex >= 0)
			{
				string impersonatingUserName = impersonatedBy.Substring(0, pipeIndex);

				string impersonatingUserGuidName = impersonatedBy.Substring(pipeIndex + 1);

				if (!Guid.TryParse(impersonatingUserGuidName, out Guid impersonatingUserGuid))
				{
					throw new IdentityException("The impersonation claim has invalid format.");
				}

				return (impersonatingUserName, impersonatingUserGuid);
			}
			else
			{
				throw new IdentityException("The impersonation claim has invalid format.");
			}
		}
	}
}
