using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Grammophone.Domos.AspNetCore.Identity
{
	/// <summary>
	/// Constants for identity claim names.
	/// </summary>
	public static class IdentityClaimNames
	{
		/// <summary>
		/// Claim name for browser session fingerprint.
		/// </summary>
		public const string Fingerprint = "fingerprint";

		/// <summary>
		/// Claim name for a session that has been impersonated by another user.
		/// </summary>
		public const string ImpersonatedBy = "impersonatedBy";
	}
}
