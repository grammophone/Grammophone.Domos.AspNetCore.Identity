using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Grammophone.Domos.AspNetCore.Identity.Models
{
	/// <summary>
	/// Represents an enncrypted cookie.
	/// </summary>
	[Serializable]
	public class EncryptedSecurityCookie
	{
		/// <summary>
		/// The timestamp.
		/// </summary>
		public required DateTime TimeStamp { get; init; }

		/// <summary>
		/// The payload oof the cookie.
		/// </summary>
		public required string CookiePayload { get; init; }
	}
}
