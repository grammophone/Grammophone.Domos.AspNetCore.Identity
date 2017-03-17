using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Grammophone.Domos.AspNet.Identity.Configuration
{
	/// <summary>
	/// Application cerdentials for accessing an OAuth provider.
	/// </summary>
	[Serializable]
	public class OAuthApplicationCredentials
	{
		/// <summary>
		/// The client or application ID.
		/// </summary>
		public string ClientID { get; set; }

		/// <summary>
		/// The client or application secret.
		/// </summary>
		public string ClientSecret { get; set; }
	}
}
