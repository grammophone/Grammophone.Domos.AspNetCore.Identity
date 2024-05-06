using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Grammophone.Domos.AspNetCore.Identity
{
	/// <summary>
	/// interface for handling encrypted cookies.
	/// </summary>
	public interface IEncryptedCookieManager
	{
		/// <summary>
		/// Create an encrypted cookie <seealso cref="Models.EncryptedSecurityCookie"/>.
		/// </summary>
		/// <param name="jsonString"></param>
		/// <returns></returns>
		byte[] CreateEncryptedToken(string jsonString);

		/// <summary>
		/// Decrypt and validate an encrypted cookie.
		/// </summary>
		/// <param name="encryptedCookie"></param>
		/// <returns></returns>
		string DecryptAndValidateEncryptedToken(byte[] encryptedCookie);
	}
}
