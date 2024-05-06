using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Grammophone.Domos.AspNetCore.Identity.Models;

namespace Grammophone.Domos.AspNetCore.Identity
{
	/// <summary>
	/// Abstract implementation of <see cref="IEncryptedCookieManager"/>.
	/// Override the <see cref="CreateEncryptionAlgorithm"/> method in a derived class and register it for dependency injection.
	/// </summary>
	public abstract class EncryptedCookieManager : IEncryptedCookieManager
	{
		#region Private fields

		private readonly Lazy<SymmetricAlgorithm> lazyEncryptionAlgorithm;

		#endregion

		#region Construction

		/// <summary>
		/// 
		/// </summary>
		public EncryptedCookieManager()
		{
			lazyEncryptionAlgorithm = new Lazy<SymmetricAlgorithm>(
				CreateEncryptionAlgorithm,
				System.Threading.LazyThreadSafetyMode.PublicationOnly);
		}

		#endregion

		#region public methods / Interface realization

		/// <inheritdoc/>
		public byte[] CreateEncryptedToken(string jsonString)
		{
			EncryptedSecurityCookie cookie = new EncryptedSecurityCookie()
			{
				TimeStamp = DateTime.UtcNow,
				CookiePayload = jsonString
			};

			return EncryptString(JsonSerializer.Serialize(cookie)); // javascriptSerializer.Serialize(cookie));
		}

		/// <inheritdoc/>
		public string DecryptAndValidateEncryptedToken(byte[] encryptedCookie)
		{
			var plainText = DecryptString(encryptedCookie);

			var cookie = JsonSerializer.Deserialize<EncryptedSecurityCookie>(plainText)!; //javascriptSerializer.Deserialize<EncryptedSecurityCookie>(plainText);

			//validate the cookie.. needs code.
			var now = DateTime.UtcNow;

			if (cookie.TimeStamp.AddSeconds(61) < DateTime.UtcNow)
				throw new ApplicationException("Security Timestamp has expired.");

			return cookie.CookiePayload;
		}

		#endregion

		#region Protected methods

		/// <summary>
		/// Called when creating the encryption algorithnm.
		/// </summary>
		protected abstract SymmetricAlgorithm CreateEncryptionAlgorithm();

		#endregion

		#region Encryption/Decription methods

		private byte[] EncryptString(string plainText)
		{
			if (plainText == null) throw new ArgumentNullException(nameof(plainText));

			var encryptor = lazyEncryptionAlgorithm.Value.CreateEncryptor();

			using (var memoryStream = new MemoryStream())
			{
				using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
				{
					using (var writer = new StreamWriter(cryptoStream))
					{
						writer.Write(plainText);
					}

					return memoryStream.ToArray();
				}
			}
		}

		/// <summary>
		/// Decrypt an encrypted string.
		/// </summary>
		/// <param name="encryptedText">The byte array holding the encrypted string.</param>
		/// <returns>Returns the decrypted string.</returns>
		private string DecryptString(byte[] encryptedText)
		{
			if (encryptedText == null) throw new ArgumentNullException(nameof(encryptedText));

			var decryptor = lazyEncryptionAlgorithm.Value.CreateDecryptor();

			using (var memoryStream = new MemoryStream(encryptedText))
			{
				using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
				{
					using (var reader = new StreamReader(cryptoStream))
					{
						return reader.ReadToEnd();
					}
				}
			}
		}

		#endregion
	}
}
