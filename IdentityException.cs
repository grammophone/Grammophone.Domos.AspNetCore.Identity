using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Grammophone.Domos.AspNet.Identity
{
	/// <summary>
	/// Exception of the ASP.NET Identity adaptation for the 
	/// users of the Domos system.
	/// </summary>
	[Serializable]
	public class IdentityException : SystemException
	{
		/// <summary>
		/// Create.
		/// </summary>
		/// <param name="message">The message of the exception.</param>
		public IdentityException(string message) : base(message) { }

		/// <summary>
		/// Create.
		/// </summary>
		/// <param name="message">The message of the exception.</param>
		/// <param name="inner">The cause of the exception.</param>
		public IdentityException(string message, Exception inner) : base(message, inner) { }

		/// <summary>
		/// Used for serialization.
		/// </summary>
		protected IdentityException(
		System.Runtime.Serialization.SerializationInfo info,
		System.Runtime.Serialization.StreamingContext context)
			: base(info, context) { }
	}
}
