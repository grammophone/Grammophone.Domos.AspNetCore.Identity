using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Grammophone.Domos.Domain;
using Microsoft.AspNet.Identity;

namespace Grammophone.Domos.AspNet.Identity
{
	/// <summary>
	/// Adapts a <see cref="Role"/> to an ASP.NET Identity <see cref="IRole{Int32}"/>.
	/// </summary>
	public class IdentityRole : IRole<long>
	{
		#region Construction

		/// <summary>
		/// Create.
		/// </summary>
		/// <param name="role">The underlying role of the domain model.</param>
		public IdentityRole(Role role)
		{
			if (role == null) throw new ArgumentNullException(nameof(role));

			this.DomainRole = role;
		}

		#endregion

		#region Public properties

		/// <summary>
		/// The underlying role of the domain model.
		/// </summary>
		public Role DomainRole { get; private set; }

		#endregion

		#region IRole<long> Members

		/// <summary>
		/// The role's primary key.
		/// </summary>
		public long Id
		{
			get { return this.DomainRole.ID; }
		}

		/// <summary>
		/// The role's name.
		/// </summary>
		public string Name
		{
			get
			{
				return this.DomainRole.Name;
			}
			set
			{
				this.DomainRole.Name = value;
			}
		}

		#endregion
	}
}
