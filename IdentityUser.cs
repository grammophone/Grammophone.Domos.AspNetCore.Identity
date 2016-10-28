using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Grammophone.Domos.DataAccess;
using Grammophone.Domos.Domain;
using Microsoft.AspNet.Identity;

namespace Grammophone.Domos.AspNet.Identity
{
	/// <summary>
	/// Adapts a <see cref="User"/> descendant to an ASP.NET Identity <see cref="IUser{TKey}"/>.
	/// </summary>
	/// <typeparam name="U">The type of the user, derived from <see cref="User"/>.</typeparam>
	public class IdentityUser<U> : IUser<long>
		where U : User
	{
		#region Construction

		/// <summary>
		/// Create a user with a default internal registration.
		/// </summary>
		/// <param name="container">The domain container of the users system.</param>
		public IdentityUser(IUsersDomainContainer<U> container)
		{
			if (container == null) throw new ArgumentNullException(nameof(container));

			this.DomainUser = container.Users.Create();

			this.DomainUser.RegistrationStatus = RegistrationStatus.PendingVerification;
			this.DomainUser.CreationDate = DateTime.UtcNow;
		}

		/// <summary>
		/// Create a user using an existing <see cref="User"/>
		/// instance.
		/// </summary>
		/// <param name="user">The underlying user of the domain model.</param>
		public IdentityUser(U user)
		{
			if (user == null) throw new ArgumentNullException(nameof(user));

			this.DomainUser = user;
		}

		#endregion

		#region Public properties

		/// <summary>
		/// The underlying user of the domain model.
		/// </summary>
		public U DomainUser { get; private set; }

		#endregion

		#region IUser<int> Members

		/// <summary>
		/// The user's primary key.
		/// </summary>
		public long Id
		{
			get { return this.DomainUser.ID; }
		}

		/// <summary>
		/// The user's unique name.
		/// </summary>
		public string UserName
		{
			get
			{
				return this.DomainUser.UserName;
			}
			set
			{
				this.DomainUser.UserName = value;
			}
		}

		#endregion

		#region Public methods

		/// <summary>
		/// Get a collection of the <see cref="UserLoginInfo"/> which
		/// correspond to this user.
		/// </summary>
		public IList<UserLoginInfo> GetLoginInfos()
		{
			var loginInfos = new List<UserLoginInfo>(this.DomainUser.Registrations.Count);

			foreach (var registration in this.DomainUser.Registrations)
			{
				loginInfos.Add(new UserLoginInfo(registration.Provider.ToString(), registration.ProviderKey));
			}

			return loginInfos;
		}

		#endregion
	}
}
