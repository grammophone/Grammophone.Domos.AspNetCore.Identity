using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Grammophone.Domos.DataAccess;
using Grammophone.Domos.Domain;
using Grammophone.Setup;

namespace Grammophone.Domos.AspNetCore.Identity
{
	/// <summary>
	/// Abstract base class for store of authentication-related entities.
	/// </summary>
	/// <typeparam name="U">The type of the user, derived from <see cref="User"/>.</typeparam>
	public abstract class Store<U> : IDisposable
		where U : User
	{
		#region Private fields

		private bool hasBeenDisposed = false;

		#endregion

		#region Construction

		/// <summary>
		/// Create.
		/// </summary>
		/// <param name="configurationSectionName">
		/// The name of a unity configuration section, where
		/// a <see cref="IUsersDomainContainer{U}"/> is defined.
		/// </param>
		public Store(string configurationSectionName)
		{
			if (configurationSectionName == null) throw new ArgumentNullException(nameof(configurationSectionName));

			var identitySettings = Settings.Load(configurationSectionName);

			this.Settings = identitySettings;

			this.DomainContainer = identitySettings.Resolve<IUsersDomainContainer<U>>();
		}

		#endregion

		#region Protected properties

		/// <summary>
		/// The container of the domain model.
		/// </summary>
		protected IUsersDomainContainer<U> DomainContainer { get; }

		/// <summary>
		/// The identity settings container.
		/// </summary>
		protected Settings Settings { get; }

		#endregion

		#region IDisposable implementation

		/// <summary>
		/// Dispose the store. The store is unusable after the method is invoked.
		/// </summary>
		public void Dispose()
		{
			if (!hasBeenDisposed)
			{
				this.DomainContainer.Dispose();
				this.Settings.Dispose();

				hasBeenDisposed = true;
			}
		}

		#endregion
	}
}
