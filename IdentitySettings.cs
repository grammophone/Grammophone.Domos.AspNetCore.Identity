using Grammophone.Caching;
using Microsoft.Practices.Unity;
using Microsoft.Practices.Unity.Configuration;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Grammophone.Domos.AspNet.Identity
{
	/// <summary>
	/// Used to resolve settings in configuration files.
	/// </summary>
	public class IdentitySettings
	{
		#region Private fields

		private static MRUCache<string, IUnityContainer> diContainersCache;

		private readonly IUnityContainer diContainer;

		#endregion

		#region Construction

		static IdentitySettings()
		{
			diContainersCache = new MRUCache<string, IUnityContainer>(configurationSectionName =>
			{
				var configurationSection = ConfigurationManager.GetSection(configurationSectionName)
					as UnityConfigurationSection;

				if (configurationSection == null)
					throw new IdentityException($"The '{configurationSectionName}' configuration section is not defined.");

				return new UnityContainer().LoadConfiguration(configurationSection);
			});
		}

		/// <summary>
		/// Create.
		/// </summary>
		/// <param name="configurationSectionName">The name of a Unity configuration section.</param>
		public IdentitySettings(string configurationSectionName)
		{
			if (configurationSectionName == null) throw new ArgumentNullException(nameof(configurationSectionName));

			diContainer = diContainersCache.Get(configurationSectionName);

			this.ConfigurationSectionName = configurationSectionName;
		}

		#endregion

		#region Public properties

		/// <summary>
		/// The name of the configuration section being accessed.
		/// </summary>
		public string ConfigurationSectionName { get; }

		#endregion

		#region Public methods

		/// <summary>
		/// Resolve an instance registered for type <typeparamref name="T"/>.
		/// </summary>
		/// <typeparam name="T">The type for which the instance is registered.</typeparam>
		public T Resolve<T>() => diContainer.Resolve<T>();

		/// <summary>
		/// Resolve an instance registered for type <typeparamref name="T"/>
		/// with a given <paramref name="name"/>.
		/// </summary>
		/// <typeparam name="T">The type for which the instance is registered.</typeparam>
		/// <param name="name">The name of the instance.</param>
		public T Resolve<T>(string name) => diContainer.Resolve<T>(name);

		/// <summary>
		/// Resolve all instances registered for type <typeparamref name="T"/>.
		/// </summary>
		/// <typeparam name="T">The type for which the instances are registered.</typeparam>
		public IEnumerable<T> ResolveAll<T>() => diContainer.ResolveAll<T>();

		#endregion
	}
}
