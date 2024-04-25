using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Grammophone.Domos.DataAccess;
using Grammophone.Domos.Domain;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Grammophone.Domos.AspNetCore.Identity
{
	/// <summary>
	/// User manager that uses a user store derived from <see cref="BrowserSessionUserStore{UB, U, D}"/>,
	/// exposes browser session methods and 
	/// uses <see cref="BrowserSessionClaimsPrincipalFactory{U}"/> to create session fingerprint claims.
	/// </summary>
	/// <typeparam name="UB">The base type of the user, derived from <see cref="User"/>.</typeparam>
	/// <typeparam name="U">The type of the user, derived from <typeparamref name="UB"/>.</typeparam>
	/// <typeparam name="D">The type of the domain container, derived from <see cref="IUsersDomainContainer{U}"/>.</typeparam>
	public class BrowserSessionUserManager<UB, U, D> : UserManager<U>
		where UB : User
		where U : UB
		where D : IUsersDomainContainer<UB>
	{
		#region Construction

		/// <summary>
		/// Create.
		/// </summary>
		public BrowserSessionUserManager(
			IUserStore<U> store,
			IOptions<IdentityOptions> optionsAccessor,
			IPasswordHasher<U> passwordHasher,
			IEnumerable<IUserValidator<U>> userValidators,
			IEnumerable<IPasswordValidator<U>> passwordValidators,
			ILookupNormalizer keyNormalizer,
			IdentityErrorDescriber errors,
			IServiceProvider services,
			ILogger<UserManager<U>> logger)
			: base(store, optionsAccessor, passwordHasher, userValidators, passwordValidators, keyNormalizer, errors, services, logger)
		{
			this.Store = (BrowserSessionUserStore<UB, U, D>)store;
		}

		#endregion

		#region Protected properties

		/// <summary>
		/// The user store, derived from <see cref="BrowserSessionUserStore{UB, U, D}"/>.
		/// </summary>
		protected new BrowserSessionUserStore<UB, U, D> Store { get; }

		#endregion

		#region Public methods

		/// <summary>
		/// Log off a browser session.
		/// </summary>
		/// <param name="userID">The ID of the user to be logged of.</param>
		/// <param name="fingerprint">The fingerprint of the session to log off.</param>
		/// <exception cref="InvalidOperationException">Thrown when no user was found having the given ID.</exception>
		public async Task LogOffBrowserSessionAsync(long userID, string fingerprint)
		{
			var user = await this.Store.FindByIdAsync(userID.ToString(), CancellationToken.None);

			if (user == null) throw new InvalidOperationException($"The user with ID {userID} was not found.");

			await this.Store.LogOffBrowserSessionAsync(user, fingerprint);
		}

		/// <summary>
		/// Log off a browser session.
		/// </summary>
		/// <param name="userName">The ID of the user to be logged of.</param>
		/// <param name="fingerprint">The fingerprint of the session to log off.</param>
		/// <exception cref="InvalidOperationException">Thrown when no user was found having the given ID.</exception>
		public async Task LogOffBrowserSessionAsync(string userName, string fingerprint)
		{
			if (userName == null) throw new ArgumentNullException(nameof(userName));

			var user = await this.Store.FindByNameAsync(userName, CancellationToken.None);

			if (user == null) throw new InvalidOperationException($"The user with ID {userName} was not found.");

			await this.Store.LogOffBrowserSessionAsync(user, fingerprint);
		}

		/// <summary>
		/// Log off a browser session.
		/// </summary>
		/// <param name="sessionID">The ID of the browser session.</param>
		public Task LogOffBrowserSessionAsync(long sessionID)
			=> this.Store.LogOffBrowserSessionAsync(sessionID);

		/// <summary>
		/// Log off all active sessions of a user.
		/// </summary>
		/// <param name="userID">The ID of the user.</param>
		/// <exception cref="InvalidOperationException">Thrown when no user was found having the given ID.</exception>
		public async Task GlobalLogOffAsync(long userID)
		{
			var user = await this.Store.FindByIdAsync(userID.ToString(), CancellationToken.None);

			if (user == null) throw new InvalidOperationException($"The user with ID {userID} was not found.");

			await this.Store.GlobalLofOffAsync(user);
		}

		#endregion
	}

	/// <summary>
	/// User manager that uses a user store derived from <see cref="BrowserSessionUserStore{UB, U, D}"/>,
	/// exposes browser session methods and 
	/// uses <see cref="BrowserSessionClaimsPrincipalFactory{U}"/> to create session fingerprint claims.
	/// </summary>
	/// <typeparam name="U">The type of the user, derived from <see cref="User"/>.</typeparam>
	/// <typeparam name="D">The type of the domain container, derived from <see cref="IUsersDomainContainer{U}"/>.</typeparam>
	public class BrowserSessionUserManager<U, D> : BrowserSessionUserManager<U, U, D>
		where U : User
		where D : IUsersDomainContainer<U>
	{
		/// <summary>
		/// Create.
		/// </summary>
		public BrowserSessionUserManager(
			IUserStore<U> store,
			IOptions<IdentityOptions> optionsAccessor,
			IPasswordHasher<U> passwordHasher,
			IEnumerable<IUserValidator<U>> userValidators,
			IEnumerable<IPasswordValidator<U>> passwordValidators,
			ILookupNormalizer keyNormalizer,
			IdentityErrorDescriber errors,
			IServiceProvider services,
			ILogger<UserManager<U>> logger)
			: base(store, optionsAccessor, passwordHasher, userValidators, passwordValidators, keyNormalizer, errors, services, logger)
		{
		}
	}
}
