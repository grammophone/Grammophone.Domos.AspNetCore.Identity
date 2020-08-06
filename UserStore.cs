using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Grammophone.Domos.DataAccess;
using Grammophone.Domos.Domain;
using Grammophone.Setup;
using Microsoft.AspNetCore.Identity;

namespace Grammophone.Domos.AspNetCore.Identity
{
	/// <summary>
	/// Implementation of an ASP.NET Identity user store that is based
	/// on user domain object derived from <see cref="User"/>.
	/// It expects a Unity container defining an <see cref="IUsersDomainContainer{U}"/>
	/// and optionally any listeners implementing <see cref="IUserListener{U}"/>.
	/// </summary>
	/// <typeparam name="U">The type of the user, derived from <see cref="User"/>.</typeparam>
	public class UserStore<U> :
		IUserStore<U>,
		IQueryableUserStore<U>,
		IUserLoginStore<U>,
		IUserPasswordStore<U>,
		IUserRoleStore<U>,
		IUserEmailStore<U>,
		IUserLockoutStore<U>,
		IUserTwoFactorStore<U>,
		IUserSecurityStampStore<U>
		where U : User
	{
		#region Auxilliary classes

		/// <summary>
		/// Information about external registration as
		/// understooed by ASP.NET Identity system.
		/// </summary>
		public class Login
		{
			#region Construction

			internal Login(U user, UserLoginInfo info)
			{
				if (user == null) throw new ArgumentNullException(nameof(user));
				if (info == null) throw new ArgumentNullException(nameof(info));

				this.User = user;
				this.Info = info;
			}

			#endregion

			#region Public properties

			/// <summary>
			/// The user.
			/// </summary>
			public U User { get; private set; }

			/// <summary>
			/// The external registration.
			/// </summary>
			public UserLoginInfo Info { get; private set; }

			#endregion
		}

		#endregion

		#region Private fields

		private readonly IEnumerable<IUserListener<U>> userListeners;

		private bool hasBeenDisposed = false;

		#endregion

		#region Construction

		/// <summary>
		/// Create.
		/// </summary>
		/// <param name="configurationSectionName">
		/// The name of a unity configuration section, where
		/// a <see cref="IUsersDomainContainer{U}"/> is defined
		/// and optionally any listeners implementing <see cref="IUserListener{U}"/>.
		/// </param>
		public UserStore(string configurationSectionName)
		{
			if (configurationSectionName == null) throw new ArgumentNullException(nameof(configurationSectionName));

			var identitySettings = Settings.Load(configurationSectionName);

			this.Settings = identitySettings;

			this.DomainContainer = identitySettings.Resolve<IUsersDomainContainer<U>>();

			this.userListeners = identitySettings.ResolveAll<IUserListener<U>>().OrderBy(l => l.Order);
		}

		#endregion

		#region Events

		/// <summary>
		/// Fired when a new user is being created.
		/// </summary>
		public event NotificationDelegate<UserStore<U>, U> CreatingUser;

		/// <summary>
		/// Fired when a user is being updated.
		/// </summary>
		public event NotificationDelegate<UserStore<U>, U> UpdatingUser;

		/// <summary>
		/// Fired when a user is being deleted.
		/// </summary>
		public event NotificationDelegate<UserStore<U>, U> DeletingUser;

		/// <summary>
		/// Fired when an external login is added to a user.
		/// </summary>
		public event NotificationDelegate<UserStore<U>, Registration> AddingLogin;

		/// <summary>
		/// Fired when an external login is removed from a user.
		/// </summary>
		public event NotificationDelegate<UserStore<U>, Registration> RemovingLogin;

		/// <summary>
		/// Fired when a user's password is changed.
		/// </summary>
		public event NotificationDelegate<UserStore<U>, U> ChangingPassword;

		/// <summary>
		/// Fired when a user's e-mail is set.
		/// </summary>
		public event NotificationDelegate<UserStore<U>, U> SettingEmail;

		/// <summary>
		/// Fired when a user's e-mail is verified.
		/// </summary>
		public event NotificationDelegate<UserStore<U>, U> ConfirmingEmail;

		/// <summary>
		/// Fired when the security stamp is read.
		/// </summary>
		public event NotificationDelegate<UserStore<U>, U> GettingSecurityStamp;

		/// <summary>
		/// Fired when the security stamp is set.
		/// </summary>
		public event NotificationDelegate<UserStore<U>, U> SettingSecurityStamp;

		#endregion

		#region Public properties

		/// <summary>
		/// The container of the domain model.
		/// </summary>
		public IUsersDomainContainer<U> DomainContainer { get; private set; }

		/// <summary>
		/// The identity settings container.
		/// </summary>
		public Settings Settings { get; private set; }

		/// <summary>
		/// The users in the system.
		/// </summary>
		public IQueryable<U> Users => this.DomainContainer.Users;

		#endregion

		#region IUserStore<U> Members

		/// <summary>
		/// Create a user.
		/// </summary>
		/// <param name="user">The user to create.</param>
		/// <param name="cancellationToken">Cancellation token used during saving.</param>
		/// <returns>Returns the task which completes the operation.</returns>
		/// <remarks>
		/// <see cref="OnCreatingUserAsync"/> is invoked whose default implementation
		/// fires the <see cref="CreatingUser"/> event during this method.
		/// </remarks>
		public virtual async Task<IdentityResult> CreateAsync(U user, CancellationToken cancellationToken)
		{
			if (user == null) throw new ArgumentNullException(nameof(user));

			using (var transaction = DomainContainer.BeginTransaction())
			{
				this.DomainContainer.Users.Add(user);

				user.SecurityStamp = String.Empty;
				user.CreationDate = DateTime.UtcNow;
				user.Guid = new Guid();

				await OnCreatingUserAsync(user);

				await this.DomainContainer.SaveChangesAsync(cancellationToken);

				transaction.Commit();
			}

			return IdentityResult.Success;
		}

		/// <summary>
		/// Delete a user.
		/// </summary>
		/// <param name="user">The user to create.</param>
		/// <param name="cancellationToken">Cancellation token used during delete.</param>
		/// <returns>Returns the task which completes the operation.</returns>
		/// <remarks>
		/// <see cref="OnDeletingUserAsync"/> is invoked whose default implementation
		/// fires the <see cref="DeletingUser"/> event during this method.
		/// </remarks>
		public virtual async Task<IdentityResult> DeleteAsync(U user, CancellationToken cancellationToken)
		{
			if (user == null) throw new ArgumentNullException("user");

			using (var transaction = DomainContainer.BeginTransaction())
			{
				DomainContainer.Users.Attach(user);

				await OnDeletingUserAsync(user);

				DomainContainer.Users.Remove(user);

				await DomainContainer.SaveChangesAsync(cancellationToken);

				transaction.Commit();
			}

			return IdentityResult.Success;
		}

		/// <summary>
		/// Find a user by her ID.
		/// </summary>
		/// <param name="userID">The ID of the user.</param>
		/// <param name="cancellationToken">Cancellation token used during find.</param>
		/// <returns>
		/// Returns a task whose <see cref="Task{T}.Result"/>
		/// is the user found or null.
		/// </returns>
		public virtual async Task<U> FindByIdAsync(string userID, CancellationToken cancellationToken)
		{
			if (!long.TryParse(userID, out long userIdValue))
			{
				throw new ArgumentException("The User ID is not a valid long integer value.", nameof(userID));
			}

			var user =
				await DomainContainer.Users
				.Include(u => u.Registrations)
				.Include(u => u.Roles)
				.Where(u => u.RegistrationStatus != RegistrationStatus.Revoked)
				.FirstOrDefaultAsync(u => u.ID == userIdValue, cancellationToken);

			return user;
		}

		/// <summary>
		/// Find a user by her unique user name.
		/// </summary>
		/// <param name="userName">The <see cref="User.UserName"/> of the user.</param>
		/// <param name="cancellationToken">Cancellation token used during retrieving.</param>
		/// <returns>
		/// Returns a task whose <see cref="Task{T}.Result"/>
		/// is the user found or null.
		/// </returns>
		public virtual async Task<U> FindByNameAsync(string userName, CancellationToken cancellationToken)
		{
			if (userName == null) throw new ArgumentNullException(nameof(userName));

			var user =
				await DomainContainer.Users
				.Include(u => u.Registrations)
				.Include(u => u.Roles)
				.Where(u => u.RegistrationStatus != RegistrationStatus.Revoked)
				.FirstOrDefaultAsync(u => u.UserName == userName, cancellationToken);

			return user;
		}

		/// <summary>
		/// Update a user.
		/// </summary>
		/// <param name="user"></param>
		/// <param name="cancellationToken">Cancellation token used during saving.</param>
		/// <returns>Returns the task which completes the operation.</returns>
		/// <remarks>
		/// <see cref="OnUpdatingUserAsync"/> is invoked whose default implementation
		/// fires the <see cref="DeletingUser"/> event during this method.
		/// </remarks>
		public virtual async Task<IdentityResult> UpdateAsync(U user, CancellationToken cancellationToken)
		{
			if (user == null) throw new ArgumentNullException(nameof(user));

			using (var transaction = DomainContainer.BeginTransaction())
			{
				DomainContainer.Users.Attach(user);

				await OnUpdatingUserAsync(user);

				DomainContainer.SetAsModified(user);

				await DomainContainer.SaveChangesAsync(cancellationToken);

				transaction.Commit();
			}

			return IdentityResult.Success;
		}

		/// <summary>
		/// Returns the ID of the user in string representation.>
		/// </summary>
		public Task<string> GetUserIdAsync(U user, CancellationToken cancellationToken)
		{
			if (user == null) throw new ArgumentNullException(nameof(user));

			return Task.FromResult(user.ID.ToString());
		}

		/// <summary>
		/// Returns the <see cref="User.UserName"/> property.
		/// </summary>
		public virtual Task<string> GetUserNameAsync(U user, CancellationToken cancellationToken)
		{
			if (user == null) throw new ArgumentNullException(nameof(user));

			return Task.FromResult(user.UserName);
		}

		/// <summary>
		/// Sets the <see cref="User.UserName"/> property of the user.
		/// </summary>
		public virtual Task SetUserNameAsync(U user, string userName, CancellationToken cancellationToken)
		{
			if (user == null) throw new ArgumentNullException(nameof(user));

			user.UserName = userName;

			return Task.CompletedTask;
		}

		/// <summary>
		/// Default implementation delegates to <see cref="GetUserNameAsync(U, CancellationToken)"/>.
		/// </summary>
		public Task<string> GetNormalizedUserNameAsync(U user, CancellationToken cancellationToken)
			=> GetUserNameAsync(user, cancellationToken);

		/// <summary>
		/// Default implementation delegates to <see cref="SetUserNameAsync(U, string, CancellationToken)"/>.
		/// </summary>
		public Task SetNormalizedUserNameAsync(U user, string normalizedName, CancellationToken cancellationToken)
		{
			if (normalizedName == null) throw new ArgumentNullException(nameof(normalizedName));

			return SetUserNameAsync(user, normalizedName.ToLower(), cancellationToken);
		}

		#endregion

		#region IDisposable Members

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

		#region IUserLoginStore<U,long> Members

		/// <summary>
		/// Add a <see cref="Registration"/> to a <see cref="User"/>.
		/// </summary>
		/// <param name="user">
		/// The Identity user which wraps a <see cref="User"/>.
		/// </param>
		/// <param name="cancellationToken">Cancellation token for the operation.</param>
		/// <param name="login">
		/// The <see cref="UserLoginInfo"/> 
		/// that corresponds to the <see cref="Registration"/>.
		/// </param>
		/// <returns>Returns the task which completes the operation.</returns>
		public virtual async Task AddLoginAsync(U user, UserLoginInfo login, CancellationToken cancellationToken)
		{
			if (user == null) throw new ArgumentNullException(nameof(user));
			if (login == null) throw new ArgumentNullException(nameof(login));

			using (var transaction = DomainContainer.BeginTransaction())
			{
				var registration = DomainContainer.Registrations.Create();

				RegistrationProvider registrationProvider;

				registrationProvider = GetRegistrationProvider(login);

				registration.Provider = registrationProvider;
				registration.ProviderKey = login.ProviderKey;
				registration.User = user;

				await OnAddingLoginAsync(registration);

				DomainContainer.Registrations.Add(registration);

				await DomainContainer.SaveChangesAsync(cancellationToken);

				transaction.Commit();
			}
		}

		/// <summary>
		/// Find a user by her (external) registration.
		/// </summary>
		/// <param name="loginProvider">The login provider name.</param>
		/// <param name="providerKey">The login provider key.</param>
		/// <param name="cancellationToken">Cancellation token for the operation.</param>
		/// <returns>
		/// Returns an task whose <see cref="Task{T}.Result"/> contains the found user
		/// or null.
		/// </returns>
		public virtual async Task<U> FindByLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken)
		{
			if (loginProvider == null) throw new ArgumentNullException(nameof(loginProvider));
			if (providerKey == null) throw new ArgumentNullException(nameof(providerKey));

			var registrationProvider = GetRegistrationProvider(loginProvider);

			var userQuery = from user in DomainContainer.Users
											.Include(user => user.Registrations)
											.Include(user => user.Roles)
											where
											user.RegistrationStatus != RegistrationStatus.Revoked &&
											user.Registrations.Any(
												registration =>
													registration.ProviderKey == providerKey
													&& registration.Provider == registrationProvider)
											select user;

			var foundUser = await userQuery.FirstOrDefaultAsync(cancellationToken);

			return foundUser;
		}

		/// <summary>
		/// Get the (external) registrations of a user.
		/// </summary>
		/// <param name="user">The user.</param>
		/// <param name="cancellationToken">Cancellation token for the operation.</param>
		/// <returns>
		/// Returns a task whose <see cref="Task{T}.Result"/> holds the 
		/// <see cref="UserLoginInfo"/>'s which correspond to the user's
		/// registrations.
		/// </returns>
		public Task<IList<UserLoginInfo>> GetLoginsAsync(U user, CancellationToken cancellationToken)
		{
			if (user == null) throw new ArgumentNullException(nameof(user));

			IList<UserLoginInfo> loginInfos = new List<UserLoginInfo>(user.Registrations.Count);

			foreach (var registration in user.Registrations)
			{
				loginInfos.Add(new UserLoginInfo(registration.Provider.ToString(), registration.ProviderKey, registration.Provider.ToString()));
			}

			return Task.FromResult(loginInfos);
		}

		/// <summary>
		/// Remove an external login of a user.
		/// </summary>
		/// <param name="user">The user.</param>
		/// <param name="loginProvider">The login provider name.</param>
		/// <param name="providerKey">The login provider key.</param>
		/// <param name="cancellationToken">Cancellation token for the operation.</param>
		/// <returns>Returns a task for the operation.</returns>
		public virtual async Task RemoveLoginAsync(U user, string loginProvider, string providerKey, CancellationToken cancellationToken)
		{
			if (user == null) throw new ArgumentNullException(nameof(user));
			if (loginProvider == null) throw new ArgumentNullException(nameof(loginProvider));
			if (providerKey == null) throw new ArgumentNullException(nameof(providerKey));

			var registrationProvider = GetRegistrationProvider(loginProvider);

			using (var transaction = DomainContainer.BeginTransaction())
			{
				var registrationFound =
					user.Registrations.FirstOrDefault(registration =>
						registration.ProviderKey == providerKey && registration.Provider == registrationProvider);

				if (registrationFound != null)
				{
					await OnRemovingLoginAsync(registrationFound);

					this.DomainContainer.Registrations.Remove(registrationFound);

					await DomainContainer.SaveChangesAsync();
				}

				transaction.Commit();
			}
		}

		#endregion

		#region IUserPasswordStore<U> Members

		/// <summary>
		/// Get the password hash of the user if set, else null.
		/// </summary>
		/// <param name="user">The user.</param>
		/// <param name="cancellationToken">Ignored; the action is immediate.</param>
		/// <returns>
		/// Returns a task whose <see cref="Task{T}.Result"/> will contain the 
		/// password hash or null.
		/// </returns>
		public Task<string> GetPasswordHashAsync(U user, CancellationToken cancellationToken)
		{
			if (user == null) throw new ArgumentNullException(nameof(user));

			switch (user.RegistrationStatus)
			{
				case RegistrationStatus.PendingVerification:
				case RegistrationStatus.Verified:
					return Task.FromResult(user.PasswordHash);

				case RegistrationStatus.Revoked:
					return Task.FromResult<string>(null);

				default:
					throw new IdentityException("Invalid user RegistrationStatus.");
			}
		}

		/// <summary>
		/// Determine whether a user has a password.
		/// </summary>
		/// <param name="user">The user.</param>
		/// <param name="cancellationToken">Ignored; the action is immediate.</param>
		/// <returns>
		/// Returns a task whose <see cref="Task{T}.Result"/> contains
		/// a boolean value indicating whether the user has a password or not.
		/// </returns>
		public Task<bool> HasPasswordAsync(U user, CancellationToken cancellationToken)
		{
			if (user == null) throw new ArgumentNullException(nameof(user));

			return Task.FromResult(user.PasswordHash != null);
		}

		/// <summary>
		/// Set the password of a user.
		/// </summary>
		/// <param name="user">The user.</param>
		/// <param name="passwordHash">The password hash to set.</param>
		/// <param name="cancellationToken">Ignored; the action is immediate.</param>
		/// <returns>Returns a task for the operation.</returns>
		public Task SetPasswordHashAsync(U user, string passwordHash, CancellationToken cancellationToken)
		{
			if (user == null) throw new ArgumentNullException(nameof(user));

			user.PasswordHash = passwordHash;

			return Task.CompletedTask;
		}

		#endregion

		#region IUserRoleStore<U> Members

		/// <summary>
		/// Add a role to a user. The role must exist in the system.
		/// </summary>
		/// <param name="user">The user.</param>
		/// <param name="roleName">The name of the role to add.</param>
		/// <param name="cancellationToken">Cancellation token for the action.</param>
		/// <returns>Returns a task completing the operation.</returns>
		/// <exception cref="IdentityException">
		/// Thrown when a role having the given <paramref name="roleName"/>
		/// does not exist in the system.
		/// </exception>
		public virtual async Task AddToRoleAsync(U user, string roleName, CancellationToken cancellationToken)
		{
			if (user == null) throw new ArgumentNullException(nameof(user));
			if (roleName == null) throw new ArgumentNullException(nameof(roleName));

			using (var transaction = DomainContainer.BeginTransaction())
			{
				this.DomainContainer.Users.Attach(user);

				if (user.Roles.Any(r => r.Name == roleName)) return;

				var role = await FindRoleAsync(roleName, cancellationToken);

				if (role == null)
					throw new IdentityException($"The role '{roleName}' does not exist in the system.");

				user.Roles.Add(role);

				await this.DomainContainer.SaveChangesAsync(cancellationToken);

				transaction.Commit();
			}
		}

		/// <summary>
		/// Get the roles of a user.
		/// </summary>
		/// <param name="user">The user.</param>
		/// <param name="cancellationToken">Cancellation token for the action.</param>
		/// <returns>
		/// Returns a task whose <see cref="Task{T}.Result"/>
		/// contains the roles names of the user.
		/// </returns>
		public Task<IList<string>> GetRolesAsync(U user, CancellationToken cancellationToken)
		{
			if (user == null) throw new ArgumentNullException(nameof(user));

			this.DomainContainer.Users.Attach(user);

			var roleNames = from role in user.Roles
											select role.Name;

			return Task.FromResult<IList<string>>(roleNames.ToList());
		}

		/// <summary>
		/// Check whether a user has a role.
		/// </summary>
		/// <param name="user">The user.</param>
		/// <param name="roleName">the role name.</param>
		/// <param name="cancellationToken">Cancellation token for the action.</param>
		/// <returns>
		/// Returns a task whose <see cref="Task{T}.Result"/>
		/// determines whether the user has the role.
		/// </returns>
		public Task<bool> IsInRoleAsync(U user, string roleName, CancellationToken cancellationToken)
		{
			if (user == null) throw new ArgumentNullException(nameof(user));
			if (roleName == null) throw new ArgumentNullException(nameof(roleName));

			this.DomainContainer.Users.Attach(user);

			return Task.FromResult(
				user.Roles.Any(role => role.Name == roleName));
		}

		/// <summary>
		/// Remove a role from a user. If the role does not exist
		/// or the user doesn't havit, nothing happens.
		/// </summary>
		/// <param name="user">The user.</param>
		/// <param name="roleName">The name of the role to remove from the user.</param>
		/// <param name="cancellationToken">Cancellation token for the action.</param>
		/// <returns>Returns a task for the operation.</returns>
		public virtual async Task RemoveFromRoleAsync(U user, string roleName, CancellationToken cancellationToken)
		{
			if (user == null) throw new ArgumentNullException(nameof(user));
			if (roleName == null) throw new ArgumentNullException(nameof(roleName));

			using (var transaction = DomainContainer.BeginTransaction())
			{
				this.DomainContainer.Users.Attach(user);

				var removedRole = user.Roles.Where(r => r.Name == roleName).FirstOrDefault();

				if (removedRole == null)
				{
					transaction.Pass();

					return;
				}

				user.Roles.Remove(removedRole);

				await this.DomainContainer.SaveChangesAsync(cancellationToken);

				transaction.Commit();
			}
		}

		/// <summary>
		/// Get the users having a role. If the role doesn't exist, returns the empty list.
		/// </summary>
		/// <param name="roleName">The name of the role.</param>
		/// <param name="cancellationToken">Cancellation token for the action.</param>
		/// <returns>Returns the list of users having the role.</returns>
		public async Task<IList<U>> GetUsersInRoleAsync(string roleName, CancellationToken cancellationToken)
		{
			if (roleName == null) throw new ArgumentNullException(nameof(roleName));

			var users = from u in this.DomainContainer.Users
									where u.Roles.Any(r => r.Name == roleName)
									select u;

			return await users.ToListAsync(cancellationToken);
		}

		#endregion

		#region IUserEmailStore<U,long> Members

		/// <summary>
		/// Find a user by her e-mail.
		/// </summary>
		/// <param name="email">The e-mail.</param>
		/// <param name="cancellationToken">Cancellation token for the operation.</param>
		/// <returns>
		/// Returns a task whose <see cref="Task{T}.Result"/> contains 
		/// the user found or null.
		/// </returns>
		public virtual async Task<U> FindByEmailAsync(string email, CancellationToken cancellationToken)
		{
			if (email == null) throw new ArgumentNullException(nameof(email));

			var userQuery = from user in DomainContainer.Users
											.Include(u => u.Registrations)
											.Include(u => u.Roles)
											where user.Email == email && user.RegistrationStatus != RegistrationStatus.Revoked
											select user;

			var userFound = await userQuery.FirstOrDefaultAsync(cancellationToken);

			return userFound;
		}

		/// <summary>
		/// Get the e-mail of a user.
		/// </summary>
		/// <param name="user">The user.</param>
		/// <param name="cancellationToken">Ignored; the action is immediate.</param>
		/// <returns>
		/// Returns a task whose <see cref="Task{T}.Result"/> contains 
		/// the user's e-mail.
		/// </returns>
		public Task<string> GetEmailAsync(U user, CancellationToken cancellationToken)
		{
			if (user == null) throw new ArgumentNullException(nameof(user));

			return Task.FromResult(user.Email);
		}

		/// <summary>
		/// Determine whether a user's e-mail is confirmed.
		/// </summary>
		/// <param name="user">the user.</param>
		/// <param name="cancellationToken">Ignored; the action is immediate.</param>
		/// <returns>
		/// Returns a task whose <see cref="Task{T}.Result"/> contains 
		/// true if the user has her e-mail confirmed.
		/// </returns>
		public Task<bool> GetEmailConfirmedAsync(U user, CancellationToken cancellationToken)
		{
			if (user == null) throw new ArgumentNullException(nameof(user));

			return Task.FromResult(user.RegistrationStatus != RegistrationStatus.PendingVerification);
		}

		/// <summary>
		/// Set the e-mail of a user.
		/// </summary>
		/// <param name="user">The user.</param>
		/// <param name="email">the user's e-mail.</param>
		/// <param name="cancellationToken">Cancellation token for the operation.</param>
		/// <returns>Returns a task which completes the operation.</returns>
		public virtual async Task SetEmailAsync(U user, string email, CancellationToken cancellationToken)
		{
			if (user == null) throw new ArgumentNullException(nameof(user));
			if (email == null) throw new ArgumentNullException(nameof(email));

			using (var transaction = DomainContainer.BeginTransaction())
			{
				user.Email = email;

				await OnSettingEmailAsync(user);

				await DomainContainer.SaveChangesAsync(cancellationToken);

				transaction.Commit();
			}
		}

		/// <summary>
		/// Set whether a user's e-mail is confirmed.
		/// </summary>
		/// <param name="user">The user.</param>
		/// <param name="confirmed">True if the user's e-mail is confirmed.</param>
		/// <param name="cancellationToken">Cancellation token for the operation.</param>
		/// <returns>Returns a task which completes the operation.</returns>
		public virtual async Task SetEmailConfirmedAsync(U user, bool confirmed, CancellationToken cancellationToken)
		{
			if (user == null) throw new ArgumentNullException(nameof(user));

			using (var transaction = DomainContainer.BeginTransaction())
			{
				if (user.RegistrationStatus == RegistrationStatus.PendingVerification)
				{
					user.RegistrationStatus = RegistrationStatus.Verified;

					await OnConfirmingEmailAsync(user);

					await DomainContainer.SaveChangesAsync(cancellationToken);

					transaction.Commit();
				}
			}
		}

		/// <summary>
		/// Default implementation delegates to <see cref="GetEmailAsync(U, CancellationToken)"/>.
		/// Override to change.
		/// </summary>
		public virtual Task<string> GetNormalizedEmailAsync(U user, CancellationToken cancellationToken)
			=> GetEmailAsync(user, cancellationToken);

		/// <summary>
		/// Default implementation delegates to <see cref="SetEmailAsync(U, string, CancellationToken)"/>
		/// Override to change.
		/// </summary>
		public virtual Task SetNormalizedEmailAsync(U user, string normalizedEmail, CancellationToken cancellationToken)
		{
			if (normalizedEmail == null) throw new ArgumentNullException(nameof(normalizedEmail));

			return SetEmailAsync(user, normalizedEmail.ToLower(), cancellationToken);
		}

		#endregion

		#region IUserLockoutStore<U,long> Members

		/// <summary>
		/// Always gets zero.
		/// </summary>
		public virtual Task<int> GetAccessFailedCountAsync(U user, CancellationToken cancellationToken)
		{
			return Task.FromResult(0);
		}

		/// <summary>
		/// Always returns false.
		/// </summary>
		public virtual Task<bool> GetLockoutEnabledAsync(U user, CancellationToken cancellationToken)
		{
			return Task.FromResult(false);
		}

		/// <summary>
		/// Returns null, representing that the account is not locked.
		/// </summary>
		public virtual Task<DateTimeOffset?> GetLockoutEndDateAsync(U user, CancellationToken cancellationToken)
		{
			return Task.FromResult<DateTimeOffset?>(null);
		}

		/// <summary>
		/// Always returns 1.
		/// </summary>
		public virtual Task<int> IncrementAccessFailedCountAsync(U user, CancellationToken cancellationToken)
		{
			return Task.FromResult(1);
		}

		/// <summary>
		/// Not implemented; does nothing. Override to change.
		/// </summary>
		public virtual Task ResetAccessFailedCountAsync(U user, CancellationToken cancellationToken)
		{
			return Task.CompletedTask;
		}

		/// <summary>
		/// Not implemented; does nothing. Override to change.
		/// </summary>
		public virtual Task SetLockoutEnabledAsync(U user, bool enabled, CancellationToken cancellationToken)
		{
			return Task.CompletedTask;
		}

		/// <summary>
		/// Not implemented; does nothing. Override to change.
		/// </summary>
		public virtual Task SetLockoutEndDateAsync(U user, DateTimeOffset? lockoutEnd, CancellationToken cancellationToken)
		{
			return Task.CompletedTask;
		}

		#endregion

		#region IUserTwoFactorStore<U,long> Members

		/// <summary>
		/// Always returns false. Override to change.
		/// </summary>
		public virtual Task<bool> GetTwoFactorEnabledAsync(U user, CancellationToken cancellationToken)
		{
			return Task.FromResult(false);
		}

		/// <summary>
		/// Does nothing. Override to change.
		/// </summary>
		public virtual Task SetTwoFactorEnabledAsync(U user, bool enabled, CancellationToken cancellationToken)
		{
			return Task.CompletedTask;
		}

		#endregion

		#region IUserSecurityStampStore<U,long> Members

		/// <summary>
		/// Get the security stamp of a user.
		/// </summary>
		/// <param name="user">The identity user to retrieve the security stamp from.</param>
		/// <param name="cancellationToken">The cancellation token for the operation.</param>
		/// <returns>
		/// Returns a task whose result contains the user's <see cref="User.SecurityStamp"/>.
		/// </returns>
		public virtual async Task<string> GetSecurityStampAsync(U user, CancellationToken cancellationToken)
		{
			if (user == null) throw new ArgumentNullException(nameof(user));

			await OnGettingSecurityStampAsync(user);

			return user.SecurityStamp;
		}

		/// <summary>
		/// Set the security stamp of a user.
		/// </summary>
		/// <param name="user">The identity user to assign the security stamp to.</param>
		/// <param name="stamp">The stamp to assign.</param>
		/// <param name="cancellationToken">The cancellation token for the operation.</param>
		/// <returns>Returns a task completing the action.</returns>
		/// <remarks>
		/// This implementation writes to the <see cref="User.SecurityStamp"/> 
		/// property of the <see cref="User"/>.
		/// </remarks>
		public virtual async Task SetSecurityStampAsync(U user, string stamp, CancellationToken cancellationToken)
		{
			if (user == null) throw new ArgumentNullException(nameof(user));

			using (var transaction = this.DomainContainer.BeginTransaction())
			{
				user.SecurityStamp = stamp;

				await OnSettingSecurityStampAsync(user);

				await transaction.CommitAsync(cancellationToken);
			}
		}

		#endregion

		#region Protected methods

		/// <summary>
		/// Called during <see cref="CreateAsync"/> method.
		/// The default implementation 
		/// fires the <see cref="CreatingUser"/> event
		/// and notifies listeners.
		/// This is the point to add default roles, permissions, managers
		/// to a user. 
		/// </summary>
		/// <param name="user">The user to administer.</param>
		protected virtual async Task OnCreatingUserAsync(U user)
		{
			foreach (var listener in this.userListeners)
			{
				await listener.OnCreatingUserAsync(this, user);
			}

			this.CreatingUser?.Invoke(this, user);
		}

		/// <summary>
		/// Called during <see cref="UpdateAsync"/> method.
		/// The default implementation 
		/// fires the <see cref="UpdatingUser"/> event
		/// and notifies listeners.
		/// </summary>
		/// <param name="user">The user to administer.</param>
		protected virtual async Task OnUpdatingUserAsync(U user)
		{
			foreach (var listener in this.userListeners)
			{
				await listener.OnUpdatingUserAsync(this, user);
			}

			this.UpdatingUser?.Invoke(this, user);
		}

		/// <summary>
		/// Called during <see cref="DeleteAsync"/> method.
		/// The default implementation 
		/// fires the <see cref="DeletingUser"/> event
		/// and notifies listeners.
		/// </summary>
		/// <param name="user">The user to administer.</param>
		protected virtual async Task OnDeletingUserAsync(U user)
		{
			foreach (var listener in this.userListeners)
			{
				await listener.OnDeletingUserAsync(this, user);
			}

			this.DeletingUser?.Invoke(this, user);
		}

		/// <summary>
		/// Called during <see cref="AddLoginAsync"/>.
		/// The default implementation 
		/// fires the <see cref="AddingLogin"/> event
		/// and notifies listeners.
		/// </summary>
		/// <param name="registration">The external registration being added.</param>
		protected virtual async Task OnAddingLoginAsync(Registration registration)
		{
			foreach (var listener in this.userListeners)
			{
				await listener.OnAddingLoginAsync(this, registration);
			}

			this.AddingLogin?.Invoke(this, registration);
		}

		/// <summary>
		/// Called during <see cref="RemoveLoginAsync"/>.
		/// The default implementation 
		/// fires the <see cref="RemovingLogin"/> event
		/// and notifies listeners.
		/// </summary>
		/// <param name="registration">The external registration being removed.</param>
		protected virtual async Task OnRemovingLoginAsync(Registration registration)
		{
			foreach (var listener in this.userListeners)
			{
				await listener.OnRemovingLoginAsync(this, registration);
			}

			this.RemovingLogin?.Invoke(this, registration);
		}

		/// <summary>
		/// Called during <see cref="SetPasswordHashAsync"/>.
		/// The default implementation 
		/// fires the <see cref="ChangingPassword"/> event
		/// and notifies listeners.
		/// </summary>
		/// <param name="user">
		/// The user holding the 
		/// password hash.
		/// </param>
		protected virtual async Task OnPasswordChangingAsync(U user)
		{
			foreach (var listener in this.userListeners)
			{
				await listener.OnPasswordChangingAsync(this, user);
			}

			this.ChangingPassword?.Invoke(this, user);
		}

		/// <summary>
		/// Called during <see cref="SetEmailAsync"/>.
		/// The default implementation
		/// fires the <see cref="SettingEmail"/> event
		/// and notifies listeners.
		/// </summary>
		/// <param name="user">
		/// Theuser holding the e-mail.
		/// </param>
		protected virtual async Task OnSettingEmailAsync(U user)
		{
			foreach (var listener in this.userListeners)
			{
				await listener.OnSettingEmailAsync(this, user);
			}

			this.SettingEmail?.Invoke(this, user);
		}

		/// <summary>
		/// Called during <see cref="SetEmailAsync"/>.
		/// The default implementation
		/// fires the <see cref="SettingEmail"/> event 
		/// and notifies listeners.
		/// </summary>
		/// <param name="user">
		/// The iuser holding the 
		/// e-mail.
		/// </param>
		protected virtual async Task OnConfirmingEmailAsync(U user)
		{
			foreach (var listener in this.userListeners)
			{
				await listener.OnConfirmingEmailAsync(this, user);
			}

			this.ConfirmingEmail?.Invoke(this, user);
		}

		/// <summary>
		/// Called during <see cref="GetSecurityStampAsync"/>.
		/// The default implementation fires the <see cref="GettingSecurityStamp"/> event
		/// and notifies listeners.
		/// </summary>
		/// <param name="user">The user whose security stamp is read.</param>
		protected virtual async Task OnGettingSecurityStampAsync(U user)
		{
			foreach (var listener in this.userListeners)
			{
				await listener.OnGettingSecurityStampAsync(this, user);
			}

			this.GettingSecurityStamp?.Invoke(this, user);
		}

		/// <summary>
		/// Called during <see cref="SetSecurityStampAsync"/>.
		/// The default implementation fires the <see cref="SettingSecurityStamp"/> event
		/// and notifies listeners.
		/// </summary>
		/// <param name="user">The user whose security stamp is set.</param>
		protected virtual async Task OnSettingSecurityStampAsync(U user)
		{
			foreach (var listener in this.userListeners)
			{
				await listener.OnSettingSecurityStampAsync(this, user);
			}

			this.SettingSecurityStamp?.Invoke(this, user);
		}

		#endregion

		#region Private methods

		/// <summary>
		/// Find the role with the given name or return null.
		/// </summary>
		/// <param name="roleName">The role name.</param>
		/// <param name="cancellationToken">Cancellation token for the operation.</param>
		/// <returns>Returna a task whose result contains the found role or null.</returns>
		private Task<Role> FindRoleAsync(string roleName, CancellationToken cancellationToken)
		{
			if (roleName == null) throw new ArgumentNullException("roleName");

			var roleQuery = from role in DomainContainer.Roles
											where role.Name == roleName
											select role;

			return roleQuery.FirstOrDefaultAsync(cancellationToken);
		}

		/// <summary>
		/// Get the <see cref="RegistrationProvider"/> which corresponds to 
		/// a given <see cref="UserLoginInfo"/>.
		/// </summary>
		/// <exception cref="IdentityException">
		/// Thrown when the <see cref="UserLoginInfo.LoginProvider"/>
		/// can't be mapped to a <see cref="RegistrationProvider"/>.
		/// </exception>
		private static RegistrationProvider GetRegistrationProvider(UserLoginInfo login)
		{
			if (login == null) throw new ArgumentNullException(nameof(login));

			return GetRegistrationProvider(login.LoginProvider);
		}

		/// <summary>
		/// Get the <see cref="RegistrationProvider"/> which corresponds to 
		/// a given login provider.
		/// </summary>
		/// <exception cref="IdentityException">
		/// Thrown when the <paramref name="loginProvider"/>
		/// can't be mapped to a <see cref="RegistrationProvider"/>.
		/// </exception>
		private static RegistrationProvider GetRegistrationProvider(string loginProvider)
		{
			try
			{
				return
					(RegistrationProvider)Enum.Parse(typeof(RegistrationProvider), loginProvider, true);
			}
			catch (Exception ex)
			{
				throw new IdentityException($"Unknown login provider '{loginProvider}'", ex);
			}
		}

		#endregion
	}
}
