using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Grammophone.Domos.DataAccess;
using Grammophone.Domos.Domain;
using Grammophone.Setup;

namespace Grammophone.Domos.AspNet.Identity
{
	/// <summary>
	/// Implementation of an ASP.NET Identity user store that is based
	/// on user domain object derived from <see cref="User"/>.
	/// It expects a Unity container defining an <see cref="IUsersDomainContainer{U}"/>
	/// and optionally any listeners implementing <see cref="IUserListener{U}"/>.
	/// </summary>
	/// <typeparam name="U">The type of the user, derived from <see cref="User"/>.</typeparam>
	public class UserStore<U> :
		IUserStore<IdentityUser<U>, long>,
		IUserLoginStore<IdentityUser<U>, long>,
		IUserPasswordStore<IdentityUser<U>, long>,
		IUserRoleStore<IdentityUser<U>, long>,
		IUserEmailStore<IdentityUser<U>, long>,
		IUserLockoutStore<IdentityUser<U>, long>,
		IUserTwoFactorStore<IdentityUser<U>, long>,
		IUserSecurityStampStore<IdentityUser<U>, long>
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

			internal Login(IdentityUser<U> user, UserLoginInfo info)
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
			public IdentityUser<U> User { get; private set; }

			/// <summary>
			/// The external registration.
			/// </summary>
			public UserLoginInfo Info { get; private set; }

			#endregion
		}

		#endregion

		#region Private fields

		private readonly IEnumerable<IUserListener<U>> userListeners;

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

		#endregion

		#region IUserStore<IdentityUser<U>,long> Members

		/// <summary>
		/// Create a user.
		/// </summary>
		/// <param name="user">The user to create.</param>
		/// <returns>Returns the task which completes the operation.</returns>
		/// <remarks>
		/// <see cref="OnCreatingUserAsync"/> is invoked whose default implementation
		/// fires the <see cref="CreatingUser"/> event during this method.
		/// </remarks>
		public virtual async Task CreateAsync(IdentityUser<U> user)
		{
			if (user == null) throw new ArgumentNullException(nameof(user));

			var domainUser = user.DomainUser;

			using (var transaction = DomainContainer.BeginTransaction())
			{
				DomainContainer.Users.Add(domainUser);

				domainUser.SecurityStamp = String.Empty;
				domainUser.CreationDate = DateTime.UtcNow;
				domainUser.Guid = new Guid();

				await OnCreatingUserAsync(domainUser);

				await DomainContainer.SaveChangesAsync();

				transaction.Commit();
			}

		}

		/// <summary>
		/// Delete a user.
		/// </summary>
		/// <param name="user">The user to create.</param>
		/// <returns>Returns the task which completes the operation.</returns>
		/// <remarks>
		/// <see cref="OnDeletingUserAsync"/> is invoked whose default implementation
		/// fires the <see cref="DeletingUser"/> event during this method.
		/// </remarks>
		public virtual async Task DeleteAsync(IdentityUser<U> user)
		{
			if (user == null) throw new ArgumentNullException("user");

			var domainUser = user.DomainUser;

			using (var transaction = DomainContainer.BeginTransaction())
			{
				DomainContainer.Users.Attach(domainUser);

				await OnDeletingUserAsync(domainUser);

				DomainContainer.Users.Remove(domainUser);

				await DomainContainer.SaveChangesAsync();

				transaction.Commit();
			}

		}

		/// <summary>
		/// Find a user by her ID.
		/// </summary>
		/// <param name="userID">The ID of the user.</param>
		/// <returns>
		/// Returns a task whose <see cref="Task{T}.Result"/>
		/// is the user found or null.
		/// </returns>
		public virtual async Task<IdentityUser<U>> FindByIdAsync(long userID)
		{
			var domainUser =
				await DomainContainer.Users
				.Include(u => u.Registrations)
				.Include(u => u.Roles)
				.Where(u => u.RegistrationStatus != RegistrationStatus.Revoked)
				.FirstOrDefaultAsync(u => u.ID == userID);

			if (domainUser == null)
				return null;
			else
				return new IdentityUser<U>(domainUser);
		}

		/// <summary>
		/// Find a user by her unique user name.
		/// </summary>
		/// <param name="userName">The <see cref="User.UserName"/> of the user.</param>
		/// <returns>
		/// Returns a task whose <see cref="Task{T}.Result"/>
		/// is the user found or null.
		/// </returns>
		public virtual async Task<IdentityUser<U>> FindByNameAsync(string userName)
		{
			if (userName == null) throw new ArgumentNullException(nameof(userName));

			var domainUser =
				await DomainContainer.Users
				.Include(u => u.Registrations)
				.Include(u => u.Roles)
				.Where(u => u.RegistrationStatus != RegistrationStatus.Revoked)
				.FirstOrDefaultAsync(u => u.UserName == userName);

			if (domainUser == null)
				return null;
			else
				return new IdentityUser<U>(domainUser);
		}

		/// <summary>
		/// Update a user.
		/// </summary>
		/// <param name="user"></param>
		/// <returns>Returns the task which completes the operation.</returns>
		/// <remarks>
		/// <see cref="OnUpdatingUserAsync"/> is invoked whose default implementation
		/// fires the <see cref="DeletingUser"/> event during this method.
		/// </remarks>
		public virtual async Task UpdateAsync(IdentityUser<U> user)
		{
			if (user == null) throw new ArgumentNullException(nameof(user));

			var domainUser = user.DomainUser;

			using (var transaction = DomainContainer.BeginTransaction())
			{
				DomainContainer.Users.Attach(domainUser);

				await OnUpdatingUserAsync(domainUser);

				DomainContainer.SetAsModified(domainUser);

				await DomainContainer.SaveChangesAsync();

				transaction.Commit();
			}
		}

		#endregion

		#region IDisposable Members

		/// <summary>
		/// Dispose the store. The store is unusable after the method is invoked.
		/// </summary>
		public void Dispose()
		{
			this.DomainContainer.Dispose();
			this.Settings.Dispose();
		}

		#endregion

		#region IUserLoginStore<IdentityUser<U>,long> Members

		/// <summary>
		/// Add a <see cref="Registration"/> to a <see cref="User"/>.
		/// </summary>
		/// <param name="user">
		/// The Identity user which wraps a <see cref="User"/>.
		/// </param>
		/// <param name="login">
		/// The <see cref="UserLoginInfo"/> 
		/// that corresponds to the <see cref="Registration"/>.
		/// </param>
		/// <returns>Returns the task which completes the operation.</returns>
		public virtual async Task AddLoginAsync(IdentityUser<U> user, UserLoginInfo login)
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
				registration.User = user.DomainUser;

				await OnAddingLoginAsync(registration);

				DomainContainer.Registrations.Add(registration);

				await DomainContainer.SaveChangesAsync();

				transaction.Commit();
			}
		}

		/// <summary>
		/// Find a user by her (external) registration.
		/// </summary>
		/// <param name="login">
		/// The <see cref="UserLoginInfo"/> that corresponds to the <see cref="Registration"/>.
		/// </param>
		/// <returns>
		/// Returns an task whose <see cref="Task{T}.Result"/> contains the found user
		/// or null.
		/// </returns>
		public virtual async Task<IdentityUser<U>> FindAsync(UserLoginInfo login)
		{
			if (login == null) throw new ArgumentNullException(nameof(login));

			var registrationProvider = GetRegistrationProvider(login);

			var userQuery = from user in DomainContainer.Users
											.Include(user => user.Registrations)
											.Include(user => user.Roles)
											where
											user.RegistrationStatus != RegistrationStatus.Revoked &&
											user.Registrations.Any(
												registration =>
													registration.ProviderKey == login.ProviderKey
													&& registration.Provider == registrationProvider)
											select user;

			var foundUser = await userQuery.FirstOrDefaultAsync();

			if (foundUser != null)
				return new IdentityUser<U>(foundUser);
			else
				return null;
		}

		/// <summary>
		/// Get the (external) registrations of a user.
		/// </summary>
		/// <param name="user">The user.</param>
		/// <returns>
		/// Returns a task whose <see cref="Task{T}.Result"/> holds the 
		/// <see cref="UserLoginInfo"/>'s which correspond to the user's
		/// registrations.
		/// </returns>
		public Task<IList<UserLoginInfo>> GetLoginsAsync(IdentityUser<U> user)
		{
			if (user == null) throw new ArgumentNullException(nameof(user));

			return Task.FromResult(user.GetLoginInfos());
		}

		/// <summary>
		/// Remove an external login of a user.
		/// </summary>
		/// <param name="user">The user.</param>
		/// <param name="login">The representation of an external login.</param>
		/// <returns>Returns a task for the operation.</returns>
		public virtual async Task RemoveLoginAsync(IdentityUser<U> user, UserLoginInfo login)
		{
			if (user == null) throw new ArgumentNullException(nameof(user));
			if (login == null) throw new ArgumentNullException(nameof(login));

			var registrationProvider = GetRegistrationProvider(login);

			using (var transaction = DomainContainer.BeginTransaction())
			{
				var registrationFound =
					user.DomainUser.Registrations.FirstOrDefault(registration =>
						registration.ProviderKey == login.ProviderKey && registration.Provider == registrationProvider);

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

		#region IUserPasswordStore<IdentityUser<U>,long> Members

		/// <summary>
		/// Get the password hash of the user if set, else null.
		/// </summary>
		/// <param name="user">The user.</param>
		/// <returns>
		/// Returns a task whose <see cref="Task{T}.Result"/> will contain the 
		/// password hash or null.
		/// </returns>
		public Task<string> GetPasswordHashAsync(IdentityUser<U> user)
		{
			if (user == null) throw new ArgumentNullException(nameof(user));

			switch (user.DomainUser.RegistrationStatus)
			{
				case RegistrationStatus.PendingVerification:
				case RegistrationStatus.Verified:
					return Task.FromResult(user.DomainUser.PasswordHash);

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
		/// <returns>
		/// Returns a task whose <see cref="Task{T}.Result"/> contains
		/// a boolean value indicating whether the user has a password or not.
		/// </returns>
		public Task<bool> HasPasswordAsync(IdentityUser<U> user)
		{
			if (user == null) throw new ArgumentNullException(nameof(user));

			return Task.FromResult(user.DomainUser.PasswordHash != null);
		}

		/// <summary>
		/// Set the password of a user.
		/// </summary>
		/// <param name="user">The user.</param>
		/// <param name="passwordHash">The password hash to set.</param>
		/// <returns>Returns a task for the operation.</returns>
		public Task SetPasswordHashAsync(IdentityUser<U> user, string passwordHash)
		{
			if (user == null) throw new ArgumentNullException(nameof(user));

			user.DomainUser.PasswordHash = passwordHash;

			return Task.CompletedTask;
		}

		#endregion

		#region IUserRoleStore<IdentityUser<U>,long> Members

		/// <summary>
		/// Add a role to a user. The role must exist in the system.
		/// </summary>
		/// <param name="user">The user.</param>
		/// <param name="roleName">The name of the role to add.</param>
		/// <returns>Returns a task completing the operation.</returns>
		/// <exception cref="IdentityException">
		/// Thrown when a role having the given <paramref name="roleName"/>
		/// does not exist in the system.
		/// </exception>
		public virtual async Task AddToRoleAsync(IdentityUser<U> user, string roleName)
		{
			if (user == null) throw new ArgumentNullException(nameof(user));
			if (roleName == null) throw new ArgumentNullException(nameof(roleName));

			var domainUser = user.DomainUser;

			using (var transaction = DomainContainer.BeginTransaction())
			{
				DomainContainer.Users.Attach(domainUser);

				if (domainUser.Roles.Any(r => r.Name == roleName)) return;

				var role = await FindRoleAsync(roleName);

				if (role == null)
					throw new IdentityException($"The role '{roleName}' does not exist in the system.");

				domainUser.Roles.Add(role);

				await DomainContainer.SaveChangesAsync();

				transaction.Commit();
			}
		}

		/// <summary>
		/// Get the roles of a user.
		/// </summary>
		/// <param name="user">The user.</param>
		/// <returns>
		/// Returns a task whose <see cref="Task{T}.Result"/>
		/// contains the roles names of the user.
		/// </returns>
		public Task<IList<string>> GetRolesAsync(IdentityUser<U> user)
		{
			if (user == null) throw new ArgumentNullException(nameof(user));

			var roleNames = from role in user.DomainUser.Roles
											select role.Name;

			return Task.FromResult<IList<string>>(roleNames.ToList());
		}

		/// <summary>
		/// Check whether a user has a role.
		/// </summary>
		/// <param name="user">The user.</param>
		/// <param name="roleName">the role name.</param>
		/// <returns>
		/// Returns a task whose <see cref="Task{T}.Result"/>
		/// determines whether the user has the role.
		/// </returns>
		public Task<bool> IsInRoleAsync(IdentityUser<U> user, string roleName)
		{
			if (user == null) throw new ArgumentNullException(nameof(user));
			if (roleName == null) throw new ArgumentNullException(nameof(roleName));

			return Task.FromResult(
				user.DomainUser.Roles.Any(role => role.Name == roleName));
		}

		/// <summary>
		/// Remove a role from a user. If the role does not exist
		/// or the user doesn't havit, nothing happens.
		/// </summary>
		/// <param name="user">The user.</param>
		/// <param name="roleName">The name of the role to remove from the user.</param>
		/// <returns>Returns a task for the operation.</returns>
		public virtual async Task RemoveFromRoleAsync(IdentityUser<U> user, string roleName)
		{
			if (user == null) throw new ArgumentNullException(nameof(user));
			if (roleName == null) throw new ArgumentNullException(nameof(roleName));

			var domainUser = user.DomainUser;

			using (var transaction = DomainContainer.BeginTransaction())
			{
				DomainContainer.Users.Attach(domainUser);

				var removedRole = domainUser.Roles.Where(r => r.Name == roleName).FirstOrDefault();

				if (removedRole == null) return;

				domainUser.Roles.Add(removedRole);

				await DomainContainer.SaveChangesAsync();

				transaction.Commit();
			}
		}

		#endregion

		#region IUserEmailStore<IdentityUser<U>,long> Members

		/// <summary>
		/// Find a user by her e-mail.
		/// </summary>
		/// <param name="email">The e-mail.</param>
		/// <returns>
		/// Returns a task whose <see cref="Task{T}.Result"/> contains 
		/// the user found or null.
		/// </returns>
		public virtual async Task<IdentityUser<U>> FindByEmailAsync(string email)
		{
			if (email == null) throw new ArgumentNullException(nameof(email));

			var userQuery = from user in DomainContainer.Users
											.Include(u => u.Registrations)
											.Include(u => u.Roles)
											where user.Email == email && user.RegistrationStatus != RegistrationStatus.Revoked
											select user;

			var userFound = await userQuery.FirstOrDefaultAsync();

			if (userFound != null)
				return new IdentityUser<U>(userFound);
			else
				return null;
		}

		/// <summary>
		/// Get the e-mail of a user.
		/// </summary>
		/// <param name="user">The user.</param>
		/// <returns>
		/// Returns a task whose <see cref="Task{T}.Result"/> contains 
		/// the user's e-mail.
		/// </returns>
		public Task<string> GetEmailAsync(IdentityUser<U> user)
		{
			if (user == null) throw new ArgumentNullException(nameof(user));

			return Task.FromResult(user.DomainUser.Email);
		}

		/// <summary>
		/// Determine whether a user's e-mail is confirmed.
		/// </summary>
		/// <param name="user">the user.</param>
		/// <returns>
		/// Returns a task whose <see cref="Task{T}.Result"/> contains 
		/// true if the user has her e-mail confirmed.
		/// </returns>
		public Task<bool> GetEmailConfirmedAsync(IdentityUser<U> user)
		{
			if (user == null) throw new ArgumentNullException(nameof(user));

			return Task.FromResult(user.DomainUser.RegistrationStatus != RegistrationStatus.PendingVerification);
		}

		/// <summary>
		/// Set the e-mail of a user.
		/// </summary>
		/// <param name="user">The user.</param>
		/// <param name="email">the user's e-mail.</param>
		/// <returns>Returns a task which completes the operation.</returns>
		public virtual async Task SetEmailAsync(IdentityUser<U> user, string email)
		{
			if (user == null) throw new ArgumentNullException(nameof(user));
			if (email == null) throw new ArgumentNullException(nameof(email));

			using (var transaction = DomainContainer.BeginTransaction())
			{
				user.DomainUser.Email = email;

				await OnSettingEmailAsync(user.DomainUser);

				await DomainContainer.SaveChangesAsync();

				transaction.Commit();
			}
		}

		/// <summary>
		/// Set whether a user's e-mail is confirmed.
		/// </summary>
		/// <param name="user">The user.</param>
		/// <param name="confirmed">True if the user's e-mail is confirmed.</param>
		/// <returns>Returns a task which completes the operation.</returns>
		public virtual async Task SetEmailConfirmedAsync(IdentityUser<U> user, bool confirmed)
		{
			if (user == null) throw new ArgumentNullException(nameof(user));

			using (var transaction = DomainContainer.BeginTransaction())
			{
				var domainUser = user.DomainUser;

				if (domainUser.RegistrationStatus == RegistrationStatus.PendingVerification)
				{
					domainUser.RegistrationStatus = RegistrationStatus.Verified;

					await OnConfirmingEmailAsync(domainUser);

					await DomainContainer.SaveChangesAsync();

					transaction.Commit();
				}
			}
		}

		#endregion

		#region IUserLockoutStore<IdentityUser<U>,long> Members

		/// <summary>
		/// Always gets zero.
		/// </summary>
		public virtual Task<int> GetAccessFailedCountAsync(IdentityUser<U> user)
		{
			return Task.FromResult(0);
		}

		/// <summary>
		/// Always returns false.
		/// </summary>
		public virtual Task<bool> GetLockoutEnabledAsync(IdentityUser<U> user)
		{
			return Task.FromResult(false);
		}

		/// <summary>
		/// Returns <see cref="DateTimeOffset.MinValue"/>, representing that the account is not locked.
		/// </summary>
		public virtual Task<DateTimeOffset> GetLockoutEndDateAsync(IdentityUser<U> user)
		{
			return Task.FromResult(DateTimeOffset.MinValue);
		}

		/// <summary>
		/// Always returns 1.
		/// </summary>
		public virtual Task<int> IncrementAccessFailedCountAsync(IdentityUser<U> user)
		{
			return Task.FromResult(1);
		}

		/// <summary>
		/// This method does notning.
		/// </summary>
		public virtual Task ResetAccessFailedCountAsync(IdentityUser<U> user)
		{
			return Task.CompletedTask;
		}

		/// <summary>
		/// Not implemented.
		/// </summary>
		public virtual Task SetLockoutEnabledAsync(IdentityUser<U> user, bool enabled)
		{
			return Task.CompletedTask;
		}

		/// <summary>
		/// Not implemented.
		/// </summary>
		public virtual Task SetLockoutEndDateAsync(IdentityUser<U> user, DateTimeOffset lockoutEnd)
		{
			return Task.CompletedTask;
		}

		#endregion

		#region IUserTwoFactorStore<IdentityUser<U>,long> Members

		/// <summary>
		/// Always returns false.
		/// </summary>
		public virtual Task<bool> GetTwoFactorEnabledAsync(IdentityUser<U> user)
		{
			return Task.FromResult(false);
		}

		/// <summary>
		/// Not implemented.
		/// </summary>
		public virtual Task SetTwoFactorEnabledAsync(IdentityUser<U> user, bool enabled)
		{
			return Task.CompletedTask;
		}

		#endregion

		#region IUserSecurityStampStore<IdentityUser<U>,long> Members

		/// <summary>
		/// Get the security stamp of a user.
		/// </summary>
		/// <param name="user">The identity user to retrieve the security stamp from.</param>
		/// <returns>
		/// Returns a task whose result contains the user's <see cref="User.SecurityStamp"/>.
		/// </returns>
		public virtual async Task<string> GetSecurityStampAsync(IdentityUser<U> user)
		{
			if (user == null) throw new ArgumentNullException(nameof(user));

			await OnGettingSecurityStampAsync(user.DomainUser);

			return user.DomainUser.SecurityStamp;
		}

		/// <summary>
		/// Set the security stamp of a user.
		/// </summary>
		/// <param name="user">The identity user to assign the security stamp to.</param>
		/// <param name="stamp">The stamp to assign.</param>
		/// <returns>Returns a task completing the action.</returns>
		/// <remarks>
		/// This implementation writes to the <see cref="User.SecurityStamp"/> 
		/// property of the <see cref="User"/>.
		/// </remarks>
		public virtual async Task SetSecurityStampAsync(IdentityUser<U> user, string stamp)
		{
			if (user == null) throw new ArgumentNullException(nameof(user));

			using (var transaction = this.DomainContainer.BeginTransaction())
			{
				user.DomainUser.SecurityStamp = stamp;

				await OnSettingSecurityStampAsync(user.DomainUser);

				await transaction.CommitAsync();
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
		/// <param name="domainUser">The user to administer.</param>
		protected virtual async Task OnCreatingUserAsync(U domainUser)
		{
			foreach (var listener in this.userListeners)
			{
				await listener.OnCreatingUserAsync(this, domainUser);
			}

			this.CreatingUser?.Invoke(this, domainUser);
		}

		/// <summary>
		/// Called during <see cref="UpdateAsync"/> method.
		/// The default implementation 
		/// fires the <see cref="UpdatingUser"/> event
		/// and notifies listeners.
		/// </summary>
		/// <param name="domainUser">The user to administer.</param>
		protected virtual async Task OnUpdatingUserAsync(U domainUser)
		{
			foreach (var listener in this.userListeners)
			{
				await listener.OnUpdatingUserAsync(this, domainUser);
			}

			this.UpdatingUser?.Invoke(this, domainUser);
		}

		/// <summary>
		/// Called during <see cref="DeleteAsync"/> method.
		/// The default implementation 
		/// fires the <see cref="DeletingUser"/> event
		/// and notifies listeners.
		/// </summary>
		/// <param name="domainUser">The user to administer.</param>
		protected virtual async Task OnDeletingUserAsync(U domainUser)
		{
			foreach (var listener in this.userListeners)
			{
				await listener.OnDeletingUserAsync(this, domainUser);
			}

			this.DeletingUser?.Invoke(this, domainUser);
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
		/// <param name="domainUser">
		/// The user holding the 
		/// password hash.
		/// </param>
		protected virtual async Task OnPasswordChangingAsync(U domainUser)
		{
			foreach (var listener in this.userListeners)
			{
				await listener.OnPasswordChangingAsync(this, domainUser);
			}

			this.ChangingPassword?.Invoke(this, domainUser);
		}

		/// <summary>
		/// Called during <see cref="SetEmailAsync"/>.
		/// The default implementation
		/// fires the <see cref="SettingEmail"/> event
		/// and notifies listeners.
		/// </summary>
		/// <param name="domainUser">
		/// Theuser holding the e-mail.
		/// </param>
		protected virtual async Task OnSettingEmailAsync(U domainUser)
		{
			foreach (var listener in this.userListeners)
			{
				await listener.OnSettingEmailAsync(this, domainUser);
			}

			this.SettingEmail?.Invoke(this, domainUser);
		}

		/// <summary>
		/// Called during <see cref="SetEmailAsync"/>.
		/// The default implementation
		/// fires the <see cref="SettingEmail"/> event 
		/// and notifies listeners.
		/// </summary>
		/// <param name="domainUser">
		/// The iuser holding the 
		/// e-mail.
		/// </param>
		protected virtual async Task OnConfirmingEmailAsync(U domainUser)
		{
			foreach (var listener in this.userListeners)
			{
				await listener.OnConfirmingEmailAsync(this, domainUser);
			}

			this.ConfirmingEmail?.Invoke(this, domainUser);
		}

		/// <summary>
		/// Called during <see cref="GetSecurityStampAsync"/>.
		/// The default implementation fires the <see cref="GettingSecurityStamp"/> event
		/// and notifies listeners.
		/// </summary>
		/// <param name="domainUser">The user whose security stamp is read.</param>
		protected virtual async Task OnGettingSecurityStampAsync(U domainUser)
		{
			foreach (var listener in this.userListeners)
			{
				await listener.OnGettingSecurityStampAsync(this, domainUser);
			}

			this.GettingSecurityStamp?.Invoke(this, domainUser);
		}

		/// <summary>
		/// Called during <see cref="SetSecurityStampAsync"/>.
		/// The default implementation fires the <see cref="SettingSecurityStamp"/> event
		/// and notifies listeners.
		/// </summary>
		/// <param name="domainUser">The user whose security stamp is set.</param>
		protected virtual async Task OnSettingSecurityStampAsync(U domainUser)
		{
			foreach (var listener in this.userListeners)
			{
				await listener.OnSettingSecurityStampAsync(this, domainUser);
			}

			this.SettingSecurityStamp?.Invoke(this, domainUser);
		}

		#endregion

		#region Private methods

		/// <summary>
		/// Find the role with the given name or return null.
		/// </summary>
		/// <param name="roleName">The role name.</param>
		/// <returns>Returna a task whose result contains the found role or null.</returns>
		private Task<Role> FindRoleAsync(string roleName)
		{
			if (roleName == null) throw new ArgumentNullException("roleName");

			var roleQuery = from role in DomainContainer.Roles
											where role.Name == roleName
											select role;

			return roleQuery.FirstOrDefaultAsync();
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
			try
			{
				return
					(RegistrationProvider)Enum.Parse(typeof(RegistrationProvider), login.LoginProvider, true);
			}
			catch (Exception ex)
			{
				throw new IdentityException($"Unknown login provider '{login.LoginProvider}'", ex);
			}
		}

		#endregion
	}
}
