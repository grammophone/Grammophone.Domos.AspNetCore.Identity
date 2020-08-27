using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Grammophone.DataAccess;
using Grammophone.Domos.DataAccess;
using Grammophone.Domos.Domain;
using Microsoft.AspNetCore.Identity;

namespace Grammophone.Domos.AspNetCore.Identity
{
	/// <summary>
	/// Implementation of an ASP.NET Identity role store that is based
	/// on user domain object derived from <see cref="User"/>.
	/// It expects a Unity container defining an <see cref="IUsersDomainContainer{U}"/>.
	/// </summary>
	/// <typeparam name="U">The type of the user, derived from <see cref="User"/>.</typeparam>
	/// <typeparam name="D">The type of the domain container, derived from <see cref="IUsersDomainContainer{U}"/>.</typeparam>
	public class RoleStore<U, D> : Store<U, D>, IRoleStore<Role>
		where U : User
		where D : IUsersDomainContainer<U>
	{
		#region Construction

		/// <summary>
		/// Create.
		/// </summary>
		/// <param name="configurationSectionName">
		/// The name of a unity configuration section, where
		/// a <see cref="IUsersDomainContainer{U}"/> is defined.
		/// </param>
		public RoleStore(string configurationSectionName) : base(configurationSectionName)
		{
		}

		#endregion

		#region Public properties

		/// <summary>
		/// The users in the system.
		/// </summary>
		public IQueryable<Role> Roles => this.DomainContainer.Roles;

		#endregion

		#region IRoleStore<Role> implementation

		/// <inheritdoc/>
		public async Task<IdentityResult> CreateAsync(Role role, CancellationToken cancellationToken)
		{
			if (role == null) throw new ArgumentNullException(nameof(role));

			using (var transaction = this.DomainContainer.BeginTransaction())
			{
				if (await this.DomainContainer.Roles.AnyAsync(r => r.CodeName == role.CodeName))
				{
					transaction.Pass();

					return IdentityResult.Failed(new IdentityError { Code = "ALREADY_EXISTS", Description = "There already exists a role with the same code name." });
				}

				if (await this.DomainContainer.Roles.AnyAsync(r => r.Name == role.Name))
				{
					transaction.Pass();

					return IdentityResult.Failed(new IdentityError { Code = "ALREADY_EXISTS", Description = "There already exists a role with the same name." });
				}

				this.DomainContainer.Roles.Add(role);

				await this.DomainContainer.SaveChangesAsync(cancellationToken);
			}

			return IdentityResult.Success;
		}

		/// <inheritdoc/>
		public async Task<IdentityResult> DeleteAsync(Role role, CancellationToken cancellationToken)
		{
			if (role == null) throw new ArgumentNullException(nameof(role));

			try
			{
				this.DomainContainer.Roles.Remove(role);

				await this.DomainContainer.SaveChangesAsync(cancellationToken);
			}
			catch (IntegrityViolationException)
			{
				return IdentityResult.Failed(new IdentityError { Code = "IN_USE", Description = "Cannot delete role because it is in use." });
			}

			return IdentityResult.Success;
		}

		/// <inheritdoc/>
		public Task<Role> FindByIdAsync(string roleId, CancellationToken cancellationToken)
		{
			if (!long.TryParse(roleId, out long roleIdValue))
			{
				throw new ArgumentException("The Role ID is not a valid long integer value.", nameof(roleId));
			}

			return this.DomainContainer.Roles.SingleAsync(r => r.ID == roleIdValue, cancellationToken);
		}

		/// <inheritdoc/>
		public Task<Role> FindByNameAsync(string normalizedRoleName, CancellationToken cancellationToken)
		{
			if (normalizedRoleName == null) throw new ArgumentNullException(nameof(normalizedRoleName));

			return this.DomainContainer.Roles.SingleAsync(r => r.CodeName == normalizedRoleName, cancellationToken);
		}

		/// <summary>
		/// Returns the role's <see cref="Role.CodeName"/>.
		/// </summary>
		public Task<string> GetNormalizedRoleNameAsync(Role role, CancellationToken cancellationToken)
		{
			if (role == null) throw new ArgumentNullException(nameof(role));

			return Task.FromResult(role.CodeName);
		}

		/// <inheritdoc/>
		public Task<string> GetRoleIdAsync(Role role, CancellationToken cancellationToken)
		{
			if (role == null) throw new ArgumentNullException(nameof(role));

			return Task.FromResult(role.ID.ToString());
		}

		/// <inheritdoc/>
		public Task<string> GetRoleNameAsync(Role role, CancellationToken cancellationToken)
		{
			if (role == null) throw new ArgumentNullException(nameof(role));

			return Task.FromResult(role.Name);
		}

		/// <summary>
		/// Sets the <see cref="Role.CodeName"/> of a role.
		/// </summary>
		/// <param name="role">The role.</param>
		/// <param name="normalizedName">The code name to set.</param>
		/// <param name="cancellationToken">The cancellation token for the operation.</param>
		public Task SetNormalizedRoleNameAsync(Role role, string normalizedName, CancellationToken cancellationToken)
		{
			if (role == null) throw new ArgumentNullException(nameof(role));
			if (normalizedName == null) throw new ArgumentNullException(nameof(normalizedName));

			role.CodeName = normalizedName;

			return this.DomainContainer.SaveChangesAsync(cancellationToken);
		}

		/// <summary>
		/// Sets the <see cref="Role.CodeName"/> of a role.
		/// </summary>
		/// <param name="role">The role.</param>
		/// <param name="roleName">The name of the role.</param>
		/// <param name="cancellationToken">The cancellation token for the operation.</param>
		public Task SetRoleNameAsync(Role role, string roleName, CancellationToken cancellationToken)
		{
			if (role == null) throw new ArgumentNullException(nameof(role));
			if (roleName == null) throw new ArgumentNullException(nameof(roleName));

			role.Name = roleName;

			return this.DomainContainer.SaveChangesAsync(cancellationToken);
		}

		/// <inheritdoc/>
		public async Task<IdentityResult> UpdateAsync(Role role, CancellationToken cancellationToken)
		{
			this.DomainContainer.AttachGraphAsModified(role);

			await this.DomainContainer.SaveChangesAsync(cancellationToken);

			return IdentityResult.Success;
		}

		#endregion
	}
}
