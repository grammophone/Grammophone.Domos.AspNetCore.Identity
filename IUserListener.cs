﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Grammophone.Domos.DataAccess;
using Grammophone.Domos.Domain;

namespace Grammophone.Domos.AspNetCore.Identity
{
	/// <summary>
	/// Interface for configured event listeners.
	/// </summary>
	/// <typeparam name="UB">The type of the user, derived from <see cref="User"/>.</typeparam>
	/// <typeparam name="U">The type of the user, derived from <typeparamref name="UB"/>.</typeparam>
	/// <typeparam name="D">The type of the domain container, derived from <see cref="IUsersDomainContainer{U}"/>.</typeparam>
	public interface IUserListener<UB, U, D>
		where UB : User
		where U : UB
		where D : IUsersDomainContainer<UB>
	{
		/// <summary>
		/// Order of listener among others.
		/// </summary>
		int Order { get; }

		/// <summary>
		/// Called when a user is created.
		/// </summary>
		/// <param name="store">The store which manages the user.</param>
		/// <param name="user">The user being created.</param>
		Task OnCreatingUserAsync(UserStore<UB, U, D> store, U user);

		/// <summary>
		/// Called when a user is updated.
		/// </summary>
		/// <param name="store">The store which manages the user.</param>
		/// <param name="user">The user being updated.</param>
		Task OnUpdatingUserAsync(UserStore<UB, U, D> store, U user);

		/// <summary>
		/// Called when a user is deleted.
		/// </summary>
		/// <param name="store">The store which manages the user.</param>
		/// <param name="user">The user being deleted.</param>
		Task OnDeletingUserAsync(UserStore<UB, U, D> store, U user);

		/// <summary>
		/// Called when an external registration is added to a user.
		/// </summary>
		/// <param name="store">The store which manages the user.</param>
		/// <param name="registration">The registration being added.</param>
		Task OnAddingLoginAsync(UserStore<UB, U, D> store, Registration registration);

		/// <summary>
		/// Called when an external registration is deleted from a user.
		/// </summary>
		/// <param name="store">The store which manages the user.</param>
		/// <param name="registration">The registration being deleted.</param>
		Task OnRemovingLoginAsync(UserStore<UB, U, D> store, Registration registration);

		/// <summary>
		/// Called when a user's password is changed.
		/// </summary>
		/// <param name="store">The store which manages the user.</param>
		/// <param name="user">The user having the password.</param>
		Task OnPasswordChangingAsync(UserStore<UB, U, D> store, U user);

		/// <summary>
		/// Called when a user's email is set.
		/// </summary>
		/// <param name="store">The store which manages the user.</param>
		/// <param name="user">The user holding the e-mail.</param>
		Task OnSettingEmailAsync(UserStore<UB, U, D> store, U user);

		/// <summary>
		/// Called when a user's email is confirmed.
		/// </summary>
		/// <param name="store">The store which manages the user.</param>
		/// <param name="user">The user holding the e-mail.</param>
		Task OnConfirmingEmailAsync(UserStore<UB, U, D> store, U user);

		/// <summary>
		/// Called when the security stamp of a user is read.
		/// </summary>
		/// <param name="store">The store which manages the user.</param>
		/// <param name="user">The user whose stamp is read.</param>
		Task OnGettingSecurityStampAsync(UserStore<UB, U, D> store, U user);

		/// <summary>
		/// Called when the security stamp of a user is changed.
		/// </summary>
		/// <param name="store">The store which manages the user.</param>
		/// <param name="user">The user whose stamp is set.</param>
		Task OnSettingSecurityStampAsync(UserStore<UB, U, D> store, U user);
	}

	/// <summary>
	/// Interface for configured event listeners.
	/// </summary>
	/// <typeparam name="U">The type of the user, derived from <see cref="User"/>.</typeparam>
	/// <typeparam name="D">The type of the domain container, derived from <see cref="IUsersDomainContainer{U}"/>.</typeparam>
	public interface IUserListener<U, D> : IUserListener<U, U, D>
		where U : User
		where D : IUsersDomainContainer<U>
	{

	}
}
