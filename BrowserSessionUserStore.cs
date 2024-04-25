using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Grammophone.Domos.DataAccess;
using Grammophone.Domos.Domain;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Net.Http.Headers;
using MyCSharp.HttpUserAgentParser;

namespace Grammophone.Domos.AspNetCore.Identity
{
	/// <summary>
	/// An an ASP.NET Identity user store implementation that tracks browser sessions.
	/// It expects a Unity container defining an <see cref="IUsersDomainContainer{U}"/>,
	/// a <see cref="IPLocation.ILocationProviderFactory"/>, a <see cref="IPLocation.Caching.LocationCache"/>
	/// and optionally any listeners implementing <see cref="IUserListener{UB, U, D}"/>.
	/// </summary>
	/// <typeparam name="UB">The base type of the user, derived from <see cref="User"/>.</typeparam>
	/// <typeparam name="U">The type of the user, derived from <typeparamref name="UB"/>.</typeparam>
	/// <typeparam name="D">The type of the domain container, derived from <see cref="IUsersDomainContainer{U}"/>.</typeparam>
	public class BrowserSessionUserStore<UB, U, D> : UserStore<UB, U, D>
		where UB : User
		where U : UB
		where D : IUsersDomainContainer<UB>
	{
		#region Private fields

		private readonly IHttpContextAccessor httpContextAccessor;

		#endregion

		#region Construction

		/// <summary>
		/// Create.
		/// </summary>
		/// <param name="configurationSectionName">
		/// The name of a unity configuration section, where
		/// a <see cref="IUsersDomainContainer{U}"/> is defined
		/// and optionally any listeners implementing <see cref="IUserListener{UB, U, D}"/>.
		/// </param>
		/// <param name="httpContextAccessor">An accessor to the <see cref="HttpContext"/> of the current request.</param>
		public BrowserSessionUserStore(string configurationSectionName, IHttpContextAccessor httpContextAccessor) : base(configurationSectionName)
		{
			if (httpContextAccessor == null) throw new ArgumentNullException(nameof(httpContextAccessor));

			this.httpContextAccessor = httpContextAccessor;
		}

		#endregion

		#region Public methods

		#region IUserSecurityStampStore<U> Members

		/// <summary>
		/// If there is a finerprint, try to fetch the security stamp from the corresponding browser session, else fall back to the base implementation
		/// and get it from the user entity directly.
		/// </summary>
		/// <param name="user">The user.</param>
		/// <param name="cancellationToken">The cancellation token.</param>
		public override async Task<string> GetSecurityStampAsync(U user, CancellationToken cancellationToken)
		{
			string fingerprint = TryFindFingerprintClaim();

			if (!String.IsNullOrEmpty(fingerprint))
			{
				var browserSession = await TryGetOrCreateBrowserSessionAsync(user, fingerprint);

				if (browserSession != null)
				{
					await OnGettingSecurityStampAsync(user);

					return browserSession.SecurityStamp;
				}
			}

			return await base.GetSecurityStampAsync(user, cancellationToken);
		}

		/// <summary>
		/// If possible, use or create a browser session to set the security stamp.
		/// </summary>
		/// <param name="user">THe identity user.</param>
		/// <param name="stamp">The security stamp to set.</param>
		/// <param name="cancellationToken">The cancellation token.</param>
		public override async Task SetSecurityStampAsync(U user, string stamp, CancellationToken cancellationToken)
		{
			string fingerprint = TryFindFingerprintClaim();

			var browserSession = await TryGetOrCreateBrowserSessionAsync(user, fingerprint);

			if (browserSession != null)
			{
				browserSession.SecurityStamp = stamp;

				await OnSettingSecurityStampAsync(user);

				await this.DomainContainer.SaveChangesAsync();

				return;
			}

			await base.SetSecurityStampAsync(user, stamp, cancellationToken);
		}

		#endregion

		#region Browser session creation and retrieval

		/// <summary>
		/// Get an existing browser based on the finger print or create a new one.
		/// </summary>
		public async Task<BrowserSession> TryGetOrCreateBrowserSessionAsync(
						U user,
						string browserFingerPrint = null)
		{
			if (user == null) throw new ArgumentNullException(nameof(user));

			BrowserSession browserSession = null;
			ClientIpAddress clientIpAddress = null;

			var context = httpContextAccessor.HttpContext;

			// Get client info
			string userAgentString = context.Request?.GetTypedHeaders()?.Get<string>(HeaderNames.UserAgent);

			string ipAddress = context.Connection?.RemoteIpAddress?.ToString();

			if (browserFingerPrint != null)
			{
				var query = from bs in this.DomainContainer.BrowserSessions
										where bs.FingerPrint == browserFingerPrint && user.ID == bs.UserID
										select new
										{
											BrowserSession = bs,
											ClientIPAddress = bs.IPAddresses.Where(ipa => ipa.IpAddress == ipAddress).OrderByDescending(ipa => ipa.LastSeen).FirstOrDefault()
										};

				var result = await query.FirstOrDefaultAsync();

				browserSession = result?.BrowserSession;
				clientIpAddress = result?.ClientIPAddress;
			}

			if (browserSession == null) //first time
			{
				using (var transaction = this.DomainContainer.BeginTransaction())
				{
					//create browser session.
					browserSession = this.DomainContainer.BrowserSessions.Create();
					this.DomainContainer.BrowserSessions.Add(browserSession);

					if (userAgentString != null)
					{
						await ParseUserAgentAsync(userAgentString, browserSession);
					}

					if (!string.IsNullOrEmpty(ipAddress))
					{
						clientIpAddress = await CreateClientIpAddressAsync(ipAddress);

						browserSession.IPAddresses.Add(clientIpAddress);
					}

					browserSession.FingerPrint = browserFingerPrint ?? Guid.NewGuid().ToString();

					browserSession.SecurityStamp = user.SecurityStamp;
					browserSession.LastSeenOn = DateTime.UtcNow;
					browserSession.FirstSignInOn = DateTime.UtcNow;

					browserSession.UserID = user.ID;

					SetFingerprintClaim(browserSession.FingerPrint);

					await transaction.CommitAsync();
				}
			}
			else //returning browser
			{
				//check if the session has been logged out.
				if (browserSession.IsLoggedOff)
				{
					return null;
				}

				//update last seen
				using (var transaction = this.DomainContainer.BeginTransaction())
				{
					browserSession.LastSeenOn = DateTime.UtcNow;

					//if first seen in this address.
					if (clientIpAddress == null && ipAddress != null)
					{
						clientIpAddress = await CreateClientIpAddressAsync(ipAddress);

						browserSession.IPAddresses.Add(clientIpAddress);
					}
					else
					{
						clientIpAddress.LastSeen = DateTime.UtcNow;
					}

					await transaction.CommitAsync();
				}
			}

			return browserSession;
		}

		#endregion

		#region Session logoff methods

		/// <summary>
		/// Log off a browser session.
		/// </summary>
		/// <param name="user">The identity user to be logged of.</param>
		/// <param name="fingerprint">The fingerprint of the session to log off.</param>
		public async Task LogOffBrowserSessionAsync(U user, string fingerprint)
		{
			if (user == null) throw new ArgumentNullException(nameof(user));

			if (string.IsNullOrEmpty(fingerprint)) throw new ArgumentNullException(nameof(fingerprint));

			using (var transaction = this.DomainContainer.BeginTransaction())
			{
				var browserSession = await this.DomainContainer.BrowserSessions
					.Where(bs => bs.FingerPrint == fingerprint && bs.UserID == user.ID && !bs.IsLoggedOff)
					.FirstOrDefaultAsync();

				if (browserSession == null)
				{
					transaction.Pass();

					return;
				}

				browserSession.IsLoggedOff = true;
				browserSession.SecurityStamp = Guid.NewGuid().ToString();

				await transaction.CommitAsync();
			}
		}

		/// <summary>
		/// Log off a browser session.
		/// </summary>
		/// <param name="sessionID">The ID of the browser session.</param>
		public async Task LogOffBrowserSessionAsync(long sessionID)
		{
			var browserSession = await this.DomainContainer.BrowserSessions.Where(bs => bs.ID == sessionID).FirstOrDefaultAsync();

			if (browserSession.IsLoggedOff) return;

			using (var transaction = this.DomainContainer.BeginTransaction())
			{
				browserSession.IsLoggedOff = true;
				browserSession.SecurityStamp = Guid.NewGuid().ToString();

				await transaction.CommitAsync();
			}
		}

		/// <summary>
		/// Log off a user from all connected devices.
		/// </summary>
		/// <param name="user">The user whose sessions to log off.</param>
		public async Task GlobalLofOffAsync(U user)
		{
			if (user == null) throw new ArgumentNullException(nameof(user));

			using (var transaction = this.DomainContainer.BeginTransaction())
			{
				var activeBrowserSessions = await this.DomainContainer.BrowserSessions.Where(bs => bs.UserID == user.ID && !bs.IsLoggedOff).ToArrayAsync();

				if (activeBrowserSessions.Length == 0)
				{
					transaction.Pass();

					return;
				}

				foreach (BrowserSession session in activeBrowserSessions)
				{
					session.IsLoggedOff = true;
					session.SecurityStamp = Guid.NewGuid().ToString();
				}

				await transaction.CommitAsync();
			}
		}

		#endregion

		#endregion

		#region Protected methods

		/// <summary>
		/// Parse the 'User-Agent' header and set the <see cref="BrowserSession.Browser"/> and <see cref="BrowserSession.OperatingSystem"/>
		/// propterties.
		/// </summary>
		/// <param name="userAgent">The value of the 'User-Agent' header.</param>
		/// <param name="browserSession">The browser session to update.</param>
		protected virtual Task ParseUserAgentAsync(string userAgent, BrowserSession browserSession)
		{
			if (userAgent == null) throw new ArgumentNullException(nameof(userAgent));
			if (browserSession == null) throw new ArgumentNullException(nameof(browserSession));

			var userAgentInfo = HttpUserAgentParser.Parse(userAgent);

			string operatingSystem = userAgentInfo.Platform.HasValue ? userAgentInfo.Platform.Value.Name : null;
			string browser = $"{userAgentInfo.Name} {userAgentInfo.Version}";

			browserSession.OperatingSystem = operatingSystem;
			browserSession.Browser = browser;

			return Task.CompletedTask;
		}

		#endregion

		#region Private methods

		private async Task<ClientIpAddress> CreateClientIpAddressAsync(string ipAddress)
		{
			ClientIpAddress clientIpAddress = this.DomainContainer.ClientIpAddresses.Create();
			clientIpAddress.IpAddress = ipAddress;
			clientIpAddress.LastSeen = DateTime.UtcNow;

			//find locatin info
			try
			{
				IPAddress ipadr = IPAddress.Parse(ipAddress);

				// check if we are in a dev environment as the client will be the same machine
				if (IPAddress.IsLoopback(ipadr))
				{
					ipadr = IPAddress.Parse("31.14.242.226");
				}

				var cache = this.Settings.Resolve<IPLocation.Caching.LocationCache>();
				var location = await cache.GetLocationAsync(ipadr);

				clientIpAddress.City = location.City.Name;
				clientIpAddress.Region = location.LastSubdivision.Name;
				clientIpAddress.Country = location.Country.Name;
				clientIpAddress.RawIpServiceData = location.Response;
			}
			catch (Exception ex)
			{
				Trace.TraceWarning($"Could not parse IP address {ipAddress}, reason: {ex.Message}.");
			}

			return clientIpAddress;
		}

		private string TryFindFingerprintClaim(ClaimsIdentity identity) => identity?.FindFirst("fingerprint")?.Value;

		private string TryFindFingerprintClaim()
		{
			string fingerprint = TryFindFingerprintClaim(Thread.CurrentPrincipal.Identity as ClaimsIdentity);

			if (fingerprint != null) return fingerprint;

			var context = httpContextAccessor.HttpContext;

			fingerprint = TryFindFingerprintClaim(context.User?.Identity as ClaimsIdentity);

			if (fingerprint != null) return fingerprint;

			if (context.Items.TryGetValue("ValidatedIdentity", out object identityObject))
			{
				fingerprint = TryFindFingerprintClaim(identityObject as ClaimsIdentity);

				if (fingerprint != null) return fingerprint;
			}

			return null;
		}

		private void SetFingerprintClaim(ClaimsIdentity identity, string fingerprint)
		{
			if (identity == null) return;

			var existingClaims = identity.Claims.Where(c => c.Type == "fingerprint").ToArray();

			foreach (var existingClaim in existingClaims)
			{
				identity.RemoveClaim(existingClaim);
			}

			identity.AddClaim(new Claim("fingerprint", fingerprint));
		}

		private void SetFingerprintClaim(string fingerprint)
		{
			if (fingerprint == null) return;

			SetFingerprintClaim(Thread.CurrentPrincipal.Identity as ClaimsIdentity, fingerprint);

			var context = httpContextAccessor.HttpContext;

			SetFingerprintClaim(context.User?.Identity as ClaimsIdentity, fingerprint);

			if (context.Items.TryGetValue("ValidatedIdentity", out object identityObject))
			{
				SetFingerprintClaim(identityObject as ClaimsIdentity, fingerprint);
			}
		}

		#endregion
	}

	/// <summary>
	/// An an ASP.NET Identity user store implementation that tracks browser sessions.
	/// It expects a Unity container defining an <see cref="IUsersDomainContainer{U}"/>,
	/// a <see cref="IPLocation.ILocationProviderFactory"/>, a <see cref="IPLocation.Caching.LocationCache"/>
	/// and optionally any listeners implementing <see cref="IUserListener{U, U, D}"/>.
	/// </summary>
	/// <typeparam name="U">The type of the user, derived from <see cref="User"/>.</typeparam>
	/// <typeparam name="D">The type of the domain container, derived from <see cref="IUsersDomainContainer{U}"/>.</typeparam>
	public class BrowserSessionUserStore<U, D> : BrowserSessionUserStore<U, U, D>
		where U : User
		where D : IUsersDomainContainer<U>
	{
		/// <summary>
		/// Create.
		/// </summary>
		/// <param name="configurationSectionName">
		/// The name of a unity configuration section, where
		/// a <see cref="IUsersDomainContainer{U}"/> is defined
		/// and optionally any listeners implementing <see cref="IUserListener{U, U, D}"/>.
		/// </param>
		/// <param name="httpContextAccessor">An accessor to the <see cref="HttpContext"/> of the current request.</param>
		public BrowserSessionUserStore(string configurationSectionName, IHttpContextAccessor httpContextAccessor)
			: base(configurationSectionName, httpContextAccessor)
		{
		}
	}
}
