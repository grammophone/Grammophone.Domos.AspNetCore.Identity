using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Grammophone.Domos.AspNet.Identity
{
	/// <summary>
	/// Signature for handlers of events including a sender
	/// and an argument.
	/// </summary>
	/// <typeparam name="S">The type of the sender.</typeparam>
	/// <typeparam name="A">The type of the event argument.</typeparam>
	/// <param name="sender">The sender of the event.</param>
	/// <param name="eventArgument">The event argument.</param>
	public delegate void NotificationDelegate<S, A>(S sender, A eventArgument);
}
