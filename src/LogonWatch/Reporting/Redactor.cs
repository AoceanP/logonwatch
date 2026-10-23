using LogonWatch.Detection;
using LogonWatch.Model;

namespace LogonWatch.Reporting;

/**
 * <summary>
 * WHAT:   Replaces account names, domains and IP addresses with stable
 *         placeholders: "user-1", "domain-1", "ip-1".
 * WHY:    Usernames and addresses are personal data. A redacted report can
 *         be shared (in a ticket, with a teacher, on GitHub) and still shows
 *         the attack, because the same name always gets the same placeholder.
 * </summary>
 */
public sealed class Redactor
{
	/**
	 * <summary>
	 * WHAT:   Real account name to placeholder.
	 * WHY:    Remembers earlier names so "alice" is always "user-1"; ignores
	 *         case because Windows account names do.
	 * </summary>
	 */
	private readonly Dictionary<string, string> users = new(StringComparer.OrdinalIgnoreCase);

	/**
	 * <summary>
	 * WHAT:   Real domain to placeholder.
	 * WHY:    Domain and computer names can identify an organisation.
	 * </summary>
	 */
	private readonly Dictionary<string, string> domains = new(StringComparer.OrdinalIgnoreCase);

	/**
	 * <summary>
	 * WHAT:   Real address to placeholder.
	 * WHY:    IP addresses can identify a home or office.
	 * </summary>
	 */
	private readonly Dictionary<string, string> addresses = new(StringComparer.OrdinalIgnoreCase);

	/**
	 * <summary>
	 * WHAT:   Redacts one event.
	 * WHY:    Done before detection, so alert text never contains a real name.
	 *         "-" (no value) stays "-", so local logons still read as local.
	 *         User names that are attack payloads ("admin' OR '1'='1") are
	 *         kept: they are not personal data, and hiding them would stop
	 *         the injection rule from seeing the attack.
	 * PRE:    logon is not null
	 * POST:   new real values are added to the placeholder maps
	 * RETURN: a copy of the event with placeholders; the original is unchanged
	 * </summary>
	 * <param name="logon">the original event</param>
	 * <returns>the redacted event</returns>
	 */
	public LogonEvent Redact(LogonEvent logon) => logon with
	{
		User = InjectionAttemptRule.Categorize(logon.User).Count > 0 ? logon.User : Placeholder(users, logon.User, "user"),
		Domain = Placeholder(domains, logon.Domain, "domain"),
		Source = logon.IsLocal ? logon.Source : Placeholder(addresses, logon.Source, "ip"),
	};

	/**
	 * <summary>
	 * WHAT:   Returns the placeholder for a value, creating it the first time.
	 * WHY:    Numbering in first-seen order keeps placeholders short and stable
	 *         within one report.
	 * PRE:    map is the map for this kind of value
	 * POST:   value is in map if it was not "-" or empty
	 * RETURN: e.g. "user-3", or "-" and "" unchanged
	 * </summary>
	 * <param name="map">the map for this kind of value</param>
	 * <param name="value">the real value</param>
	 * <param name="prefix">"user", "domain" or "ip"</param>
	 * <returns>the placeholder</returns>
	 */
	private static string Placeholder(Dictionary<string, string> map, string value, string prefix)
	{
		// "-" and "" mean "no value"; there is nothing to hide
		if (value is "-" or "")
		{
			return value;
		}

		// the first time a value is seen it gets the next number: user-1, user-2, ...
		if (!map.TryGetValue(value, out string? placeholder))
		{
			placeholder = $"{prefix}-{map.Count + 1}";
			map[value] = placeholder;
		}
		return placeholder;
	}
}
