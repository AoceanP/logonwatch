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
	/** <summary>WHAT: real account name to placeholder.</summary> */
	private readonly Dictionary<string, string> users = new(StringComparer.OrdinalIgnoreCase);

	/** <summary>WHAT: real domain to placeholder.</summary> */
	private readonly Dictionary<string, string> domains = new(StringComparer.OrdinalIgnoreCase);

	/** <summary>WHAT: real address to placeholder.</summary> */
	private readonly Dictionary<string, string> addresses = new(StringComparer.OrdinalIgnoreCase);

	/**
	 * <summary>
	 * WHAT:   Redacts one event.
	 * WHY:    Done before detection, so alert text never contains a real name.
	 *         "-" (no value) stays "-", so local logons still read as local.
	 *         User names that are attack payloads ("admin' OR '1'='1") are
	 *         kept: they are not personal data, and hiding them would stop
	 *         the injection rule from seeing the attack.
	 * RETURN: a copy of the event with placeholders
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
	 * RETURN: e.g. "user-3", or "-" unchanged
	 * </summary>
	 * <param name="map">the map for this kind of value</param>
	 * <param name="value">the real value</param>
	 * <param name="prefix">"user", "domain" or "ip"</param>
	 * <returns>the placeholder</returns>
	 */
	private static string Placeholder(Dictionary<string, string> map, string value, string prefix)
	{
		if (value is "-" or "")
		{
			return value;
		}
		if (!map.TryGetValue(value, out string? placeholder))
		{
			placeholder = $"{prefix}-{map.Count + 1}";
			map[value] = placeholder;
		}
		return placeholder;
	}
}
