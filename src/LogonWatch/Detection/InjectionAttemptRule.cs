using System.Text;
using System.Text.RegularExpressions;
using LogonWatch.Model;

namespace LogonWatch.Detection;

/**
 * <summary>
 * WHAT:   Logons whose user name is an attack payload instead of a name,
 *         e.g. "admin' OR '1'='1" or "${jndi:ldap://...}".
 * WHY:    Automated scanners spray SQL injection, command injection and
 *         Log4Shell strings into every login prompt they find, hoping some
 *         system behind it (a database, a web app, a logging library) runs
 *         them. A single one is worth an alert: no person types these by
 *         accident, and it shows exactly what the attacker is trying.
 * </summary>
 */
public sealed class InjectionAttemptRule : IDetectionRule
{
	/** <summary>WHAT: how long a payload may be in the alert text before it is cut.</summary> */
	private const int ShownLength = 40;

	/**
	 * <summary>
	 * WHAT:   The payload patterns, by category.
	 * WHY:    User names come from attackers, so a normal regex could be made
	 *         to run for minutes on a crafted name (ReDoS, catastrophic
	 *         backtracking). NonBacktracking guarantees time linear in the
	 *         input. The SQL patterns need a quote followed by OR/AND or a
	 *         comment, so real names such as O'Brien are not flagged.
	 * </summary>
	 */
	private static readonly (string Category, Regex Pattern)[] Patterns =
	[
		("SQL injection", Create(@"['""]\s*(or|and)\s+\S+\s*=")),
		("SQL injection", Create(@"['""]\s*(--|#|/\*|;)")),
		("SQL injection", Create(@"\bunion\b.*\bselect\b")),
		("SQL injection", Create(@"\b(xp_cmdshell|information_schema|waitfor\s+delay)\b|\b(sleep|benchmark)\s*\(")),
		("command injection", Create(@"(;|&&|\|\|?)\s*(whoami|id|ls|dir|cat|type|ping|nslookup|curl|wget|powershell|cmd|bash|sh|nc|net)\b")),
		("command injection", Create(@"\$\([^)]*\)|`[^`]*`")),
		("Log4Shell (JNDI lookup)", Create(@"\$\{[^}]*(jndi|ldap|rmi|env:|sys:|lower:|upper:)")),
		("script injection", Create(@"<\s*/?\s*(script|img|svg|iframe|body)\b|javascript:|\bon(error|load)\s*=")),
		("path traversal", Create(@"\.\.[/\\]")),
		("format string", Create(@"(%[0-9]*[snx]){2,}")),
		("control characters", Create(@"[\x00-\x1F\x7F]")),
	];

	/** <inheritdoc /> */
	public string Name => "injection-attempt";

	/**
	 * <summary>
	 * WHAT:   Finds every logon whose user name matches a payload pattern,
	 *         and reports them grouped by source.
	 * WHY:    One alert per source lists every technique it tried. Severity
	 *         is High, or Critical if such a logon succeeded: Windows should
	 *         never accept a user name like that.
	 * PRE:    events are sorted by time
	 * RETURN: one alert per source that sent payloads
	 * </summary>
	 * <param name="events">the logon events</param>
	 * <param name="settings">not used: one payload is always suspicious</param>
	 * <returns>the alerts</returns>
	 */
	public IEnumerable<Alert> Evaluate(IReadOnlyList<LogonEvent> events, DetectionSettings settings)
	{
		var matches = events
			.Select(logon => (Logon: logon, Categories: Categorize(logon.User)))
			.Where(match => match.Categories.Count > 0)
			.GroupBy(match => match.Logon.Source, StringComparer.OrdinalIgnoreCase);

		foreach (var group in matches)
		{
			var attempts = group.ToList();
			List<string> categories = attempts.SelectMany(match => match.Categories).Distinct().ToList();
			List<string> payloads = attempts.Select(match => Shown(match.Logon.User)).Distinct().ToList();
			bool succeeded = attempts.Any(match => !match.Logon.IsFailure);

			yield return new Alert(Name, succeeded ? Severity.Critical : Severity.High, group.Key, payloads,
				attempts.Count, attempts[0].Logon.Time, attempts[^1].Logon.Time,
				$"{RuleText.Source(group.Key)} sent {attempts.Count} user name{(attempts.Count == 1 ? "" : "s")} that are "
				+ $"attack payloads ({string.Join(", ", categories)}): {RuleText.Join(payloads.Select(Quote).ToList())}"
				+ (succeeded ? "; one was accepted, investigate this system now" : ""));
		}
	}

	/**
	 * <summary>
	 * WHAT:   Lists the payload categories a user name matches.
	 * WHY:    Public so it can be tested on its own, and reused by other
	 *         tools that need to check a name.
	 * RETURN: the categories, without duplicates; empty for a normal name
	 * </summary>
	 * <param name="user">the user name</param>
	 * <returns>the matching categories</returns>
	 */
	public static List<string> Categorize(string user) =>
		Patterns.Where(entry => entry.Pattern.IsMatch(user)).Select(entry => entry.Category).Distinct().ToList();

	/**
	 * <summary>
	 * WHAT:   Makes a payload safe to print: control characters become
	 *         escapes like \n, and long payloads are cut.
	 * WHY:    The payload is attacker-controlled; printed raw, a line break
	 *         or terminal escape code in it could forge or hide report lines.
	 * RETURN: the printable payload
	 * </summary>
	 * <param name="payload">the raw user name</param>
	 * <returns>the safe text</returns>
	 */
	internal static string Shown(string payload)
	{
		StringBuilder text = new();
		foreach (char c in payload)
		{
			text.Append(c switch
			{
				'\n' => "\\n",
				'\r' => "\\r",
				'\t' => "\\t",
				_ when char.IsControl(c) => $"\\x{(int)c:x2}",
				_ => c.ToString(),
			});
			if (text.Length >= ShownLength)
			{
				return text.ToString(0, ShownLength) + "...";
			}
		}
		return text.ToString();
	}

	/**
	 * <summary>
	 * WHAT:   Puts quotes around a payload for the alert sentence.
	 * RETURN: the quoted text
	 * </summary>
	 * <param name="payload">the safe payload text</param>
	 * <returns>the payload in quotes</returns>
	 */
	private static string Quote(string payload) => $"\"{payload}\"";

	/**
	 * <summary>
	 * WHAT:   Builds one case-insensitive, non-backtracking pattern.
	 * RETURN: the compiled regex
	 * </summary>
	 * <param name="pattern">the regular expression</param>
	 * <returns>the regex</returns>
	 */
	private static Regex Create(string pattern) =>
		new(pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
}
