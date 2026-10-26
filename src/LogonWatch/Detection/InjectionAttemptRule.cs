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
	/**
	 * <summary>
	 * WHAT:   How long a payload may be in the alert text before it is cut.
	 * WHY:    One enormous user name must not flood the report.
	 * </summary>
	 */
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
		// a quote that closes the SQL string, then OR/AND and a comparison: admin' OR '1'='1
		("SQL injection", Create(@"['""]\s*(or|and)\s+\S+\s*=")),
		// a quote followed by a comment or a new statement: admin'-- or x'; DROP TABLE
		("SQL injection", Create(@"['""]\s*(--|#|/\*|;)")),
		// pulling data from another table: ' UNION SELECT password FROM users
		("SQL injection", Create(@"\bunion\b.*\bselect\b")),
		// SQL Server and MySQL tricks: running commands, reading the schema, timing attacks
		("SQL injection", Create(@"\b(xp_cmdshell|information_schema|waitfor\s+delay)\b|\b(sleep|benchmark)\s*\(")),
		// a shell separator followed by a common command: ; whoami, && powershell, | nc
		("command injection", Create(@"(;|&&|\|\|?)\s*(whoami|id|ls|dir|cat|type|ping|nslookup|curl|wget|powershell|cmd|bash|sh|nc|net)\b")),
		// shell command substitution: $(curl ...) or `id`
		("command injection", Create(@"\$\([^)]*\)|`[^`]*`")),
		// Log4Shell: ${jndi:ldap://...}, including disguised forms such as ${${lower:j}ndi:...}
		("Log4Shell (JNDI lookup)", Create(@"\$\{[^}]*(jndi|ldap|rmi|env:|sys:|lower:|upper:)")),
		// HTML or JavaScript meant for a web page that later shows the name
		("script injection", Create(@"<\s*/?\s*(script|img|svg|iframe|body)\b|javascript:|\bon(error|load)\s*=")),
		// climbing out of a folder: ..\..\windows or ../../etc
		("path traversal", Create(@"\.\.[/\\]")),
		// C printf placeholders that read or write memory: %s%s%n
		("format string", Create(@"(%[0-9]*[snx]){2,}")),
		// line breaks, tabs, escape codes: used to forge or hide lines in logs
		("control characters", Create(@"[\x00-\x1F\x7F]")),
	];

	/**
	 * <summary>
	 * WHAT:   The rule's name in alerts: "injection-attempt".
	 * WHY:    Identifies the rule in reports and JSON.
	 * PRE:    none
	 * RETURN: "injection-attempt"
	 * </summary>
	 */
	public string Name => "injection-attempt";

	/**
	 * <summary>
	 * WHAT:   The ATT&amp;CK techniques: ExploitPublicFacing.
	 * WHY:    Payloads aimed at whatever reads the user name, not password guesses.
	 * PRE:    none
	 * RETURN: the techniques
	 * </summary>
	 */
	public IReadOnlyList<Technique> Techniques { get; } = [Attack.ExploitPublicFacing];

	/**
	 * <summary>
	 * WHAT:   Finds every logon whose user name matches a payload pattern,
	 *         and reports them grouped by source.
	 * WHY:    One alert per source lists every technique it tried. Severity
	 *         is High, or Critical if such a logon succeeded: Windows should
	 *         never accept a user name like that.
	 * PRE:    events are sorted by time
	 * POST:   events are not changed
	 * RETURN: one alert per source that sent payloads
	 * </summary>
	 * <param name="events">the logon events</param>
	 * <param name="settings">not used: one payload is always suspicious</param>
	 * <returns>the alerts</returns>
	 */
	public IEnumerable<Alert> Evaluate(IReadOnlyList<LogonEvent> events, DetectionSettings settings)
	{
		// 1. check every logon's user name, keeping only those that match at least one category
		var matches = events
			.Select(logon => (Logon: logon, Categories: Categorize(logon.User)))
			.Where(match => match.Categories.Count > 0)
			// 2. one group per attacking source
			.GroupBy(match => match.Logon.Source, StringComparer.OrdinalIgnoreCase);

		foreach (var group in matches)
		{
			// 3. summarise the group: which techniques, which payloads (made safe), and whether any got in
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
	 * WHY:    Public so it can be tested on its own, and reused by the
	 *         Redactor to keep payloads visible.
	 * PRE:    user is not null
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
	 * PRE:    payload is not null
	 * RETURN: the printable payload, at most ShownLength characters plus "..."
	 * </summary>
	 * <param name="payload">the raw user name</param>
	 * <returns>the safe text</returns>
	 */
	internal static string Shown(string payload)
	{
		StringBuilder text = new();
		foreach (char c in payload)
		{
			// replace each invisible character with a visible escape; keep everything else as it is
			text.Append(c switch
			{
				'\n' => "\\n",
				'\r' => "\\r",
				'\t' => "\\t",
				_ when char.IsControl(c) => $"\\x{(int)c:x2}",
				_ => c.ToString(),
			});

			// stop as soon as the text is long enough, so a huge payload is never fully copied
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
	 * WHY:    Shows exactly where a payload starts and ends, including spaces.
	 * PRE:    payload is already made safe by Shown
	 * RETURN: the quoted text
	 * </summary>
	 * <param name="payload">the safe payload text</param>
	 * <returns>the payload in quotes</returns>
	 */
	private static string Quote(string payload) => $"\"{payload}\"";

	/**
	 * <summary>
	 * WHAT:   Builds one case-insensitive, non-backtracking pattern.
	 * WHY:    Every pattern gets the same safe options in one place.
	 * PRE:    pattern is a valid regex without lookarounds or backreferences
	 *         (NonBacktracking does not support them)
	 * RETURN: the compiled regex
	 * </summary>
	 * <param name="pattern">the regular expression</param>
	 * <returns>the regex</returns>
	 */
	private static Regex Create(string pattern) =>
		new(pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
}
