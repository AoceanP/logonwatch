using LogonWatch.Model;

namespace LogonWatch.Detection;

/**
 * <summary>
 * WHAT:   Small helpers the rules share to build alert text.
 * WHY:    Keeps every alert sentence in the same style, and keeps the
 *         rules focused on detection instead of formatting.
 * </summary>
 */
internal static class RuleText
{
	/**
	 * <summary>
	 * WHAT:   The account names in a list of events, once each, in first-seen order.
	 * WHY:    Windows account names are not case-sensitive: "Admin" and
	 *         "admin" are the same account.
	 * PRE:    events is not null
	 * RETURN: the distinct names
	 * </summary>
	 * <param name="events">the events</param>
	 * <returns>the account names</returns>
	 */
	public static List<string> Accounts(IEnumerable<LogonEvent> events) =>
		events.Select(e => e.User).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

	/**
	 * <summary>
	 * WHAT:   Lists up to three names, then "(+N more)".
	 * WHY:    A spray across 500 accounts must still fit on one line.
	 * PRE:    names is not null
	 * RETURN: e.g. "admin, backup, sql (+5 more)"
	 * </summary>
	 * <param name="names">the names to list</param>
	 * <returns>the short list</returns>
	 */
	public static string Join(IReadOnlyList<string> names)
	{
		const int shown = 3;
		string text = string.Join(", ", names.Take(shown));
		return names.Count > shown ? $"{text} (+{names.Count - shown} more)" : text;
	}

	/**
	 * <summary>
	 * WHAT:   Formats a duration the way people say it: "45 s", "3 min", "2 h".
	 * WHY:    "00:02:58" is harder to read in a sentence than "3 min".
	 * PRE:    span is zero or positive
	 * RETURN: the rounded duration, never "0 s"
	 * </summary>
	 * <param name="span">the duration</param>
	 * <returns>the readable text</returns>
	 */
	public static string Duration(TimeSpan span)
	{
		// under 90 seconds: seconds; under 90 minutes: minutes; otherwise hours with one decimal
		if (span.TotalSeconds < 90)
		{
			return $"{Math.Max(1, (int)Math.Round(span.TotalSeconds))} s";
		}
		if (span.TotalMinutes < 90)
		{
			return $"{(int)Math.Round(span.TotalMinutes)} min";
		}
		return $"{span.TotalHours:0.#} h";
	}

	/**
	 * <summary>
	 * WHAT:   Names a source address for a sentence.
	 * WHY:    "-" means nothing to a reader; "this machine" does.
	 * PRE:    source is not null
	 * RETURN: "this machine" for "-", otherwise the address
	 * </summary>
	 * <param name="source">the source address</param>
	 * <returns>the readable source</returns>
	 */
	public static string Source(string source) => source == "-" ? "this machine" : source;
}
