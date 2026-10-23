using LogonWatch.Model;

namespace LogonWatch.Detection;

/**
 * <summary>
 * WHAT:   Runs every detection rule over a set of logon events.
 * WHY:    One entry point: clean the events once, run all rules, and sort
 *         the alerts so the most urgent come first.
 * </summary>
 */
public static class Detector
{
	/**
	 * <summary>
	 * WHAT:   Built-in Windows accounts that log on constantly.
	 * WHY:    SYSTEM and the service accounts produce thousands of normal
	 *         logons a day; they are noise, not people.
	 * </summary>
	 */
	private static readonly HashSet<string> ServiceAccounts = new(StringComparer.OrdinalIgnoreCase)
	{
		"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "DWM-1", "DWM-2", "UMFD-0", "UMFD-1", "UMFD-2",
	};

	/**
	 * <summary>
	 * WHAT:   The rules, most important first.
	 * </summary>
	 */
	public static IReadOnlyList<IDetectionRule> Rules { get; } =
	[
		new SuccessAfterFailuresRule(),
		new InjectionAttemptRule(),
		new BruteForceRule(),
		new PasswordSprayRule(),
		new DistributedAttackRule(),
	];

	/**
	 * <summary>
	 * WHAT:   Cleans the events, runs every rule, and sorts the alerts.
	 * WHY:    Rules expect sorted events; logs and files are not always in
	 *         order (e.g. several exported logs combined).
	 * THROWS: ArgumentException if the settings are invalid
	 * RETURN: the alerts, most severe first, then oldest first
	 * </summary>
	 * <param name="events">the logon events, in any order</param>
	 * <param name="settings">the thresholds and windows</param>
	 * <returns>the alerts</returns>
	 * <exception cref="ArgumentException">a setting is invalid</exception>
	 */
	public static List<Alert> Run(IEnumerable<LogonEvent> events, DetectionSettings settings)
	{
		settings.Validate();
		List<LogonEvent> prepared = Prepare(events);
		return Rules.SelectMany(rule => rule.Evaluate(prepared, settings))
			.OrderByDescending(alert => alert.Severity)
			.ThenBy(alert => alert.First)
			.ToList();
	}

	/**
	 * <summary>
	 * WHAT:   Removes service and computer accounts, and sorts by time.
	 * WHY:    Computer accounts end in "$" and log on all day across a
	 *         domain; logon types 0 (system) and 5 (service) are Windows
	 *         itself. The sort is stable, so equal times keep their order.
	 * RETURN: the cleaned, sorted events
	 * </summary>
	 * <param name="events">the raw events</param>
	 * <returns>the prepared events</returns>
	 */
	public static List<LogonEvent> Prepare(IEnumerable<LogonEvent> events) =>
		events.Where(e => !e.User.EndsWith('$') && !ServiceAccounts.Contains(e.User) && e.LogonType is not (0 or 5))
			.OrderBy(e => e.Time)
			.ToList();
}
