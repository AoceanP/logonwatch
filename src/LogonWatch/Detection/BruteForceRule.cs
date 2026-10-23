using LogonWatch.Model;

namespace LogonWatch.Detection;

/**
 * <summary>
 * WHAT:   Brute force: many failed logons from one source in a short time.
 * WHY:    The most common attack on anything with a login, e.g. a bot
 *         guessing Remote Desktop passwords thousands of times.
 * </summary>
 */
public sealed class BruteForceRule : IDetectionRule
{
	/**
	 * <summary>
	 * WHAT:   The rule's name in alerts: "brute-force".
	 * WHY:    Identifies the rule in reports and JSON.
	 * PRE:    none
	 * RETURN: "brute-force"
	 * </summary>
	 */
	public string Name => "brute-force";

	/**
	 * <summary>
	 * WHAT:   Finds bursts of at least BruteForceThreshold failures from one
	 *         source within BruteForceWindow.
	 * WHY:    Severity grows with size: local bursts are Low (a person
	 *         mistyping), remote ones Medium, and five times the threshold High.
	 * PRE:    events are sorted by time
	 * POST:   events are not changed
	 * RETURN: one alert per burst
	 * </summary>
	 * <param name="events">the logon events</param>
	 * <param name="settings">the thresholds and windows</param>
	 * <returns>the alerts</returns>
	 */
	public IEnumerable<Alert> Evaluate(IReadOnlyList<LogonEvent> events, DetectionSettings settings)
	{
		// 1. one group of failures per source address ("203.0.113.7", or "-" for local)
		foreach (IGrouping<string, LogonEvent> group in events.Where(e => e.IsFailure)
			.GroupBy(e => e.Source, StringComparer.OrdinalIgnoreCase))
		{
			List<LogonEvent> failures = group.ToList();

			// 2. slide a window over that source's failures; count events, not distinct values
			foreach (List<LogonEvent> burst in Bursts.Find(failures, e => e.Time, settings.BruteForceWindow,
				settings.BruteForceThreshold))
			{
				// 3. rate the burst: typed locally, normal, or five times the threshold
				List<string> accounts = RuleText.Accounts(burst);
				Severity severity = burst[0].IsLocal ? Severity.Low
					: burst.Count >= settings.BruteForceThreshold * 5 ? Severity.High
					: Severity.Medium;

				yield return new Alert(Name, severity, group.Key, accounts, burst.Count, burst[0].Time, burst[^1].Time,
					$"{burst.Count} failed logons from {RuleText.Source(group.Key)} in "
					+ $"{RuleText.Duration(burst[^1].Time - burst[0].Time)} against {RuleText.Join(accounts)}");
			}
		}
	}
}
