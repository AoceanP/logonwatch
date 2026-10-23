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
	/** <inheritdoc /> */
	public string Name => "brute-force";

	/**
	 * <summary>
	 * WHAT:   Finds bursts of at least BruteForceThreshold failures from one
	 *         source within BruteForceWindow.
	 * WHY:    Severity grows with size: local bursts are Low (a person
	 *         mistyping), remote ones Medium, and five times the threshold High.
	 * PRE:    events are sorted by time
	 * RETURN: one alert per burst
	 * </summary>
	 * <param name="events">the logon events</param>
	 * <param name="settings">the thresholds and windows</param>
	 * <returns>the alerts</returns>
	 */
	public IEnumerable<Alert> Evaluate(IReadOnlyList<LogonEvent> events, DetectionSettings settings)
	{
		foreach (IGrouping<string, LogonEvent> group in events.Where(e => e.IsFailure)
			.GroupBy(e => e.Source, StringComparer.OrdinalIgnoreCase))
		{
			List<LogonEvent> failures = group.ToList();
			foreach (List<LogonEvent> burst in Bursts.Find(failures, e => e.Time, settings.BruteForceWindow,
				settings.BruteForceThreshold))
			{
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
