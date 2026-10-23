using LogonWatch.Model;

namespace LogonWatch.Detection;

/**
 * <summary>
 * WHAT:   Password spraying: one source trying many different accounts.
 * WHY:    Attackers try one common password ("Winter2026!") on every
 *         account, a few tries each, to stay under lockout limits. Per
 *         account it looks like a typo; only counting accounts per source
 *         reveals it.
 * </summary>
 */
public sealed class PasswordSprayRule : IDetectionRule
{
	/**
	 * <summary>
	 * WHAT:   The rule's name in alerts: "password-spray".
	 * WHY:    Identifies the rule in reports and JSON.
	 * PRE:    none
	 * RETURN: "password-spray"
	 * </summary>
	 */
	public string Name => "password-spray";

	/**
	 * <summary>
	 * WHAT:   Finds bursts where one source fails against at least
	 *         SprayAccountThreshold different accounts within SprayWindow.
	 * WHY:    Distinct accounts, not attempts, are counted, so one user
	 *         mistyping 20 times never triggers it.
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
		// 1. one group of failures per source address
		foreach (IGrouping<string, LogonEvent> group in events.Where(e => e.IsFailure)
			.GroupBy(e => e.Source, StringComparer.OrdinalIgnoreCase))
		{
			List<LogonEvent> failures = group.ToList();

			// 2. slide a window over them, counting distinct account names (e => e.User)
			foreach (List<LogonEvent> burst in Bursts.Find(failures, e => e.Time, settings.SprayWindow,
				settings.SprayAccountThreshold, e => e.User))
			{
				// 3. spraying is deliberate, so it is High unless typed at the machine itself
				List<string> accounts = RuleText.Accounts(burst);
				Severity severity = burst[0].IsLocal ? Severity.Low : Severity.High;

				yield return new Alert(Name, severity, group.Key, accounts, burst.Count, burst[0].Time, burst[^1].Time,
					$"{RuleText.Source(group.Key)} tried {accounts.Count} different accounts ({burst.Count} attempts) in "
					+ $"{RuleText.Duration(burst[^1].Time - burst[0].Time)}: {RuleText.Join(accounts)}");
			}
		}
	}
}
