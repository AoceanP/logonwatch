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
	 * WHAT:   The ATT&amp;CK techniques: PasswordSpraying.
	 * WHY:    A few passwords tried against many accounts.
	 * PRE:    none
	 * RETURN: the techniques
	 * </summary>
	 */
	public IReadOnlyList<Technique> Techniques { get; } = [Attack.PasswordSpraying];

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
		foreach ((string source, List<LogonEvent> burst) in FindBursts(events, settings))
		{
			// 3. spraying is deliberate, so it is High unless typed at the machine itself
			List<string> accounts = RuleText.Accounts(burst);
			Severity severity = burst[0].IsLocal ? Severity.Low : Severity.High;

			yield return new Alert(Name, severity, source, accounts, burst.Count, burst[0].Time, burst[^1].Time,
				$"{RuleText.Source(source)} tried {accounts.Count} different accounts ({burst.Count} attempts) in "
				+ $"{RuleText.Duration(burst[^1].Time - burst[0].Time)}: {RuleText.Join(accounts)}");
		}
	}

	/**
	 * <summary>
	 * WHAT:   The bursts this rule reports, each with the source it belongs to.
	 * WHY:    The slow rules take these events out before counting, so an
	 *         attack is never reported as both fast and slow, and "fast" has
	 *         one definition: this one.
	 * PRE:    events are sorted by time
	 * POST:   events are not changed
	 * RETURN: each burst's source and events
	 * </summary>
	 * <param name="events">the logon events</param>
	 * <param name="settings">the thresholds and windows</param>
	 * <returns>the bursts</returns>
	 */
	internal static IEnumerable<(string Key, List<LogonEvent> Burst)> FindBursts(IReadOnlyList<LogonEvent> events,
		DetectionSettings settings)
	{
		// 1. one group of failures per source address
		foreach (IGrouping<string, LogonEvent> group in events.Where(e => e.IsFailure)
			.GroupBy(e => e.Source, StringComparer.OrdinalIgnoreCase))
		{
			// 2. slide a window over them, counting distinct account names (e => e.User)
			foreach (List<LogonEvent> burst in Bursts.Find(group.ToList(), e => e.Time, settings.SprayWindow,
				settings.SprayAccountThreshold, e => e.User))
			{
				yield return (group.Key, burst);
			}
		}
	}
}
