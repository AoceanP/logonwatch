using LogonWatch.Model;

namespace LogonWatch.Detection;

/**
 * <summary>
 * WHAT:   Slow password spraying: one source trying many different accounts
 *         over a day, but never fast enough for the password-spray rule.
 * WHY:    A sprayer that tries one account every hour or two never has 5
 *         accounts inside 10 minutes, but after a day it has tried a dozen.
 *         No honest address fails against that many different accounts.
 * </summary>
 */
public sealed class SlowSprayRule : IDetectionRule
{
	/**
	 * <summary>
	 * WHAT:   The rule's name in alerts: "slow-spray".
	 * WHY:    Identifies the rule in reports and JSON.
	 * PRE:    none
	 * RETURN: "slow-spray"
	 * </summary>
	 */
	public string Name => "slow-spray";

	/**
	 * <summary>
	 * WHAT:   The ATT&amp;CK techniques: PasswordSpraying.
	 * WHY:    A few passwords against many accounts, only spread out in time.
	 * PRE:    none
	 * RETURN: the techniques
	 * </summary>
	 */
	public IReadOnlyList<Technique> Techniques { get; } = [Attack.PasswordSpraying];

	/**
	 * <summary>
	 * WHAT:   Finds stretches where one source fails against at least
	 *         SlowSprayAccountThreshold different accounts within SlowWindow,
	 *         counting only failures the password-spray rule did not report.
	 * WHY:    A fast spray is already reported; this rule is for the ones that
	 *         slowed down to hide, including a sprayer that slows down after a
	 *         fast start. High unless typed at the machine itself.
	 * PRE:    events are sorted by time
	 * POST:   events are not changed
	 * RETURN: one alert per slow stretch
	 * </summary>
	 * <param name="events">the logon events</param>
	 * <param name="settings">the thresholds and windows</param>
	 * <returns>the alerts</returns>
	 */
	public IEnumerable<Alert> Evaluate(IReadOnlyList<LogonEvent> events, DetectionSettings settings)
	{
		// 1. the failures the fast spray rule already reported, compared by reference
		HashSet<LogonEvent> reported = new(ReferenceEqualityComparer.Instance);
		reported.UnionWith(PasswordSprayRule.FindBursts(events, settings).SelectMany(b => b.Burst));

		// 2. one group of the remaining failures per source address
		foreach (IGrouping<string, LogonEvent> group in events.Where(e => e.IsFailure && !reported.Contains(e))
			.GroupBy(e => e.Source, StringComparer.OrdinalIgnoreCase))
		{
			// 3. a day-wide window counting distinct accounts, like the fast spray rule
			foreach (List<LogonEvent> stretch in Bursts.Find(group.ToList(), e => e.Time, settings.SlowWindow,
				settings.SlowSprayAccountThreshold, e => e.User))
			{
				List<string> accounts = RuleText.Accounts(stretch);
				Severity severity = stretch[0].IsLocal ? Severity.Low : Severity.High;

				yield return new Alert(Name, severity, group.Key, accounts, stretch.Count, stretch[0].Time,
					stretch[^1].Time,
					$"{RuleText.Source(group.Key)} tried {accounts.Count} different accounts ({stretch.Count} attempts) "
					+ $"over {RuleText.Duration(stretch[^1].Time - stretch[0].Time)}, too slow for the "
					+ $"password-spray rule: {RuleText.Join(accounts)}");
			}
		}
	}
}
