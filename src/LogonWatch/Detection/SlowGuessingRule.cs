using LogonWatch.Model;

namespace LogonWatch.Detection;

/**
 * <summary>
 * WHAT:   Slow password guessing: one account failing many times over a
 *         day, but never fast enough for the burst rules.
 * WHY:    Automated attackers are patient. Three guesses an hour, from
 *         addresses that keep changing, stays under every 5- and 10-minute
 *         threshold, yet adds up to 72 guesses a day. Counting per account
 *         over a long window catches it however the addresses change.
 * </summary>
 */
public sealed class SlowGuessingRule : IDetectionRule
{
	/**
	 * <summary>
	 * WHAT:   The rule's name in alerts: "slow-guessing".
	 * WHY:    Identifies the rule in reports and JSON.
	 * PRE:    none
	 * RETURN: "slow-guessing"
	 * </summary>
	 */
	public string Name => "slow-guessing";

	/**
	 * <summary>
	 * WHAT:   The ATT&amp;CK techniques: PasswordGuessing.
	 * WHY:    Many passwords tried against one account, only spread out in time.
	 * PRE:    none
	 * RETURN: the techniques
	 * </summary>
	 */
	public IReadOnlyList<Technique> Techniques { get; } = [Attack.PasswordGuessing];

	/**
	 * <summary>
	 * WHAT:   Finds stretches where one account fails at least SlowGuessThreshold
	 *         times within SlowWindow, from any sources, counting only failures
	 *         the brute-force and distributed-attack rules did not report.
	 * WHY:    A fast attack is already reported by those rules; counting it
	 *         again would report the same attack twice. Taking out only those
	 *         failures, instead of ignoring the whole day, still catches an
	 *         attacker who bursts once and then carries on slowly. Severity is
	 *         High when the failures came from more than one address (rotating
	 *         addresses is a deliberate way to hide), Medium from one, Low if
	 *         typed locally.
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
		// 1. the failures the fast rules already reported; compared by reference, since two
		//    identical events (same second, user and address) are still two attempts
		HashSet<LogonEvent> reported = new(ReferenceEqualityComparer.Instance);
		reported.UnionWith(BruteForceRule.FindBursts(events, settings).SelectMany(b => b.Burst));
		reported.UnionWith(DistributedAttackRule.FindBursts(events, settings).SelectMany(b => b.Burst));

		// 2. one group of the remaining failures per account, whatever address they came from
		foreach (IGrouping<string, LogonEvent> group in events.Where(e => e.IsFailure && !reported.Contains(e))
			.GroupBy(e => e.User, StringComparer.OrdinalIgnoreCase))
		{
			// 3. the same sliding window as the fast rules, only a day wide
			foreach (List<LogonEvent> stretch in Bursts.Find(group.ToList(), e => e.Time, settings.SlowWindow,
				settings.SlowGuessThreshold))
			{
				// 4. rate it: typed at the machine, one patient address, or rotating addresses
				int sources = stretch.Select(e => e.Source).Distinct(StringComparer.OrdinalIgnoreCase).Count();
				Severity severity = stretch.All(e => e.IsLocal) ? Severity.Low
					: sources > 1 ? Severity.High
					: Severity.Medium;
				string from = sources > 1 ? $"{sources} sources" : stretch[0].Source;

				yield return new Alert(Name, severity, from, [group.Key], stretch.Count, stretch[0].Time,
					stretch[^1].Time,
					$"{stretch.Count} failed logons against {group.Key} over "
					+ $"{RuleText.Duration(stretch[^1].Time - stretch[0].Time)} from "
					+ (sources > 1 ? $"{sources} different addresses" : RuleText.Source(stretch[0].Source))
					+ ", too slow for the brute-force rule");
			}
		}
	}
}
