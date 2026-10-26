using LogonWatch.Model;

namespace LogonWatch.Detection;

/**
 * <summary>
 * WHAT:   Distributed attack: many different sources attacking one account.
 * WHY:    Botnets spread guesses across hundreds of IP addresses so no
 *         single address looks like brute force; grouping by account
 *         instead of by source catches them.
 * </summary>
 */
public sealed class DistributedAttackRule : IDetectionRule
{
	/**
	 * <summary>
	 * WHAT:   The rule's name in alerts: "distributed-attack".
	 * WHY:    Identifies the rule in reports and JSON.
	 * PRE:    none
	 * RETURN: "distributed-attack"
	 * </summary>
	 */
	public string Name => "distributed-attack";

	/**
	 * <summary>
	 * WHAT:   The ATT&amp;CK techniques: PasswordGuessing.
	 * WHY:    One account's password guessed from many addresses.
	 * PRE:    none
	 * RETURN: the techniques
	 * </summary>
	 */
	public IReadOnlyList<Technique> Techniques { get; } = [Attack.PasswordGuessing];

	/**
	 * <summary>
	 * WHAT:   Finds bursts where one account fails from at least
	 *         DistributedSourceThreshold different remote sources within
	 *         DistributedWindow.
	 * WHY:    Local failures are left out: they all share the source "-",
	 *         so they could never look distributed anyway.
	 * PRE:    events are sorted by time
	 * POST:   events are not changed
	 * RETURN: one alert per burst, with Source set to "N sources"
	 * </summary>
	 * <param name="events">the logon events</param>
	 * <param name="settings">the thresholds and windows</param>
	 * <returns>the alerts</returns>
	 */
	public IEnumerable<Alert> Evaluate(IReadOnlyList<LogonEvent> events, DetectionSettings settings)
	{
		// 1. the mirror image of brute force: one group per account, not per source
		foreach (IGrouping<string, LogonEvent> group in events.Where(e => e.IsFailure && !e.IsLocal)
			.GroupBy(e => e.User, StringComparer.OrdinalIgnoreCase))
		{
			List<LogonEvent> failures = group.ToList();

			// 2. slide a window over the account's failures, counting distinct sources (e => e.Source)
			foreach (List<LogonEvent> burst in Bursts.Find(failures, e => e.Time, settings.DistributedWindow,
				settings.DistributedSourceThreshold, e => e.Source))
			{
				int sources = CountSources(burst);
				yield return new Alert(Name, Severity.High, $"{sources} sources", [group.Key], burst.Count,
					burst[0].Time, burst[^1].Time,
					$"{group.Key} was attacked from {sources} different addresses ({burst.Count} attempts) in "
					+ RuleText.Duration(burst[^1].Time - burst[0].Time));
			}
		}
	}

	/**
	 * <summary>
	 * WHAT:   Counts the different source addresses in some events.
	 * WHY:    The alert says how many addresses took part in the whole burst.
	 * PRE:    events is not null
	 * RETURN: the number of distinct sources, ignoring case
	 * </summary>
	 * <param name="events">the events</param>
	 * <returns>the count</returns>
	 */
	private static int CountSources(IEnumerable<LogonEvent> events) =>
		events.Select(e => e.Source).Distinct(StringComparer.OrdinalIgnoreCase).Count();
}
