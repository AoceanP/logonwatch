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
	/** <inheritdoc /> */
	public string Name => "distributed-attack";

	/**
	 * <summary>
	 * WHAT:   Finds bursts where one account fails from at least
	 *         DistributedSourceThreshold different remote sources within
	 *         DistributedWindow.
	 * WHY:    Local failures are left out: they all share the source "-".
	 * PRE:    events are sorted by time
	 * RETURN: one alert per burst, with Source set to "N sources"
	 * </summary>
	 * <param name="events">the logon events</param>
	 * <param name="settings">the thresholds and windows</param>
	 * <returns>the alerts</returns>
	 */
	public IEnumerable<Alert> Evaluate(IReadOnlyList<LogonEvent> events, DetectionSettings settings)
	{
		foreach (IGrouping<string, LogonEvent> group in events.Where(e => e.IsFailure && !e.IsLocal)
			.GroupBy(e => e.User, StringComparer.OrdinalIgnoreCase))
		{
			List<LogonEvent> failures = group.ToList();
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
	 * RETURN: the number of distinct sources
	 * </summary>
	 * <param name="events">the events</param>
	 * <returns>the count</returns>
	 */
	private static int CountSources(IEnumerable<LogonEvent> events) =>
		events.Select(e => e.Source).Distinct(StringComparer.OrdinalIgnoreCase).Count();
}
