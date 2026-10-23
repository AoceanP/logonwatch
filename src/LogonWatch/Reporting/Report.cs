using LogonWatch.Model;

namespace LogonWatch.Reporting;

/**
 * <summary>
 * WHAT:   Everything one run found: what was read, and the alerts.
 * WHY:    The text and JSON writers print the same data, so it is built once.
 * </summary>
 * <param name="Input">where the events came from</param>
 * <param name="Events">how many logon events were analysed</param>
 * <param name="Failures">how many of them were failures</param>
 * <param name="Successes">how many of them were successes</param>
 * <param name="TopSources">the sources with the most failures, most first</param>
 * <param name="Alerts">the alerts, most severe first</param>
 */
public sealed record Report(
	string Input,
	int Events,
	int Failures,
	int Successes,
	IReadOnlyList<SourceCount> TopSources,
	IReadOnlyList<Alert> Alerts)
{
	/** <summary>WHAT: how many sources the "top sources" list shows.</summary> */
	public const int TopSourceCount = 5;

	/**
	 * <summary>
	 * WHAT:   Builds a report from the analysed events and the alerts.
	 * RETURN: the report
	 * </summary>
	 * <param name="input">where the events came from</param>
	 * <param name="events">the events that were analysed</param>
	 * <param name="alerts">the alerts the detector found</param>
	 * <returns>the report</returns>
	 */
	public static Report Build(string input, IReadOnlyList<LogonEvent> events, IReadOnlyList<Alert> alerts)
	{
		List<SourceCount> top = events.Where(e => e.IsFailure)
			.GroupBy(e => e.Source, StringComparer.OrdinalIgnoreCase)
			.Select(group => new SourceCount(group.Key, group.Count()))
			.OrderByDescending(item => item.Failures)
			.ThenBy(item => item.Source, StringComparer.Ordinal)
			.Take(TopSourceCount)
			.ToList();
		int failures = events.Count(e => e.IsFailure);
		return new Report(input, events.Count, failures, events.Count - failures, top, alerts);
	}
}

/**
 * <summary>
 * WHAT:   One row of the "top sources" list.
 * </summary>
 * <param name="Source">the source address, or "-" for local</param>
 * <param name="Failures">failed logons from it</param>
 */
public sealed record SourceCount(string Source, int Failures);
