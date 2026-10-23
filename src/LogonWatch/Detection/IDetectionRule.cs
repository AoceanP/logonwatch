using LogonWatch.Model;

namespace LogonWatch.Detection;

/**
 * <summary>
 * WHAT:   One way of spotting an attack in a list of logon events.
 * WHY:    Each attack pattern is its own class, so a new rule can be added
 *         and tested without touching the others (the open/closed principle).
 * </summary>
 */
public interface IDetectionRule
{
	/**
	 * <summary>
	 * WHAT:   The rule's short name, e.g. "brute-force".
	 * WHY:    Shown in every alert and used by scripts reading the JSON report.
	 * PRE:    none
	 * RETURN: a lowercase, hyphenated name that never changes
	 * </summary>
	 */
	string Name { get; }

	/**
	 * <summary>
	 * WHAT:   Looks for the rule's pattern.
	 * WHY:    The detector calls every rule the same way.
	 * PRE:    events are sorted by time, oldest first, with service accounts
	 *         removed (Detector.Prepare does both)
	 * POST:   events and settings are not changed
	 * RETURN: one alert per attack found; empty when there is none
	 * </summary>
	 * <param name="events">the logon events to check</param>
	 * <param name="settings">the thresholds and windows</param>
	 * <returns>the alerts</returns>
	 */
	IEnumerable<Alert> Evaluate(IReadOnlyList<LogonEvent> events, DetectionSettings settings);
}
