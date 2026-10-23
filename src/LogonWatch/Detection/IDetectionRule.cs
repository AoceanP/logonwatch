using LogonWatch.Model;

namespace LogonWatch.Detection;

/**
 * <summary>
 * WHAT:   One way of spotting an attack in a list of logon events.
 * WHY:    Each attack pattern is its own class, so a new rule can be added
 *         and tested without touching the others.
 * </summary>
 */
public interface IDetectionRule
{
	/** <summary>WHAT: the rule's short name, shown in every alert, e.g. "brute-force".</summary> */
	string Name { get; }

	/**
	 * <summary>
	 * WHAT:   Looks for the rule's pattern.
	 * PRE:    events are sorted by time, oldest first, with service accounts removed
	 * RETURN: one alert per attack found
	 * </summary>
	 * <param name="events">the logon events to check</param>
	 * <param name="settings">the thresholds and windows</param>
	 * <returns>the alerts</returns>
	 */
	IEnumerable<Alert> Evaluate(IReadOnlyList<LogonEvent> events, DetectionSettings settings);
}
