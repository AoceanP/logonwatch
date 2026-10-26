namespace LogonWatch.Model;

/**
 * <summary>
 * WHAT:   How urgent an alert is, from Low to Critical.
 * WHY:    Lets the report put "someone probably got in" above "someone is
 *         knocking", the way a SOC triages alerts. The order of the values
 *         matters: sorting by Severity puts Critical last, so the report
 *         sorts descending.
 * </summary>
 */
public enum Severity
{
	/**
	 * <summary>
	 * WHAT:   Worth a look, probably harmless.
	 * WHY:    Used for bursts typed at the machine itself, e.g. someone who
	 *         forgot their password.
	 * </summary>
	 */
	Low,

	/**
	 * <summary>
	 * WHAT:   An attack pattern, but nothing suggests it worked.
	 * WHY:    A normal-sized brute force from the network.
	 * </summary>
	 */
	Medium,

	/**
	 * <summary>
	 * WHAT:   A large or targeted attack.
	 * WHY:    Big brute forces, password spraying, botnets and injection
	 *         payloads take planning or tooling, so they rank above Medium.
	 * </summary>
	 */
	High,

	/**
	 * <summary>
	 * WHAT:   A logon succeeded right after an attack.
	 * WHY:    The account should be treated as compromised: this is the alert
	 *         that needs action now.
	 * </summary>
	 */
	Critical,
}

/**
 * <summary>
 * WHAT:   One finding from a detection rule.
 * WHY:    Every rule returns the same shape, so the text and JSON reports
 *         do not need to know which rule produced an alert, and new rules
 *         need no report changes.
 * PRE:    Accounts has no duplicates; First is not after Last.
 * </summary>
 * <param name="Rule">the rule's short name, e.g. "brute-force"</param>
 * <param name="Severity">how urgent the alert is</param>
 * <param name="Source">the attacking IP address, "-" for local, or "N sources" for a distributed attack</param>
 * <param name="Accounts">the account names (or, for injection, the payloads) involved, without duplicates</param>
 * <param name="Attempts">how many logons are part of the alert</param>
 * <param name="First">time of the first event in the alert</param>
 * <param name="Last">time of the last event in the alert</param>
 * <param name="Summary">one sentence describing what happened</param>
 */
public sealed record Alert(
	string Rule,
	Severity Severity,
	string Source,
	IReadOnlyList<string> Accounts,
	int Attempts,
	DateTimeOffset First,
	DateTimeOffset Last,
	string Summary)
{
	/**
	 * <summary>
	 * WHAT:   The MITRE ATT&amp;CK techniques the alert is evidence of.
	 * WHY:    Lets a SOC or SIEM group and search alerts by technique; filled
	 *         in by the Detector from the rule that raised the alert, unless
	 *         the rule chose techniques for this alert itself.
	 * PRE:    none
	 * RETURN: the techniques, most specific first; empty only for alerts
	 *         built outside the Detector
	 * </summary>
	 */
	public IReadOnlyList<Technique> Techniques { get; init; } = [];
}
