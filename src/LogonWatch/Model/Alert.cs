namespace LogonWatch.Model;

/**
 * <summary>
 * WHAT:   How urgent an alert is.
 * WHY:    Lets the report put "someone probably got in" above "someone is
 *         knocking", the way a SOC triages alerts.
 * </summary>
 */
public enum Severity
{
	/** <summary>WHAT: worth a look, probably harmless (e.g. a user mistyping locally).</summary> */
	Low,

	/** <summary>WHAT: an attack pattern, but nothing suggests it worked.</summary> */
	Medium,

	/** <summary>WHAT: a large or targeted attack.</summary> */
	High,

	/** <summary>WHAT: a logon succeeded right after an attack: treat the account as compromised.</summary> */
	Critical,
}

/**
 * <summary>
 * WHAT:   One finding from a detection rule.
 * WHY:    A single shape for every rule, so the text and JSON reports do not
 *         need to know which rule produced an alert.
 * </summary>
 * <param name="Rule">the rule's short name, e.g. "brute-force"</param>
 * <param name="Severity">how urgent the alert is</param>
 * <param name="Source">the attacking IP address, "-" for local, or "N sources" for a distributed attack</param>
 * <param name="Accounts">the account names involved, without duplicates</param>
 * <param name="Attempts">how many failed logons are part of the alert</param>
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
	string Summary);
