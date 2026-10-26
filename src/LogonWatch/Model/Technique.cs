namespace LogonWatch.Model;

/**
 * <summary>
 * WHAT:   One MITRE ATT&amp;CK technique: its ID, name and tactic.
 * WHY:    ATT&amp;CK is the shared vocabulary of security teams. "T1110.003"
 *         means password spraying to every analyst, SIEM and threat report,
 *         so tagging alerts with it lets them be searched, counted and
 *         compared with other tools without reading the summary text.
 * PRE:    Id looks like "T1110" or "T1110.003".
 * </summary>
 * <param name="Id">the technique ID, e.g. "T1110.003"</param>
 * <param name="Name">the technique name, e.g. "Password Spraying"</param>
 * <param name="Tactic">the attacker's goal it serves, e.g. "Credential Access"</param>
 */
public sealed record Technique(string Id, string Name, string Tactic)
{
	/**
	 * <summary>
	 * WHAT:   The technique's page on attack.mitre.org.
	 * WHY:    One click from an alert to the full description, detections
	 *         and mitigations.
	 * PRE:    none
	 * RETURN: e.g. https://attack.mitre.org/techniques/T1110/003/
	 * </summary>
	 */
	public string Url => $"https://attack.mitre.org/techniques/{Id.Replace('.', '/')}/";

	/**
	 * <summary>
	 * WHAT:   The technique as one line, e.g. "T1110.003 Password Spraying (Credential Access)".
	 * WHY:    How the text report shows it.
	 * PRE:    none
	 * RETURN: the line
	 * </summary>
	 * <returns>the line</returns>
	 */
	public override string ToString() => $"{Id} {Name} ({Tactic})";
}

/**
 * <summary>
 * WHAT:   The ATT&amp;CK techniques logonwatch can see in logon events.
 * WHY:    One place for the IDs, so a rule refers to Attack.PasswordSpraying
 *         instead of repeating a string that could be mistyped.
 *         Source: MITRE ATT&amp;CK Enterprise matrix (attack.mitre.org).
 * </summary>
 */
public static class Attack
{
	/**
	 * <summary>
	 * WHAT:   T1110 Brute Force, the parent technique.
	 * WHY:    Used when the failures before a break-in could be guessing or
	 *         spraying, so the sub-technique is not known.
	 * </summary>
	 */
	public static readonly Technique BruteForce = new("T1110", "Brute Force", "Credential Access");

	/**
	 * <summary>
	 * WHAT:   T1110.001 Password Guessing: many passwords against an account.
	 * WHY:    What brute-force and distributed-attack alerts show.
	 * </summary>
	 */
	public static readonly Technique PasswordGuessing = new("T1110.001", "Password Guessing", "Credential Access");

	/**
	 * <summary>
	 * WHAT:   T1110.003 Password Spraying: one or two passwords against many accounts.
	 * WHY:    What password-spray alerts show; it avoids lockouts, so it
	 *         looks quieter than guessing.
	 * </summary>
	 */
	public static readonly Technique PasswordSpraying = new("T1110.003", "Password Spraying", "Credential Access");

	/**
	 * <summary>
	 * WHAT:   T1078 Valid Accounts: logging on with a real account's password.
	 * WHY:    A success after an attack means the attacker now holds a working
	 *         password, which is how most intrusions start.
	 * </summary>
	 */
	public static readonly Technique ValidAccounts = new("T1078", "Valid Accounts", "Initial Access");

	/**
	 * <summary>
	 * WHAT:   T1021.001 Remote Desktop Protocol.
	 * WHY:    Added when the successful logon was a Remote Desktop logon
	 *         (type 10): the attacker has an interactive session.
	 * </summary>
	 */
	public static readonly Technique RemoteDesktop = new("T1021.001", "Remote Desktop Protocol", "Lateral Movement");

	/**
	 * <summary>
	 * WHAT:   T1190 Exploit Public-Facing Application.
	 * WHY:    A user name that is an SQL injection or Log4Shell payload is an
	 *         attempt to exploit whatever reads the login, not to guess a password.
	 * </summary>
	 */
	public static readonly Technique ExploitPublicFacing = new("T1190", "Exploit Public-Facing Application",
		"Initial Access");
}
