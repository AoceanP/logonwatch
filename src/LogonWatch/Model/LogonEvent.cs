namespace LogonWatch.Model;

/**
 * <summary>
 * WHAT:   Whether a logon attempt worked.
 * WHY:    Detection compares failures (4625) with successes (4624).
 * </summary>
 */
public enum LogonOutcome
{
	/** <summary>WHAT: event 4624, the account logged on.</summary> */
	Success,

	/** <summary>WHAT: event 4625, Windows refused the logon.</summary> */
	Failure,
}

/**
 * <summary>
 * WHAT:   One logon attempt taken from the Windows Security log.
 * WHY:    Keeps only the fields the detection rules need, so the rules can be
 *         tested with plain objects instead of real Windows events.
 * PRE:    Time is in UTC; Source is an IP address, or "-" when Windows
 *         recorded none (a logon typed at the machine itself).
 * </summary>
 * <param name="Time">when the attempt happened, in UTC</param>
 * <param name="Outcome">success (4624) or failure (4625)</param>
 * <param name="User">the account name that was tried, e.g. "administrator"</param>
 * <param name="Domain">the account's domain or computer name, or "-"</param>
 * <param name="Source">the IP address the attempt came from, or "-" for local</param>
 * <param name="LogonType">how the logon was made: 2 at the keyboard, 3 over the network, 10 Remote Desktop</param>
 * <param name="Reason">why a failure happened, e.g. "wrong password"; empty for successes</param>
 */
public sealed record LogonEvent(
	DateTimeOffset Time,
	LogonOutcome Outcome,
	string User,
	string Domain,
	string Source,
	int LogonType,
	string Reason)
{
	/**
	 * <summary>
	 * WHAT:   Tells whether the attempt came from this machine itself.
	 * WHY:    A person mistyping their own password at the keyboard is not
	 *         an attack, so local bursts get a low severity.
	 * RETURN: true for "-", 127.0.0.1 and ::1
	 * </summary>
	 */
	public bool IsLocal => Source is "-" or "127.0.0.1" or "::1";

	/**
	 * <summary>
	 * WHAT:   Shorthand for Outcome == Failure.
	 * WHY:    Most rules only look at failures.
	 * </summary>
	 */
	public bool IsFailure => Outcome == LogonOutcome.Failure;
}
