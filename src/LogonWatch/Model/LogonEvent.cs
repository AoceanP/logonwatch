namespace LogonWatch.Model;

/**
 * <summary>
 * WHAT:   Whether a logon attempt worked or was refused.
 * WHY:    Every rule compares failures with successes, so the outcome is
 *         its own small type instead of a raw event ID number.
 * </summary>
 */
public enum LogonOutcome
{
	/**
	 * <summary>
	 * WHAT:   Event 4624: the account logged on.
	 * WHY:    A success right after many failures is the sign an attack worked.
	 * </summary>
	 */
	Success,

	/**
	 * <summary>
	 * WHAT:   Event 4625: Windows refused the logon.
	 * WHY:    Failures are the trail every password-guessing attack leaves.
	 * </summary>
	 */
	Failure,
}

/**
 * <summary>
 * WHAT:   One logon attempt taken from the Windows Security log (or a
 *         JSON-lines file), reduced to the fields the rules need.
 * WHY:    The rules only ever see this record, never Windows' own event
 *         objects, so they can be tested with plain objects and the same
 *         rules work on every input source.
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
	 *         an attack, so rules give local bursts a low severity.
	 * PRE:    none
	 * RETURN: true for "-" (no address), 127.0.0.1 and ::1 (loopback)
	 * </summary>
	 */
	public bool IsLocal => Source is "-" or "127.0.0.1" or "::1";

	/**
	 * <summary>
	 * WHAT:   Shorthand for Outcome == Failure.
	 * WHY:    Most rules only look at failures, and this reads better in LINQ
	 *         queries such as events.Where(e => e.IsFailure).
	 * PRE:    none
	 * RETURN: true for a failed logon
	 * </summary>
	 */
	public bool IsFailure => Outcome == LogonOutcome.Failure;
}
