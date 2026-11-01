namespace LogonWatch.Detection;

/**
 * <summary>
 * WHAT:   The thresholds and time windows every rule uses.
 * WHY:    What counts as an attack depends on the network: 10 failures in
 *         5 minutes is loud on a home PC but normal on a busy server, so
 *         the numbers are settings, not constants. A record with init
 *         properties lets the command line change one value with "with".
 * </summary>
 */
public sealed record DetectionSettings
{
	/**
	 * <summary>
	 * WHAT:   Failed logons from one source that make a brute-force alert.
	 * WHY:    10 is well above an honest user's retries but far below a tool's.
	 * </summary>
	 */
	public int BruteForceThreshold { get; init; } = 10;

	/**
	 * <summary>
	 * WHAT:   How close together those failures must be.
	 * WHY:    Tools guess many times a second; 5 minutes catches slow ones too.
	 * </summary>
	 */
	public TimeSpan BruteForceWindow { get; init; } = TimeSpan.FromMinutes(5);

	/**
	 * <summary>
	 * WHAT:   Different accounts one source must try to count as password spraying.
	 * WHY:    A person mistypes their own account, not five different ones.
	 * </summary>
	 */
	public int SprayAccountThreshold { get; init; } = 5;

	/**
	 * <summary>
	 * WHAT:   The window for password spraying.
	 * WHY:    Sprayers go slowly on purpose, so the window is longer.
	 * </summary>
	 */
	public TimeSpan SprayWindow { get; init; } = TimeSpan.FromMinutes(10);

	/**
	 * <summary>
	 * WHAT:   Different sources attacking one account that make a distributed-attack alert.
	 * WHY:    One account failing from five addresses is not one forgetful user.
	 * </summary>
	 */
	public int DistributedSourceThreshold { get; init; } = 5;

	/**
	 * <summary>
	 * WHAT:   The window for a distributed attack.
	 * WHY:    Botnets coordinate loosely, so a longer window is needed.
	 * </summary>
	 */
	public TimeSpan DistributedWindow { get; init; } = TimeSpan.FromMinutes(10);

	/**
	 * <summary>
	 * WHAT:   Failures before a success that make it suspicious.
	 * WHY:    Getting a password right on the 5th try is normal; after more is not.
	 * </summary>
	 */
	public int SuccessAfterFailuresThreshold { get; init; } = 5;

	/**
	 * <summary>
	 * WHAT:   How far back from a success to count failures.
	 * WHY:    Failures an hour earlier are unrelated to a success now.
	 * </summary>
	 */
	public TimeSpan SuccessAfterFailuresWindow { get; init; } = TimeSpan.FromMinutes(10);

	/**
	 * <summary>
	 * WHAT:   Failures against one account over SlowWindow that make a slow-guessing alert.
	 * WHY:    An honest user mistypes a few times a day, not 20; a patient
	 *         tool at one guess an hour reaches 20 well inside a day.
	 * </summary>
	 */
	public int SlowGuessThreshold { get; init; } = 20;

	/**
	 * <summary>
	 * WHAT:   Different accounts one source must fail against over SlowWindow to count as slow spraying.
	 * WHY:    Twice the fast threshold: a shared address (an office behind one
	 *         router) can fail against a few accounts in a day, not ten.
	 * </summary>
	 */
	public int SlowSprayAccountThreshold { get; init; } = 10;

	/**
	 * <summary>
	 * WHAT:   The window for the slow rules.
	 * WHY:    A day covers an attacker pacing itself to stay under the
	 *         5- and 10-minute windows, and logs are commonly reviewed daily.
	 * </summary>
	 */
	public TimeSpan SlowWindow { get; init; } = TimeSpan.FromHours(24);

	/**
	 * <summary>
	 * WHAT:   Checks every threshold is at least 2, every window is positive,
	 *         and the slow window is longer than every fast one.
	 * WHY:    A threshold of 1 would turn every typo into an alert, a zero
	 *         window would never match anything, and a "slow" window shorter
	 *         than a fast one would only find what the fast rules already do.
	 * PRE:    none
	 * POST:   nothing is changed
	 * RETURN: nothing; returns normally when every setting is valid
	 * THROWS: ArgumentException naming the first bad setting
	 * </summary>
	 * <exception cref="ArgumentException">a threshold is below 2, a window is not positive,
	 *                                     or SlowWindow is not the longest window</exception>
	 */
	public void Validate()
	{
		CheckThreshold(nameof(BruteForceThreshold), BruteForceThreshold);
		CheckThreshold(nameof(SprayAccountThreshold), SprayAccountThreshold);
		CheckThreshold(nameof(DistributedSourceThreshold), DistributedSourceThreshold);
		CheckThreshold(nameof(SuccessAfterFailuresThreshold), SuccessAfterFailuresThreshold);
		CheckThreshold(nameof(SlowGuessThreshold), SlowGuessThreshold);
		CheckThreshold(nameof(SlowSprayAccountThreshold), SlowSprayAccountThreshold);
		CheckWindow(nameof(BruteForceWindow), BruteForceWindow);
		CheckWindow(nameof(SprayWindow), SprayWindow);
		CheckWindow(nameof(DistributedWindow), DistributedWindow);
		CheckWindow(nameof(SuccessAfterFailuresWindow), SuccessAfterFailuresWindow);
		CheckWindow(nameof(SlowWindow), SlowWindow);

		TimeSpan longestFast = new[] { BruteForceWindow, SprayWindow, DistributedWindow }.Max();
		if (SlowWindow <= longestFast)
		{
			throw new ArgumentException(
				$"{nameof(SlowWindow)} must be longer than the fast windows ({longestFast}), got {SlowWindow}");
		}
	}

	/**
	 * <summary>
	 * WHAT:   Refuses a threshold below 2.
	 * WHY:    Keeps the rule and its message in one place for every threshold.
	 * PRE:    name is the setting's property name
	 * RETURN: nothing
	 * THROWS: ArgumentException if value is below 2
	 * </summary>
	 * <param name="name">the setting's name, for the message</param>
	 * <param name="value">the threshold</param>
	 * <exception cref="ArgumentException">value is below 2</exception>
	 */
	private static void CheckThreshold(string name, int value)
	{
		if (value < 2)
		{
			throw new ArgumentException($"{name} must be at least 2, got {value}");
		}
	}

	/**
	 * <summary>
	 * WHAT:   Refuses a window that is zero or negative.
	 * WHY:    Keeps the rule and its message in one place for every window.
	 * PRE:    name is the setting's property name
	 * RETURN: nothing
	 * THROWS: ArgumentException if value is not positive
	 * </summary>
	 * <param name="name">the setting's name, for the message</param>
	 * <param name="value">the window</param>
	 * <exception cref="ArgumentException">value is not positive</exception>
	 */
	private static void CheckWindow(string name, TimeSpan value)
	{
		if (value <= TimeSpan.Zero)
		{
			throw new ArgumentException($"{name} must be longer than zero, got {value}");
		}
	}
}
