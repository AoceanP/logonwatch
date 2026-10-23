namespace LogonWatch.Detection;

/**
 * <summary>
 * WHAT:   The thresholds and time windows every rule uses.
 * WHY:    What counts as an attack depends on the network: 10 failures in
 *         5 minutes is loud on a home PC but normal on a busy server, so
 *         the numbers are settings, not constants.
 * </summary>
 */
public sealed record DetectionSettings
{
	/** <summary>WHAT: failed logons from one source that make a brute-force alert.</summary> */
	public int BruteForceThreshold { get; init; } = 10;

	/** <summary>WHAT: how close together those failures must be.</summary> */
	public TimeSpan BruteForceWindow { get; init; } = TimeSpan.FromMinutes(5);

	/** <summary>WHAT: different accounts one source must try to count as password spraying.</summary> */
	public int SprayAccountThreshold { get; init; } = 5;

	/** <summary>WHAT: the window for password spraying.</summary> */
	public TimeSpan SprayWindow { get; init; } = TimeSpan.FromMinutes(10);

	/** <summary>WHAT: different sources attacking one account that make a distributed-attack alert.</summary> */
	public int DistributedSourceThreshold { get; init; } = 5;

	/** <summary>WHAT: the window for a distributed attack.</summary> */
	public TimeSpan DistributedWindow { get; init; } = TimeSpan.FromMinutes(10);

	/** <summary>WHAT: failures before a success that make it suspicious.</summary> */
	public int SuccessAfterFailuresThreshold { get; init; } = 5;

	/** <summary>WHAT: how far back from a success to count failures.</summary> */
	public TimeSpan SuccessAfterFailuresWindow { get; init; } = TimeSpan.FromMinutes(10);

	/**
	 * <summary>
	 * WHAT:   Checks every threshold is at least 2 and every window is positive.
	 * WHY:    A threshold of 1 would turn every typo into an alert, and a
	 *         zero window would never match anything.
	 * THROWS: ArgumentException naming the bad setting
	 * </summary>
	 * <exception cref="ArgumentException">a threshold is below 2 or a window is not positive</exception>
	 */
	public void Validate()
	{
		CheckThreshold(nameof(BruteForceThreshold), BruteForceThreshold);
		CheckThreshold(nameof(SprayAccountThreshold), SprayAccountThreshold);
		CheckThreshold(nameof(DistributedSourceThreshold), DistributedSourceThreshold);
		CheckThreshold(nameof(SuccessAfterFailuresThreshold), SuccessAfterFailuresThreshold);
		CheckWindow(nameof(BruteForceWindow), BruteForceWindow);
		CheckWindow(nameof(SprayWindow), SprayWindow);
		CheckWindow(nameof(DistributedWindow), DistributedWindow);
		CheckWindow(nameof(SuccessAfterFailuresWindow), SuccessAfterFailuresWindow);
	}

	/**
	 * <summary>
	 * WHAT:   Refuses a threshold below 2.
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
