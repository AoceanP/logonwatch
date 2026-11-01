using LogonWatch.Cli;
using LogonWatch.Detection;
using LogonWatch.Model;

namespace LogonWatch.Tests;

/**
 * WHAT:   Tests for the slow rules: slow-guessing and slow-spray.
 * WHY:    A patient attacker paces itself to stay under the fast rules'
 *         5- and 10-minute windows. These tests check the slow rules catch
 *         that, stay quiet just below their thresholds, and never report an
 *         attack the fast rules already did.
 */
public class SlowAttackTests
{
	/**
	 * WHAT:   One hour, in seconds.
	 * WHY:    The slow attacks below are paced in hours.
	 */
	private const double Hour = 3600;

	/**
	 * WHAT:   Runs the whole detector and returns the rule names that fired.
	 * WHY:    "Not reported twice" can only be checked with every rule running.
	 * PRE:    events is not null
	 * RETURN: the rule names, one per alert
	 */
	private static List<string> RulesFired(IEnumerable<LogonEvent> events) =>
		Detector.Run(events, new DetectionSettings()).Select(a => a.Rule).ToList();

	/**
	 * WHAT:   Runs one rule on events, after the same cleaning a real run does.
	 * PRE:    rule and events are not null
	 * RETURN: the rule's alerts
	 */
	private static List<Alert> Run(IDetectionRule rule, IEnumerable<LogonEvent> events) =>
		rule.Evaluate(Detector.Prepare(events), new DetectionSettings()).ToList();

	/**
	 * WHAT:   20 failures against one account, one an hour, from one address.
	 * WHY:    The threshold itself must fire, and no fast rule sees it.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void SlowGuessingFiresAtThreshold()
	{
		List<LogonEvent> events = TestData.Failures(20, spacing: Hour);

		Alert alert = Assert.Single(Detector.Run(events, new DetectionSettings()));
		Assert.Equal("slow-guessing", alert.Rule);
		Assert.Equal(Severity.Medium, alert.Severity);
		Assert.Equal(20, alert.Attempts);
		Assert.Equal("203.0.113.7", alert.Source);
		Assert.Equal(["administrator"], alert.Accounts);
	}

	/**
	 * WHAT:   19 failures in a day.
	 * WHY:    One below the threshold is a user who keeps forgetting a new password.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void SlowGuessingIgnoresBelowThreshold()
	{
		Assert.Empty(Run(new SlowGuessingRule(), TestData.Failures(19, spacing: Hour)));
	}

	/**
	 * WHAT:   30 failures, one every 2 hours: 60 hours in all.
	 * WHY:    No 24-hour stretch holds 20 of them (at most 13), so it is too
	 *         spread out to be one attack by this rule's definition.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void SlowGuessingIgnoresFailuresSpreadOverDays()
	{
		Assert.Empty(Run(new SlowGuessingRule(), TestData.Failures(30, spacing: 2 * Hour)));
	}

	/**
	 * WHAT:   21 failures against one account from three addresses taking turns.
	 * WHY:    Rotating addresses defeats every per-source rule, and 3 sources
	 *         is below the distributed-attack threshold; it is deliberate
	 *         hiding, so it is High.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void SlowGuessingFromRotatingAddressesIsHigh()
	{
		List<LogonEvent> events = Enumerable.Range(0, 21)
			.Select(i => TestData.Failure(i * Hour, source: $"198.51.100.{40 + i % 3}")).ToList();

		Alert alert = Assert.Single(Detector.Run(events, new DetectionSettings()));
		Assert.Equal("slow-guessing", alert.Rule);
		Assert.Equal(Severity.High, alert.Severity);
		Assert.Equal("3 sources", alert.Source);
		Assert.Contains("3 different addresses", alert.Summary);
	}

	/**
	 * WHAT:   20 failures in a day typed at the machine itself.
	 * WHY:    Someone at the keyboard is far less likely to be an attack.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void SlowGuessingTypedLocallyIsLow()
	{
		Alert alert = Assert.Single(Run(new SlowGuessingRule(), TestData.Failures(20, spacing: Hour, source: "-")));
		Assert.Equal(Severity.Low, alert.Severity);
	}

	/**
	 * WHAT:   60 failures in 2 minutes.
	 * WHY:    A fast attack is brute force; reporting it as slow guessing too
	 *         would be the same attack twice.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void FastAttackIsNotAlsoSlowGuessing()
	{
		Assert.Equal(["brute-force"], RulesFired(TestData.Failures(60, spacing: 2)));
	}

	/**
	 * WHAT:   A burst of 10 in 5 minutes, then 20 more at one an hour.
	 * WHY:    The burst is brute force; the patient attack after it must
	 *         still be caught, counting only the 20 slow failures.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void BurstThenSlowGivesBothAlerts()
	{
		List<LogonEvent> events = TestData.Failures(10, spacing: 20);
		events.AddRange(TestData.Failures(20, spacing: Hour, first: Hour));

		List<Alert> alerts = Detector.Run(events, new DetectionSettings());
		Assert.Equal(10, Assert.Single(alerts, a => a.Rule == "brute-force").Attempts);
		Assert.Equal(20, Assert.Single(alerts, a => a.Rule == "slow-guessing").Attempts);
	}

	/**
	 * WHAT:   One address failing against 10 different accounts, one an hour.
	 * WHY:    Never 5 accounts inside 10 minutes, so the fast spray rule
	 *         misses it; 10 accounts in a day is the slow threshold.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void SlowSprayFiresAtThreshold()
	{
		List<LogonEvent> events = Enumerable.Range(0, 10).Select(i => TestData.Failure(i * Hour, $"user{i}")).ToList();

		Alert alert = Assert.Single(Detector.Run(events, new DetectionSettings()));
		Assert.Equal("slow-spray", alert.Rule);
		Assert.Equal(Severity.High, alert.Severity);
		Assert.Equal(10, alert.Accounts.Count);
		Assert.Equal(["T1110.003"], alert.Techniques.Select(t => t.Id));
	}

	/**
	 * WHAT:   9 different accounts in a day.
	 * WHY:    One below the threshold: a shared address (an office behind one
	 *         router) can fail against a handful of accounts.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void SlowSprayIgnoresBelowThreshold()
	{
		List<LogonEvent> events = Enumerable.Range(0, 9).Select(i => TestData.Failure(i * Hour, $"user{i}")).ToList();
		Assert.Empty(Run(new SlowSprayRule(), events));
	}

	/**
	 * WHAT:   12 accounts in 2 minutes.
	 * WHY:    A fast spray is password-spray (and, at 12 attempts in 2 minutes,
	 *         brute force too), but never slow-spray.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void FastSprayIsNotAlsoSlowSpray()
	{
		List<LogonEvent> events = Enumerable.Range(0, 12).Select(i => TestData.Failure(i * 10, $"user{i}")).ToList();

		List<string> rules = RulesFired(events);
		Assert.Contains("password-spray", rules);
		Assert.DoesNotContain("slow-spray", rules);
	}

	/**
	 * WHAT:   One account failing 30 times in a day from one address.
	 * WHY:    Many failures on one account are guessing, not spraying.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void OneAccountIsNeverSlowSpray()
	{
		Assert.Equal(["slow-guessing"], RulesFired(TestData.Failures(30, spacing: Hour / 2)));
	}

	/**
	 * WHAT:   A slow window no longer than a fast one.
	 * WHY:    It could only find what the fast rules already find, so it is
	 *         refused, and on the command line it is a usage error (exit 2).
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void SlowWindowMustBeLongerThanFastWindows()
	{
		Assert.Throws<ArgumentException>(() =>
			new DetectionSettings { SlowWindow = TimeSpan.FromMinutes(10) }.Validate());
		Assert.Throws<UsageException>(() => OptionsParser.Parse(["--demo", "--slow-window", "10m"], out _));
	}

	/**
	 * WHAT:   --slow-window and --slow-threshold on the command line.
	 * WHY:    A busy server may need a higher threshold; a quiet one a longer window.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void ParsesSlowOptions()
	{
		Options options = OptionsParser.Parse(["--demo", "--slow-window", "48h", "--slow-threshold", "40"], out _)!;
		Assert.Equal(TimeSpan.FromHours(48), options.Settings.SlowWindow);
		Assert.Equal(40, options.Settings.SlowGuessThreshold);
	}
}
