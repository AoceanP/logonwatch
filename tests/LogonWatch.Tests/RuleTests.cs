using LogonWatch.Detection;
using LogonWatch.Model;

namespace LogonWatch.Tests;

/**
 * WHAT:   Tests for the four time-window rules (the injection rule has
 *         its own file, InjectionTests.cs), each with an attack that
 *         must fire and a near-miss that must not.
 * WHY:    A rule that fires too easily buries real attacks in noise; one
 *         that never fires is worse. Both sides are checked at the boundary.
 */
public class RuleTests
{
	/**
	 * WHAT:   The default settings: brute force 10 in 5 min, spray 5 accounts,
	 *         distributed 5 sources, success after 5 failures.
	 * WHY:    Each test builds its attack just above or just below these
	 *         numbers, so the boundaries are tested exactly.
	 */
	private static readonly DetectionSettings Settings = new();

	/**
	 * WHAT:   Runs one rule on events, after the same cleaning a real run does.
	 * WHY:    Tests one rule in isolation, without the other rules' alerts.
	 * PRE:    rule and events are not null
	 * RETURN: the rule's alerts
	 */
	private static List<Alert> Run(IDetectionRule rule, IEnumerable<LogonEvent> events) =>
		rule.Evaluate(Detector.Prepare(events), Settings).ToList();

	/**
	 * WHAT:   Exactly 10 failures in 5 minutes.
	 * WHY:    The threshold itself must fire.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void BruteForceFiresAtThreshold()
	{
		List<Alert> alerts = Run(new BruteForceRule(), TestData.Failures(10, spacing: 30));

		Alert alert = Assert.Single(alerts);
		Assert.Equal("brute-force", alert.Rule);
		Assert.Equal(Severity.Medium, alert.Severity);
		Assert.Equal(10, alert.Attempts);
		Assert.Equal("203.0.113.7", alert.Source);
	}

	/**
	 * WHAT:   9 failures.
	 * WHY:    One below the threshold is a user having a bad day.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void BruteForceIgnoresBelowThreshold()
	{
		Assert.Empty(Run(new BruteForceRule(), TestData.Failures(9, spacing: 30)));
	}

	/**
	 * WHAT:   10 failures spread over 10 minutes.
	 * WHY:    Too slow for a 5-minute window.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void BruteForceIgnoresSlowFailures()
	{
		Assert.Empty(Run(new BruteForceRule(), TestData.Failures(10, spacing: 65)));
	}

	/**
	 * WHAT:   50 or more failures.
	 * WHY:    Five times the threshold is a large attack, so High.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void BruteForceLargeAttackIsHigh()
	{
		Assert.Equal(Severity.High, Assert.Single(Run(new BruteForceRule(), TestData.Failures(50, spacing: 1))).Severity);
	}

	/**
	 * WHAT:   Two attacks an hour apart.
	 * WHY:    Separate bursts must be separate alerts, not one.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void BruteForceSplitsSeparateBursts()
	{
		List<LogonEvent> events = TestData.Failures(12, spacing: 5);
		events.AddRange(TestData.Failures(12, spacing: 5, first: 3600));
		Assert.Equal(2, Run(new BruteForceRule(), events).Count);
	}

	/**
	 * WHAT:   200 failures in a row.
	 * WHY:    One long attack must be one alert, not 190 overlapping ones.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void BruteForceMergesOneLongAttack()
	{
		Alert alert = Assert.Single(Run(new BruteForceRule(), TestData.Failures(200, spacing: 3)));
		Assert.Equal(200, alert.Attempts);
	}

	/**
	 * WHAT:   Failures typed at the machine itself.
	 * WHY:    A person mistyping is reported, but only as Low.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void BruteForceLocalIsLow()
	{
		Assert.Equal(Severity.Low,
			Assert.Single(Run(new BruteForceRule(), TestData.Failures(10, spacing: 5, source: "-"))).Severity);
	}

	/**
	 * WHAT:   One source, 5 different accounts.
	 * WHY:    The spray threshold itself must fire.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void SprayFiresOnManyAccounts()
	{
		string[] users = ["admin", "backup", "sql", "guest", "test"];
		List<LogonEvent> events = users.Select((user, i) => TestData.Failure(i * 20, user, "198.51.100.23")).ToList();

		Alert alert = Assert.Single(Run(new PasswordSprayRule(), events));
		Assert.Equal(Severity.High, alert.Severity);
		Assert.Equal(5, alert.Accounts.Count);
	}

	/**
	 * WHAT:   One account mistyped 20 times.
	 * WHY:    Many attempts at one account is not spraying.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void SprayIgnoresOneAccount()
	{
		Assert.Empty(Run(new PasswordSprayRule(), TestData.Failures(20, spacing: 5)));
	}

	/**
	 * WHAT:   "Admin" and "admin".
	 * WHY:    Windows account names ignore case, so they are one account.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void SprayCountsAccountsIgnoringCase()
	{
		string[] users = ["admin", "Admin", "ADMIN", "backup", "sql"];
		List<LogonEvent> events = users.Select((user, i) => TestData.Failure(i * 20, user, "198.51.100.23")).ToList();
		Assert.Empty(Run(new PasswordSprayRule(), events));
	}

	/**
	 * WHAT:   5 sources, one account.
	 * WHY:    A botnet spreads guesses so no single address stands out.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void DistributedFiresOnManySources()
	{
		List<LogonEvent> events = Enumerable.Range(1, 5).Select(i => TestData.Failure(i * 30, "backup", $"192.0.2.{i}")).ToList();

		Alert alert = Assert.Single(Run(new DistributedAttackRule(), events));
		Assert.Equal("5 sources", alert.Source);
		Assert.Equal(new[] { "backup" }, alert.Accounts);
	}

	/**
	 * WHAT:   4 sources.
	 * WHY:    One below the threshold.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void DistributedIgnoresFewSources()
	{
		List<LogonEvent> events = Enumerable.Range(1, 4).Select(i => TestData.Failure(i * 30, "backup", $"192.0.2.{i}")).ToList();
		Assert.Empty(Run(new DistributedAttackRule(), events));
	}

	/**
	 * WHAT:   5 failures, then a success from the same address.
	 * WHY:    The attack probably worked: Critical.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void SuccessAfterFailuresIsCritical()
	{
		List<LogonEvent> events = TestData.Failures(5, spacing: 10);
		events.Add(TestData.Success(60));

		Alert alert = Assert.Single(Run(new SuccessAfterFailuresRule(), events));
		Assert.Equal(Severity.Critical, alert.Severity);
		Assert.Equal(5, alert.Attempts);
		Assert.Contains("compromised", alert.Summary);
	}

	/**
	 * WHAT:   Failures from one address, success from another, same account.
	 * WHY:    Attackers switch addresses.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void SuccessAfterFailuresMatchesAccount()
	{
		List<LogonEvent> events = TestData.Failures(5, spacing: 10);
		events.Add(TestData.Success(60, source: "198.51.100.99"));
		Assert.Single(Run(new SuccessAfterFailuresRule(), events));
	}

	/**
	 * WHAT:   The failures were an hour before the success.
	 * WHY:    Outside the window, they are unrelated.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void SuccessAfterOldFailuresIsIgnored()
	{
		List<LogonEvent> events = TestData.Failures(5, spacing: 10);
		events.Add(TestData.Success(3600));
		Assert.Empty(Run(new SuccessAfterFailuresRule(), events));
	}

	/**
	 * WHAT:   4 failures then a success.
	 * WHY:    Someone remembering their password on the 5th try is normal.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void SuccessAfterFewFailuresIsIgnored()
	{
		List<LogonEvent> events = TestData.Failures(4, spacing: 10);
		events.Add(TestData.Success(60));
		Assert.Empty(Run(new SuccessAfterFailuresRule(), events));
	}

	/**
	 * WHAT:   Three successes right after one attack.
	 * WHY:    One break-in, one alert.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void SuccessAfterFailuresAlertsOnce()
	{
		List<LogonEvent> events = TestData.Failures(10, spacing: 5);
		events.Add(TestData.Success(60));
		events.Add(TestData.Success(70));
		events.Add(TestData.Success(80));
		Assert.Single(Run(new SuccessAfterFailuresRule(), events));
	}
}
