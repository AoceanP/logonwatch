using System.Diagnostics;
using LogonWatch.Detection;
using LogonWatch.Model;

namespace LogonWatch.Tests;

/**
 * WHAT:   Edge cases, each listed in the README's "Edge cases" table.
 * WHY:    Boundaries and odd data are where detection rules are wrong in
 *         practice: an off-by-one second, a case difference, a huge log.
 */
public class EdgeCaseTests
{
	/**
	 * WHAT:   The default settings, shared by every test in this class.
	 * WHY:    Edge cases are checked against the same thresholds a real run uses.
	 */
	private static readonly DetectionSettings Settings = new();

	/**
	 * WHAT:   10 failures exactly 5:00 apart first to last.
	 * WHY:    The window is inclusive.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void WindowBoundaryIsInclusive()
	{
		List<LogonEvent> events = TestData.Failures(10, spacing: 300.0 / 9);
		Assert.Single(new BruteForceRule().Evaluate(Detector.Prepare(events), Settings));
	}

	/**
	 * WHAT:   The same 10 failures one second wider.
	 * WHY:    Just outside the window must not fire.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void WindowBoundaryPlusOneSecond()
	{
		List<LogonEvent> events = TestData.Failures(9, spacing: 300.0 / 8);
		events.Add(TestData.Failure(301));
		Assert.Empty(new BruteForceRule().Evaluate(Detector.Prepare(events), Settings));
	}

	/**
	 * WHAT:   10 failures with the same timestamp.
	 * WHY:    Logs record to the millisecond; bursts can share one.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void IdenticalTimestamps()
	{
		List<LogonEvent> events = TestData.Failures(10, spacing: 0);
		Assert.Equal(10, Assert.Single(new BruteForceRule().Evaluate(Detector.Prepare(events), Settings)).Attempts);
	}

	/**
	 * WHAT:   No events at all.
	 * WHY:    An empty log is normal and must give no alerts, not an error.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void EmptyInput()
	{
		Assert.Empty(Detector.Run([], Settings));
	}

	/**
	 * WHAT:   Only successful logons.
	 * WHY:    A quiet, healthy log.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void OnlySuccesses()
	{
		Assert.Empty(Detector.Run(Enumerable.Range(0, 50).Select(i => TestData.Success(i * 10, "alice")), Settings));
	}

	/**
	 * WHAT:   The same IPv6 source in upper and lower case.
	 * WHY:    "2001:DB8::1" and "2001:db8::1" are one address.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void SourcesIgnoreCase()
	{
		List<LogonEvent> events = TestData.Failures(5, spacing: 5, source: "2001:DB8::1");
		events.AddRange(TestData.Failures(5, spacing: 5, first: 30, source: "2001:db8::1"));
		Assert.Single(new BruteForceRule().Evaluate(Detector.Prepare(events), Settings));
	}

	/**
	 * WHAT:   One source both brute-forcing and spraying.
	 * WHY:    Both patterns are real, so both rules report.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void OneSourceCanTriggerTwoRules()
	{
		string[] users = ["admin", "backup", "sql", "guest", "test", "web", "ftp", "oracle", "root", "user"];
		List<LogonEvent> events = users.Select((user, i) => TestData.Failure(i * 5, user, "198.51.100.23")).ToList();
		List<string> rules = Detector.Run(events, Settings).Select(a => a.Rule).ToList();
		Assert.Contains("brute-force", rules);
		Assert.Contains("password-spray", rules);
	}

	/**
	 * WHAT:   A success with no failures before it.
	 * WHY:    The most common event of all must never alert.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void SuccessWithoutFailures()
	{
		Assert.Empty(new SuccessAfterFailuresRule().Evaluate([TestData.Success(0)], Settings));
	}

	/**
	 * WHAT:   Local failures from many accounts.
	 * WHY:    A shared PC with several users mistyping is not a distributed attack.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void LocalFailuresAreNotDistributed()
	{
		List<LogonEvent> events = Enumerable.Range(0, 10).Select(i => TestData.Failure(i * 5, "admin", "-")).ToList();
		Assert.Empty(new DistributedAttackRule().Evaluate(Detector.Prepare(events), Settings));
	}

	/**
	 * WHAT:   Account names with accents and spaces.
	 * WHY:    Real names are not only ASCII.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void UnicodeAccountNames()
	{
		List<LogonEvent> events = TestData.Failures(10, spacing: 5, user: "José Müller");
		Alert alert = Assert.Single(new BruteForceRule().Evaluate(Detector.Prepare(events), Settings));
		Assert.Contains("José Müller", alert.Summary);
	}

	/**
	 * WHAT:   100,000 events.
	 * WHY:    A busy server logs that many in a day; analysis must stay fast.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void LargeLogIsFast()
	{
		List<LogonEvent> events = Enumerable.Range(0, 100_000)
			.Select(i => i % 2 == 0
				? TestData.Success(i, $"user{i % 500}", $"192.0.2.{i % 250}")
				: TestData.Failure(i, $"user{i % 500}", $"192.0.2.{i % 250}"))
			.ToList();

		Stopwatch timer = Stopwatch.StartNew();
		Detector.Run(events, Settings);
		Assert.True(timer.Elapsed < TimeSpan.FromSeconds(2), $"took {timer.Elapsed}");
	}

	/**
	 * WHAT:   One source sending 100,000 failures in under 2 minutes.
	 * WHY:    A real brute force; the window holds thousands of events at once.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void HugeSingleBurstIsFast()
	{
		List<LogonEvent> events = Enumerable.Range(0, 100_000)
			.Select(i => TestData.Failure(i * 0.001, $"user{i % 1000}", "203.0.113.7"))
			.ToList();

		Stopwatch timer = Stopwatch.StartNew();
		List<Alert> alerts = Detector.Run(events, Settings);
		Assert.True(timer.Elapsed < TimeSpan.FromSeconds(2), $"took {timer.Elapsed}");
		Assert.Equal(100_000, alerts.Single(a => a.Rule == "brute-force").Attempts);
	}
}
