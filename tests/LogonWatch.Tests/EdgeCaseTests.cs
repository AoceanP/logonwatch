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
	/** WHAT: default settings. */
	private static readonly DetectionSettings Settings = new();

	/** WHAT: 10 failures exactly 5:00 apart first to last. WHY: the window is inclusive. */
	[Fact]
	public void WindowBoundaryIsInclusive()
	{
		List<LogonEvent> events = TestData.Failures(10, spacing: 300.0 / 9);
		Assert.Single(new BruteForceRule().Evaluate(Detector.Prepare(events), Settings));
	}

	/** WHAT: the same 10 failures one second wider. WHY: just outside the window must not fire. */
	[Fact]
	public void WindowBoundaryPlusOneSecond()
	{
		List<LogonEvent> events = TestData.Failures(9, spacing: 300.0 / 8);
		events.Add(TestData.Failure(301));
		Assert.Empty(new BruteForceRule().Evaluate(Detector.Prepare(events), Settings));
	}

	/** WHAT: 10 failures with the same timestamp. WHY: logs record to the millisecond; bursts can share one. */
	[Fact]
	public void IdenticalTimestamps()
	{
		List<LogonEvent> events = TestData.Failures(10, spacing: 0);
		Assert.Equal(10, Assert.Single(new BruteForceRule().Evaluate(Detector.Prepare(events), Settings)).Attempts);
	}

	/** WHAT: no events at all. WHY: an empty log is normal and must give no alerts, not an error. */
	[Fact]
	public void EmptyInput()
	{
		Assert.Empty(Detector.Run([], Settings));
	}

	/** WHAT: only successful logons. WHY: a quiet, healthy log. */
	[Fact]
	public void OnlySuccesses()
	{
		Assert.Empty(Detector.Run(Enumerable.Range(0, 50).Select(i => TestData.Success(i * 10, "alice")), Settings));
	}

	/** WHAT: the same IPv6 source in upper and lower case. WHY: "2001:DB8::1" and "2001:db8::1" are one address. */
	[Fact]
	public void SourcesIgnoreCase()
	{
		List<LogonEvent> events = TestData.Failures(5, spacing: 5, source: "2001:DB8::1");
		events.AddRange(TestData.Failures(5, spacing: 5, first: 30, source: "2001:db8::1"));
		Assert.Single(new BruteForceRule().Evaluate(Detector.Prepare(events), Settings));
	}

	/** WHAT: one source both brute-forcing and spraying. WHY: both patterns are real, so both rules report. */
	[Fact]
	public void OneSourceCanTriggerTwoRules()
	{
		string[] users = ["admin", "backup", "sql", "guest", "test", "web", "ftp", "oracle", "root", "user"];
		List<LogonEvent> events = users.Select((user, i) => TestData.Failure(i * 5, user, "198.51.100.23")).ToList();
		List<string> rules = Detector.Run(events, Settings).Select(a => a.Rule).ToList();
		Assert.Contains("brute-force", rules);
		Assert.Contains("password-spray", rules);
	}

	/** WHAT: a success with no failures before it. WHY: the most common event of all must never alert. */
	[Fact]
	public void SuccessWithoutFailures()
	{
		Assert.Empty(new SuccessAfterFailuresRule().Evaluate([TestData.Success(0)], Settings));
	}

	/** WHAT: local failures from many accounts. WHY: a shared PC with several users mistyping is not a distributed attack. */
	[Fact]
	public void LocalFailuresAreNotDistributed()
	{
		List<LogonEvent> events = Enumerable.Range(0, 10).Select(i => TestData.Failure(i * 5, "admin", "-")).ToList();
		Assert.Empty(new DistributedAttackRule().Evaluate(Detector.Prepare(events), Settings));
	}

	/** WHAT: account names with accents and spaces. WHY: real names are not only ASCII. */
	[Fact]
	public void UnicodeAccountNames()
	{
		List<LogonEvent> events = TestData.Failures(10, spacing: 5, user: "José Müller");
		Alert alert = Assert.Single(new BruteForceRule().Evaluate(Detector.Prepare(events), Settings));
		Assert.Contains("José Müller", alert.Summary);
	}

	/** WHAT: 100,000 events. WHY: a busy server logs that many in a day; analysis must stay fast. */
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

	/** WHAT: one source sending 100,000 failures in under 2 minutes. WHY: a real brute force; the window holds thousands of events at once. */
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
