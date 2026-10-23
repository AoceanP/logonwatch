using LogonWatch.Cli;
using LogonWatch.Detection;
using LogonWatch.Model;
using LogonWatch.Reporting;
using LogonWatch.Sources;

namespace LogonWatch.Tests;

/**
 * WHAT:   Tests for everything around the rules: the detector, sources,
 *         redaction, reports and the command line.
 * WHY:    The rules can be perfect and the tool still useless if input,
 *         output or the command line is wrong.
 */
public class PipelineTests
{
	/**
	 * WHAT:   The demo scenario.
	 * WHY:    It is the README example, so it must produce exactly these five alerts.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void DemoFiresEveryRuleOnce()
	{
		List<Alert> alerts = Detector.Run(new DemoSource().Read(), new DetectionSettings());

		Assert.Equal(new[] { "success-after-failures", "brute-force", "password-spray", "distributed-attack", "injection-attempt" },
			alerts.Select(a => a.Rule));
		Assert.Equal(Severity.Critical, alerts[0].Severity);
	}

	/**
	 * WHAT:   Computer accounts, SYSTEM and service logons.
	 * WHY:    They log on all day and are not people.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void DetectorIgnoresServiceAccounts()
	{
		List<LogonEvent> events =
		[
			TestData.Success(0, "DESKTOP-7$"),
			TestData.Success(1, "SYSTEM"),
			TestData.Success(2, "svc-backup", logonType: 5),
			TestData.Success(3, "alice"),
		];
		Assert.Equal(new[] { "alice" }, Detector.Prepare(events).Select(e => e.User));
	}

	/**
	 * WHAT:   Events in reverse order.
	 * WHY:    Combined logs are not sorted; the detector must sort them.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void DetectorSortsEvents()
	{
		List<LogonEvent> events = TestData.Failures(10, spacing: 10);
		events.Reverse();
		Assert.Single(Detector.Run(events, new DetectionSettings()));
	}

	/**
	 * WHAT:   A threshold of 1.
	 * WHY:    It would turn every typo into an alert, so it is refused.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void DetectorRejectsBadSettings()
	{
		Assert.Throws<ArgumentException>(() => Detector.Run([], new DetectionSettings { BruteForceThreshold = 1 }));
	}

	/**
	 * WHAT:   A JSON-lines file with comments and a blank line.
	 * WHY:    The documented file format.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void JsonLinesReadsEvents()
	{
		const string text = """
			# a comment
			{"time":"2026-10-21T10:00:00Z","outcome":"failure","user":"admin","source":"203.0.113.7"}

			{"time":"2026-10-21T10:00:05Z","outcome":"success","user":"admin","source":"203.0.113.7","logonType":10}
			""";
		List<LogonEvent> events = new JsonLinesSource(new StringReader(text), "test").Read().ToList();

		Assert.Equal(2, events.Count);
		Assert.Equal(LogonOutcome.Failure, events[0].Outcome);
		Assert.Equal(3, events[0].LogonType);
		Assert.Equal(10, events[1].LogonType);
	}

	/**
	 * WHAT:   Bad lines.
	 * WHY:    The error must name the line, not silently skip data that might hide an attack.
	 * PRE:    the parameters come from the InlineData rows below
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Theory]
	[InlineData("{not json", "line 1: not valid JSON")]
	[InlineData("{\"time\":\"2026-10-21T10:00:00Z\",\"outcome\":\"failure\"}", "line 1: \"time\", \"user\" and \"source\" are required")]
	[InlineData("{\"time\":\"yesterday\",\"outcome\":\"failure\",\"user\":\"a\",\"source\":\"b\"}", "is not a date and time")]
	[InlineData("{\"time\":\"2026-10-21T10:00:00Z\",\"outcome\":\"maybe\",\"user\":\"a\",\"source\":\"b\"}", "must be \"success\" or \"failure\"")]
	public void JsonLinesReportsBadLines(string line, string expected)
	{
		SourceException error = Assert.Throws<SourceException>(
			() => new JsonLinesSource(new StringReader(line), "test").Read().ToList());
		Assert.Contains(expected, error.Message);
	}

	/**
	 * WHAT:   A missing file.
	 * WHY:    A clear message, not a stack trace.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void JsonLinesMissingFile()
	{
		Assert.Throws<SourceException>(() => JsonLinesSource.FromFile("no-such-file.jsonl"));
	}

	/**
	 * WHAT:   Redaction.
	 * WHY:    The same name always gets the same placeholder, and local stays local.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void RedactorIsConsistent()
	{
		Redactor redactor = new();
		LogonEvent first = redactor.Redact(TestData.Failure(0, "Alice", "203.0.113.7"));
		LogonEvent second = redactor.Redact(TestData.Failure(1, "alice", "203.0.113.7"));
		LogonEvent other = redactor.Redact(TestData.Failure(2, "bob", "-"));

		Assert.Equal("user-1", first.User);
		Assert.Equal("user-1", second.User);
		Assert.Equal("ip-1", first.Source);
		Assert.Equal("user-2", other.User);
		Assert.Equal("-", other.Source);
	}

	/**
	 * WHAT:   The text report.
	 * WHY:    Alerts first, then the top sources, with "this machine" for local.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void TextReportShowsAlertsAndSources()
	{
		List<LogonEvent> events = TestData.Failures(10, spacing: 5);
		events.Add(TestData.Failure(100, "bob", "-"));
		Report report = Report.Build("test", events, Detector.Run(events, new DetectionSettings()));
		StringWriter output = new();
		ReportWriter.WriteText(report, output);
		string text = output.ToString();

		Assert.Contains("11 logon events from test (11 failed, 0 successful)", text);
		Assert.Contains("[MEDIUM] brute-force", text);
		Assert.Contains("this machine", text);
		Assert.True(text.IndexOf("brute-force", StringComparison.Ordinal) < text.IndexOf("Most failed", StringComparison.Ordinal));
	}

	/**
	 * WHAT:   The JSON report.
	 * WHY:    Severities as words, so scripts can read "Critical" instead of 3.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void JsonReportUsesWords()
	{
		List<Alert> alerts = Detector.Run(new DemoSource().Read(), new DetectionSettings());
		StringWriter output = new();
		ReportWriter.WriteJson(Report.Build("demo", [], alerts), output);
		Assert.Contains("\"severity\": \"Critical\"", output.ToString());
	}

	/**
	 * WHAT:   Durations.
	 * WHY:    "30s", "5m", "24h", "7d" are the documented forms.
	 * PRE:    the parameters come from the InlineData rows below
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Theory]
	[InlineData("30s", 30)]
	[InlineData("5m", 300)]
	[InlineData("24h", 86400)]
	[InlineData("7D", 604800)]
	public void ParsesDurations(string text, int seconds)
	{
		Assert.Equal(TimeSpan.FromSeconds(seconds), OptionsParser.ParseDuration(text, "--since"));
	}

	/**
	 * WHAT:   Bad durations.
	 * WHY:    Zero, negative, no unit or an unknown unit must be refused.
	 * PRE:    the parameters come from the InlineData rows below
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Theory]
	[InlineData("0m")]
	[InlineData("-5m")]
	[InlineData("5")]
	[InlineData("5w")]
	[InlineData("m")]
	public void RejectsBadDurations(string text)
	{
		Assert.Throws<UsageException>(() => OptionsParser.ParseDuration(text, "--since"));
	}

	/**
	 * WHAT:   Bad command lines.
	 * WHY:    Each must give exit code 2 and a message naming the problem.
	 * PRE:    the parameters come from the InlineData rows below
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Theory]
	[InlineData(new[] { "--demo", "--live" }, "choose only one input")]
	[InlineData(new[] { "--json" }, "choose an input")]
	[InlineData(new[] { "--file" }, "--file needs a value")]
	[InlineData(new[] { "--demo", "--threshold", "1" }, "must be at least 2")]
	[InlineData(new[] { "--demo", "--threshold", "abc" }, "needs a whole number")]
	[InlineData(new[] { "--demo", "--bogus" }, "unknown option --bogus")]
	public void BadCommandLinesExitWithTwo(string[] args, string expected)
	{
		StringWriter output = new();
		StringWriter error = new();
		Assert.Equal(Program.BadUsage, Program.Run(args, output, error));
		Assert.Contains(expected, error.ToString());
	}

	/**
	 * WHAT:   The whole program on the demo.
	 * WHY:    Exit code 3 means alerts were found.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void ProgramExitCodeShowsAlerts()
	{
		StringWriter output = new();
		Assert.Equal(Program.AlertsFound, Program.Run(["--demo"], output, new StringWriter()));
		Assert.Contains("[CRITICAL] success-after-failures", output.ToString());
	}

	/**
	 * WHAT:   A quiet log.
	 * WHY:    Exit code 0 and a clear "no attacks" line.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void ProgramExitCodeWhenQuiet()
	{
		string path = Path.Combine(Path.GetTempPath(), $"logonwatch-test-{Guid.NewGuid():N}.jsonl");
		File.WriteAllText(path, "{\"time\":\"2026-10-21T10:00:00Z\",\"outcome\":\"success\",\"user\":\"alice\",\"source\":\"192.0.2.10\"}\n");
		try
		{
			StringWriter output = new();
			Assert.Equal(Program.NoAlerts, Program.Run(["--jsonl", path], output, new StringWriter()));
			Assert.Contains("No attacks found.", output.ToString());
		}
		finally
		{
			File.Delete(path);
		}
	}

	/**
	 * WHAT:   --help and no arguments.
	 * WHY:    Both print the usage and succeed.
	 * PRE:    the parameters come from the InlineData rows below
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Theory]
	[InlineData("")]
	[InlineData("--help")]
	public void HelpPrintsUsage(string argument)
	{
		string[] args = argument.Length == 0 ? [] : [argument];
		StringWriter output = new();
		Assert.Equal(Program.NoAlerts, Program.Run(args, output, new StringWriter()));
		Assert.Contains("usage: logonwatch", output.ToString());
	}
}
