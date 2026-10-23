using LogonWatch.Model;
using LogonWatch.Parsing;

namespace LogonWatch.Tests;

/**
 * WHAT:   Tests for SecurityEventParser.
 * WHY:    Every input path ends here, so a parsing mistake would make the
 *         detector blind; real Windows XML is used throughout.
 */
public class ParserTests
{
	/** WHAT: a real 4625. WHY: every field the rules use must come out right. */
	[Fact]
	public void ParsesFailedLogon()
	{
		LogonEvent? logon = SecurityEventParser.Parse(TestData.FailureXml());

		Assert.NotNull(logon);
		Assert.Equal(LogonOutcome.Failure, logon.Outcome);
		Assert.Equal("administrator", logon.User);
		Assert.Equal("WORKSTATION", logon.Domain);
		Assert.Equal("203.0.113.7", logon.Source);
		Assert.Equal(10, logon.LogonType);
		Assert.Equal("wrong password", logon.Reason);
		Assert.Equal(new DateTimeOffset(2026, 10, 21, 10, 1, 3, TimeSpan.Zero), logon.Time.AddTicks(-1234567));
	}

	/** WHAT: a 4624. WHY: successes are what the most important rule looks for. */
	[Fact]
	public void ParsesSuccessfulLogon()
	{
		LogonEvent? logon = SecurityEventParser.Parse(TestData.FailureXml(eventId: "4624"));

		Assert.NotNull(logon);
		Assert.Equal(LogonOutcome.Success, logon.Outcome);
		Assert.Equal("", logon.Reason);
	}

	/** WHAT: SubStatus codes. WHY: "user does not exist" in bulk points to username guessing. */
	[Theory]
	[InlineData("0xc0000064", "user does not exist")]
	[InlineData("0xC000006A", "wrong password")]
	[InlineData("0xc0000234", "account locked out")]
	[InlineData("0xc0000072", "account disabled")]
	[InlineData("0xc0000999", "0xc0000999")]
	public void DescribesFailureReasons(string subStatus, string expected)
	{
		Assert.Equal(expected, SecurityEventParser.Parse(TestData.FailureXml(subStatus: subStatus))?.Reason);
	}

	/** WHAT: SubStatus 0x0. WHY: Windows then puts the reason in Status instead. */
	[Fact]
	public void FallsBackToStatus()
	{
		Assert.Equal("bad user name or password", SecurityEventParser.Parse(TestData.FailureXml(subStatus: "0x0"))?.Reason);
	}

	/** WHAT: other event IDs. WHY: only 4624 and 4625 are logons. */
	[Theory]
	[InlineData("4634")]
	[InlineData("4672")]
	[InlineData("1102")]
	public void IgnoresOtherEvents(string eventId)
	{
		Assert.Null(SecurityEventParser.Parse(TestData.FailureXml(eventId: eventId)));
	}

	/** WHAT: a 4625 from another provider. WHY: any program can write fake 4625s; only Windows auditing is trusted. */
	[Fact]
	public void IgnoresForgedProvider()
	{
		Assert.Null(SecurityEventParser.Parse(TestData.FailureXml(provider: "EvilApp")));
	}

	/** WHAT: IPv4 written as IPv6. WHY: "::ffff:203.0.113.7" and "203.0.113.7" are the same attacker. */
	[Fact]
	public void NormalizesIpv4MappedAddresses()
	{
		Assert.Equal("203.0.113.7", SecurityEventParser.Parse(TestData.FailureXml(ip: "::ffff:203.0.113.7"))?.Source);
		Assert.Equal("2001:db8::1", SecurityEventParser.NormalizeAddress("2001:db8::1"));
		Assert.Equal("-", SecurityEventParser.NormalizeAddress("   "));
	}

	/** WHAT: a logon with no IP address. WHY: keyboard logons have IpAddress "-" and count as local. */
	[Fact]
	public void LocalLogonHasNoAddress()
	{
		LogonEvent? logon = SecurityEventParser.Parse(TestData.FailureXml(ip: "-"));
		Assert.NotNull(logon);
		Assert.True(logon.IsLocal);
	}

	/** WHAT: broken or empty XML. WHY: one bad record must not stop a scan of the whole log. */
	[Theory]
	[InlineData("")]
	[InlineData("not xml")]
	[InlineData("<Event>")]
	[InlineData("<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"></Event>")]
	public void ReturnsNullForBadXml(string xml)
	{
		Assert.Null(SecurityEventParser.Parse(xml));
	}

	/** WHAT: an event without a target user. WHY: nothing can be attributed to it. */
	[Fact]
	public void IgnoresEventWithoutUser()
	{
		Assert.Null(SecurityEventParser.Parse(TestData.FailureXml(user: "-")));
	}
}
