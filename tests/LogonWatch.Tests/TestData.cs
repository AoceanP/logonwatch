using LogonWatch.Model;

namespace LogonWatch.Tests;

/**
 * WHAT:   Builders for test events and real Windows event XML.
 * WHY:    Tests read like the attack they describe ("60 failures from
 *         203.0.113.7") instead of walls of constructor arguments. Every
 *         address is from the documentation ranges (RFC 5737), so all test
 *         data is fake.
 */
internal static class TestData
{
	/**
	 * WHAT:   A fixed start time: 2026-10-21 10:00:00 UTC.
	 * WHY:    Tests never depend on the clock, so they give the same result
	 *         every time they run.
	 */
	public static readonly DateTimeOffset Start = new(2026, 10, 21, 10, 0, 0, TimeSpan.Zero);

	/**
	 * WHAT:   A failed network logon, a number of seconds after Start.
	 * WHY:    The most common event in every test; defaults describe a
	 *         typical attack on "administrator" from 203.0.113.7.
	 * PRE:    seconds is zero or more
	 * RETURN: the event
	 */
	public static LogonEvent Failure(double seconds, string user = "administrator", string source = "203.0.113.7",
		int logonType = 3) =>
		new(Start.AddSeconds(seconds), LogonOutcome.Failure, user, "WORKSTATION", source, logonType, "wrong password");

	/**
	 * WHAT:   A successful network logon, a number of seconds after Start.
	 * WHY:    Used to finish an attack ("and then it worked") or as normal activity.
	 * PRE:    seconds is zero or more
	 * RETURN: the event
	 */
	public static LogonEvent Success(double seconds, string user = "administrator", string source = "203.0.113.7",
		int logonType = 3) =>
		new(Start.AddSeconds(seconds), LogonOutcome.Success, user, "WORKSTATION", source, logonType, "");

	/**
	 * WHAT:   A run of failures from one source, evenly spaced.
	 * WHY:    "10 failures, 30 seconds apart" is one line instead of ten.
	 * PRE:    count is zero or more; spacing and first are zero or more
	 * RETURN: count failures, the first at `first` seconds, then every
	 *         `spacing` seconds
	 */
	public static List<LogonEvent> Failures(int count, double spacing, double first = 0, string user = "administrator",
		string source = "203.0.113.7") =>
		Enumerable.Range(0, count).Select(i => Failure(first + i * spacing, user, source)).ToList();

	/**
	 * WHAT:   A real event 4625, in the exact XML layout Windows produces.
	 * WHY:    The parser is tested against what EventRecord.ToXml() returns,
	 *         including the namespace and the Data elements Windows writes;
	 *         each argument changes one field to build a variation.
	 * PRE:    none
	 * RETURN: the XML
	 */
	public static string FailureXml(string user = "administrator", string ip = "203.0.113.7",
		string subStatus = "0xc000006a", string provider = "Microsoft-Windows-Security-Auditing",
		string eventId = "4625") => $"""
		<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
		  <System>
		    <Provider Name="{provider}" Guid="{"{"}54849625-5478-4994-a5ba-3e3b0328c30d{"}"}" />
		    <EventID>{eventId}</EventID>
		    <Version>0</Version>
		    <Level>0</Level>
		    <Task>12544</Task>
		    <Keywords>0x8010000000000000</Keywords>
		    <TimeCreated SystemTime="2026-10-21T10:01:03.1234567Z" />
		    <EventRecordID>48211</EventRecordID>
		    <Channel>Security</Channel>
		    <Computer>WORKSTATION</Computer>
		  </System>
		  <EventData>
		    <Data Name="SubjectUserSid">S-1-0-0</Data>
		    <Data Name="SubjectUserName">-</Data>
		    <Data Name="TargetUserSid">S-1-0-0</Data>
		    <Data Name="TargetUserName">{user}</Data>
		    <Data Name="TargetDomainName">WORKSTATION</Data>
		    <Data Name="Status">0xc000006d</Data>
		    <Data Name="FailureReason">%%2313</Data>
		    <Data Name="SubStatus">{subStatus}</Data>
		    <Data Name="LogonType">10</Data>
		    <Data Name="LogonProcessName">User32</Data>
		    <Data Name="AuthenticationPackageName">Negotiate</Data>
		    <Data Name="WorkstationName">ATTACKER-PC</Data>
		    <Data Name="IpAddress">{ip}</Data>
		    <Data Name="IpPort">51234</Data>
		  </EventData>
		</Event>
		""";
}
