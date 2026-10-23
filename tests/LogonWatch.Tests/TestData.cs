using LogonWatch.Model;

namespace LogonWatch.Tests;

/**
 * WHAT:   Builders for test events and real Windows event XML.
 * WHY:    Tests read like the attack they describe ("60 failures from
 *         203.0.113.7") instead of walls of constructor arguments. Every
 *         address is from the documentation ranges (RFC 5737).
 */
internal static class TestData
{
	/** WHAT: a fixed start time, so tests never depend on the clock. */
	public static readonly DateTimeOffset Start = new(2026, 10, 21, 10, 0, 0, TimeSpan.Zero);

	/**
	 * WHAT:   A failed network logon, seconds after Start.
	 * RETURN: the event
	 */
	public static LogonEvent Failure(double seconds, string user = "administrator", string source = "203.0.113.7",
		int logonType = 3) =>
		new(Start.AddSeconds(seconds), LogonOutcome.Failure, user, "WORKSTATION", source, logonType, "wrong password");

	/**
	 * WHAT:   A successful network logon, seconds after Start.
	 * RETURN: the event
	 */
	public static LogonEvent Success(double seconds, string user = "administrator", string source = "203.0.113.7",
		int logonType = 3) =>
		new(Start.AddSeconds(seconds), LogonOutcome.Success, user, "WORKSTATION", source, logonType, "");

	/**
	 * WHAT:   count failures from one source, spacing seconds apart, starting at first.
	 * RETURN: the events
	 */
	public static List<LogonEvent> Failures(int count, double spacing, double first = 0, string user = "administrator",
		string source = "203.0.113.7") =>
		Enumerable.Range(0, count).Select(i => Failure(first + i * spacing, user, source)).ToList();

	/**
	 * WHAT:   A real event 4625, in the exact XML layout Windows produces.
	 * WHY:    The parser is tested against what EventRecord.ToXml() returns,
	 *         including the namespace and the Data elements Windows writes.
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
