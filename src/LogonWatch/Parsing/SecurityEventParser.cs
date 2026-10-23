using System.Globalization;
using System.Xml;
using System.Xml.Linq;
using LogonWatch.Model;

namespace LogonWatch.Parsing;

/**
 * <summary>
 * WHAT:   Turns the XML of a Windows Security event (4624 or 4625) into a LogonEvent.
 * WHY:    Every Windows event can be read as XML (EventRecord.ToXml), so
 *         parsing XML works the same for the live log, exported .evtx files
 *         and test data, and the parser can be tested without admin rights.
 * </summary>
 */
public static class SecurityEventParser
{
	/**
	 * <summary>
	 * WHAT:   The XML namespace every Windows event uses.
	 * WHY:    Element names in the event XML only match when this namespace
	 *         is added, e.g. EventNamespace + "System".
	 * </summary>
	 */
	private static readonly XNamespace EventNamespace = "http://schemas.microsoft.com/win/2004/08/events/event";

	/**
	 * <summary>
	 * WHAT:   The only provider whose 4624/4625 events are trusted.
	 * WHY:    Any program with the right permission can write events with
	 *         ID 4625 under its own name; only Windows' auditing subsystem
	 *         writes the real ones, so forged look-alikes are ignored.
	 * </summary>
	 */
	public const string AuditingProvider = "Microsoft-Windows-Security-Auditing";

	/**
	 * <summary>
	 * WHAT:   Readable reasons for the NTSTATUS codes in a failed logon.
	 * WHY:    "user does not exist" in bulk is the sign of password spraying
	 *         or username guessing; "wrong password" of brute force. The keys
	 *         ignore case because Windows writes both 0xC000006A and 0xc000006a.
	 * </summary>
	 */
	private static readonly Dictionary<string, string> FailureReasons = new(StringComparer.OrdinalIgnoreCase)
	{
		["0xc0000064"] = "user does not exist",
		["0xc000006a"] = "wrong password",
		["0xc000006d"] = "bad user name or password",
		["0xc000006f"] = "outside allowed logon hours",
		["0xc0000070"] = "workstation not allowed",
		["0xc0000071"] = "password expired",
		["0xc0000072"] = "account disabled",
		["0xc0000193"] = "account expired",
		["0xc0000224"] = "password must be changed",
		["0xc0000234"] = "account locked out",
		["0xc000015b"] = "logon type not granted",
	};

	/**
	 * <summary>
	 * WHAT:   Parses one event.
	 * WHY:    Returns null instead of throwing for anything that is not a
	 *         genuine logon event, so one odd record never stops a scan of a
	 *         whole log.
	 * PRE:    xml is the text of one event, as from EventRecord.ToXml()
	 * POST:   nothing is changed; the parser has no state
	 * RETURN: the logon event, or null if the XML is malformed, from another
	 *         provider, another event ID, or missing its time or user
	 * THROWS: nothing
	 * </summary>
	 * <param name="xml">the event XML</param>
	 * <returns>the parsed event, or null</returns>
	 */
	public static LogonEvent? Parse(string xml)
	{
		// 1. Load the XML. Broken XML means it is not an event at all.
		XDocument document;
		try
		{
			document = XDocument.Parse(xml);
		}
		catch (XmlException)
		{
			return null;
		}

		// 2. Every event has a <System> block with who wrote it, its ID and its time.
		XElement? system = document.Root?.Element(EventNamespace + "System");
		if (system is null)
		{
			return null;
		}

		string? provider = system.Element(EventNamespace + "Provider")?.Attribute("Name")?.Value;
		string? eventId = system.Element(EventNamespace + "EventID")?.Value;
		string? systemTime = system.Element(EventNamespace + "TimeCreated")?.Attribute("SystemTime")?.Value;

		// 3. Trust only Windows' own auditing provider, so a forged "4625" is ignored.
		if (provider != AuditingProvider || systemTime is null)
		{
			return null;
		}

		// 4. Only logon events matter: 4624 worked, 4625 failed. Everything else is skipped.
		LogonOutcome outcome;
		switch (eventId)
		{
			case "4624": outcome = LogonOutcome.Success; break;
			case "4625": outcome = LogonOutcome.Failure; break;
			default: return null;
		}

		// 5. SystemTime is ISO 8601 in UTC, e.g. 2026-10-21T10:01:03.1234567Z.
		if (!DateTimeOffset.TryParse(systemTime, CultureInfo.InvariantCulture,
			DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out DateTimeOffset time))
		{
			return null;
		}

		// 6. <EventData> holds named fields: <Data Name="TargetUserName">admin</Data> and so on.
		//    Collect them into a dictionary so each field can be looked up by name.
		Dictionary<string, string> data = new(StringComparer.Ordinal);
		foreach (XElement item in document.Root!.Element(EventNamespace + "EventData")?.Elements(EventNamespace + "Data") ?? [])
		{
			string? name = item.Attribute("Name")?.Value;
			if (name is not null)
			{
				data[name] = item.Value.Trim();
			}
		}

		// 7. An event that names no account cannot be attributed to anyone.
		string user = data.GetValueOrDefault("TargetUserName", "");
		if (user.Length == 0 || user == "-")
		{
			return null;
		}

		// 8. Build the event; a missing or unreadable logon type becomes 0 (unknown).
		int logonType = int.TryParse(data.GetValueOrDefault("LogonType"), out int type) ? type : 0;
		string reason = outcome == LogonOutcome.Failure ? DescribeFailure(data) : "";

		return new LogonEvent(time, outcome, user, data.GetValueOrDefault("TargetDomainName", "-"),
			NormalizeAddress(data.GetValueOrDefault("IpAddress", "-")), logonType, reason);
	}

	/**
	 * <summary>
	 * WHAT:   Cleans up the IpAddress field.
	 * WHY:    Windows writes IPv4 clients of an IPv6 socket as "::ffff:1.2.3.4";
	 *         without this, one attacker would look like two different sources.
	 * PRE:    address is not null
	 * RETURN: the plain address, or "-" when there is none
	 * </summary>
	 * <param name="address">the raw IpAddress value</param>
	 * <returns>the normalised address</returns>
	 */
	public static string NormalizeAddress(string address)
	{
		string trimmed = address.Trim();
		if (trimmed.Length == 0)
		{
			return "-";
		}

		// "::ffff:" followed by a dotted IPv4 address is an IPv4-mapped IPv6 address: keep the IPv4 part
		if (trimmed.StartsWith("::ffff:", StringComparison.OrdinalIgnoreCase) && trimmed.Contains('.'))
		{
			return trimmed["::ffff:".Length..];
		}
		return trimmed;
	}

	/**
	 * <summary>
	 * WHAT:   Turns a failure's status codes into words.
	 * WHY:    SubStatus is the precise reason; Status is the fallback when
	 *         SubStatus is 0x0 (Windows leaves it empty for some failures).
	 * PRE:    data holds the event's named fields
	 * RETURN: the readable reason, the raw code if it is not known, or
	 *         "unknown" if there is no code at all
	 * </summary>
	 * <param name="data">the event's named data fields</param>
	 * <returns>the reason text</returns>
	 */
	private static string DescribeFailure(Dictionary<string, string> data)
	{
		string subStatus = data.GetValueOrDefault("SubStatus", "");
		string code = subStatus is "" or "0x0" ? data.GetValueOrDefault("Status", "") : subStatus;
		return FailureReasons.TryGetValue(code, out string? reason) ? reason : code.Length > 0 ? code : "unknown";
	}
}
