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
	/** <summary>WHAT: the XML namespace every Windows event uses.</summary> */
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
	 *         or username guessing; "wrong password" of brute force.
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
	 * RETURN: the logon event, or null if the XML is malformed, from another
	 *         provider, another event ID, or missing its time or user
	 * </summary>
	 * <param name="xml">the event XML</param>
	 * <returns>the parsed event, or null</returns>
	 */
	public static LogonEvent? Parse(string xml)
	{
		XDocument document;
		try
		{
			document = XDocument.Parse(xml);
		}
		catch (XmlException)
		{
			return null;
		}

		XElement? system = document.Root?.Element(EventNamespace + "System");
		if (system is null)
		{
			return null;
		}

		string? provider = system.Element(EventNamespace + "Provider")?.Attribute("Name")?.Value;
		string? eventId = system.Element(EventNamespace + "EventID")?.Value;
		string? systemTime = system.Element(EventNamespace + "TimeCreated")?.Attribute("SystemTime")?.Value;
		if (provider != AuditingProvider || systemTime is null)
		{
			return null;
		}

		LogonOutcome outcome;
		switch (eventId)
		{
			case "4624": outcome = LogonOutcome.Success; break;
			case "4625": outcome = LogonOutcome.Failure; break;
			default: return null;
		}

		if (!DateTimeOffset.TryParse(systemTime, CultureInfo.InvariantCulture,
			DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out DateTimeOffset time))
		{
			return null;
		}

		// EventData holds <Data Name="TargetUserName">admin</Data> and so on
		Dictionary<string, string> data = new(StringComparer.Ordinal);
		foreach (XElement item in document.Root!.Element(EventNamespace + "EventData")?.Elements(EventNamespace + "Data") ?? [])
		{
			string? name = item.Attribute("Name")?.Value;
			if (name is not null)
			{
				data[name] = item.Value.Trim();
			}
		}

		string user = data.GetValueOrDefault("TargetUserName", "");
		if (user.Length == 0 || user == "-")
		{
			return null;
		}

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
	 *         SubStatus is 0x0.
	 * RETURN: the readable reason, or the raw code if it is not known
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
