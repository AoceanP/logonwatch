using System.Globalization;
using System.Text.Json;
using LogonWatch.Model;

namespace LogonWatch.Sources;

/**
 * <summary>
 * WHAT:   Reads logon events from a JSON-lines file: one JSON object per line.
 * WHY:    Lets the detector run on any machine and on data from other
 *         systems (exported from a SIEM, or a Linux auth log converted to
 *         JSON), and makes the demo possible without admin rights.
 *         Blank lines and lines starting with '#' are skipped.
 * </summary>
 * <example>
 * {"time":"2026-10-21T10:01:03Z","outcome":"failure","user":"admin","source":"203.0.113.7","logonType":3,"reason":"wrong password"}
 * </example>
 * <param name="reader">the text to read</param>
 * <param name="name">the file or resource name, used in messages</param>
 */
public sealed class JsonLinesSource(TextReader reader, string name) : ILogonEventSource
{
	/** <summary>WHAT: matches the JSON field names in camelCase.</summary> */
	private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web);

	/** <inheritdoc /> */
	public string Description => name;

	/**
	 * <summary>
	 * WHAT:   Opens a JSON-lines file.
	 * THROWS: SourceException if the file cannot be opened
	 * RETURN: a source reading that file
	 * </summary>
	 * <param name="path">the file path</param>
	 * <returns>the source</returns>
	 * <exception cref="SourceException">the file is missing or unreadable</exception>
	 */
	public static JsonLinesSource FromFile(string path)
	{
		try
		{
			return new JsonLinesSource(new StreamReader(path), Path.GetFileName(path));
		}
		catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException)
		{
			throw new SourceException($"could not open {path}: {e.Message}", e);
		}
	}

	/**
	 * <summary>
	 * WHAT:   Reads every event in the file.
	 * WHY:    A bad line stops the read with its line number, instead of
	 *         silently skipping data that might hide an attack.
	 * THROWS: SourceException naming the bad line
	 * RETURN: the events, in file order
	 * </summary>
	 * <returns>the events</returns>
	 * <exception cref="SourceException">a line is not a valid event</exception>
	 */
	public IEnumerable<LogonEvent> Read()
	{
		using (reader)
		{
			int number = 0;
			for (string? line = reader.ReadLine(); line is not null; line = reader.ReadLine())
			{
				number++;
				string trimmed = line.Trim();
				if (trimmed.Length == 0 || trimmed.StartsWith('#'))
				{
					continue;
				}
				yield return ParseLine(trimmed, number);
			}
		}
	}

	/**
	 * <summary>
	 * WHAT:   Turns one line into an event.
	 * THROWS: SourceException with the line number
	 * RETURN: the event
	 * </summary>
	 * <param name="line">the JSON text</param>
	 * <param name="number">the line number, for messages</param>
	 * <returns>the event</returns>
	 * <exception cref="SourceException">the line is not a valid event</exception>
	 */
	private LogonEvent ParseLine(string line, int number)
	{
		JsonLine? item;
		try
		{
			item = JsonSerializer.Deserialize<JsonLine>(line, Options);
		}
		catch (JsonException e)
		{
			throw new SourceException($"{name} line {number}: not valid JSON ({e.Message})", e);
		}

		if (item?.Time is null || string.IsNullOrWhiteSpace(item.User) || string.IsNullOrWhiteSpace(item.Source))
		{
			throw new SourceException($"{name} line {number}: \"time\", \"user\" and \"source\" are required");
		}
		if (!DateTimeOffset.TryParse(item.Time, CultureInfo.InvariantCulture,
			DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out DateTimeOffset time))
		{
			throw new SourceException($"{name} line {number}: \"{item.Time}\" is not a date and time");
		}

		LogonOutcome outcome = item.Outcome?.ToLowerInvariant() switch
		{
			"success" => LogonOutcome.Success,
			"failure" => LogonOutcome.Failure,
			_ => throw new SourceException($"{name} line {number}: \"outcome\" must be \"success\" or \"failure\""),
		};

		return new LogonEvent(time, outcome, item.User.Trim(), item.Domain ?? "-", item.Source.Trim(),
			item.LogonType ?? 3, outcome == LogonOutcome.Failure ? item.Reason ?? "unknown" : "");
	}

	/**
	 * <summary>
	 * WHAT:   The shape of one JSON line.
	 * </summary>
	 * <param name="Time">ISO 8601 time, e.g. "2026-10-21T10:01:03Z"</param>
	 * <param name="Outcome">"success" or "failure"</param>
	 * <param name="User">the account name</param>
	 * <param name="Domain">the domain, optional</param>
	 * <param name="Source">the source IP address, or "-" for local</param>
	 * <param name="LogonType">the Windows logon type, optional (default 3, network)</param>
	 * <param name="Reason">why a failure happened, optional</param>
	 */
	private sealed record JsonLine(string? Time, string? Outcome, string? User, string? Domain, string? Source,
		int? LogonType, string? Reason);
}
