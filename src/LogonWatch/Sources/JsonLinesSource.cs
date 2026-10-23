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
 * PRE:    reader is open and positioned at the start of the data
 * </summary>
 * <example>
 * {"time":"2026-10-21T10:01:03Z","outcome":"failure","user":"admin","source":"203.0.113.7","logonType":3,"reason":"wrong password"}
 * </example>
 * <param name="reader">the text to read</param>
 * <param name="name">the file or resource name, used in messages</param>
 */
public sealed class JsonLinesSource(TextReader reader, string name) : ILogonEventSource
{
	/**
	 * <summary>
	 * WHAT:   JSON settings for the web convention: camelCase names, case-insensitive.
	 * WHY:    Matches "logonType" in the file to LogonType in the record.
	 * </summary>
	 */
	private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web);

	/**
	 * <summary>
	 * WHAT:   The file or resource name.
	 * WHY:    Shown in the report and in error messages.
	 * PRE:    none
	 * RETURN: the name given to the constructor
	 * </summary>
	 */
	public string Description => name;

	/**
	 * <summary>
	 * WHAT:   Opens a JSON-lines file.
	 * WHY:    Turns the many ways opening a file can fail into one clear message.
	 * PRE:    path is not null
	 * POST:   the file is open; it is closed when Read finishes
	 * RETURN: a source reading that file
	 * THROWS: SourceException if the file cannot be opened
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
	 * PRE:    Read has not been called before (the reader is used up after one read)
	 * POST:   the reader is closed
	 * RETURN: the events, in file order
	 * THROWS: SourceException naming the bad line
	 * </summary>
	 * <returns>the events</returns>
	 * <exception cref="SourceException">a line is not a valid event</exception>
	 */
	public IEnumerable<LogonEvent> Read()
	{
		using (reader)
		{
			// count lines so an error can say exactly where the problem is
			int number = 0;
			for (string? line = reader.ReadLine(); line is not null; line = reader.ReadLine())
			{
				number++;
				string trimmed = line.Trim();

				// blank lines and # comments let people annotate their test files
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
	 * WHY:    Checks each required field separately so the error says which
	 *         one is missing or wrong.
	 * PRE:    line is not blank and not a comment
	 * RETURN: the event
	 * THROWS: SourceException with the line number
	 * </summary>
	 * <param name="line">the JSON text</param>
	 * <param name="number">the line number, for messages</param>
	 * <returns>the event</returns>
	 * <exception cref="SourceException">the line is not a valid event</exception>
	 */
	private LogonEvent ParseLine(string line, int number)
	{
		// 1. is it JSON at all?
		JsonLine? item;
		try
		{
			item = JsonSerializer.Deserialize<JsonLine>(line, Options);
		}
		catch (JsonException e)
		{
			throw new SourceException($"{name} line {number}: not valid JSON ({e.Message})", e);
		}

		// 2. the fields every event needs
		if (item?.Time is null || string.IsNullOrWhiteSpace(item.User) || string.IsNullOrWhiteSpace(item.Source))
		{
			throw new SourceException($"{name} line {number}: \"time\", \"user\" and \"source\" are required");
		}

		// 3. a real date and time; without a zone it is taken as UTC
		if (!DateTimeOffset.TryParse(item.Time, CultureInfo.InvariantCulture,
			DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out DateTimeOffset time))
		{
			throw new SourceException($"{name} line {number}: \"{item.Time}\" is not a date and time");
		}

		// 4. the outcome, in any letter case
		LogonOutcome outcome = item.Outcome?.ToLowerInvariant() switch
		{
			"success" => LogonOutcome.Success,
			"failure" => LogonOutcome.Failure,
			_ => throw new SourceException($"{name} line {number}: \"outcome\" must be \"success\" or \"failure\""),
		};

		// 5. optional fields get sensible defaults: domain "-", logon type 3 (network), reason "unknown"
		return new LogonEvent(time, outcome, item.User.Trim(), item.Domain ?? "-", item.Source.Trim(),
			item.LogonType ?? 3, outcome == LogonOutcome.Failure ? item.Reason ?? "unknown" : "");
	}

	/**
	 * <summary>
	 * WHAT:   The shape of one JSON line, with every field optional.
	 * WHY:    Optional (nullable) fields let ParseLine report which one is
	 *         missing instead of failing inside the JSON library.
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
