using System.Diagnostics.Eventing.Reader;
using System.Runtime.Versioning;
using LogonWatch.Model;
using LogonWatch.Parsing;

namespace LogonWatch.Sources;

/**
 * <summary>
 * WHAT:   Reads logon events from the live Windows Security log, or from an
 *         exported .evtx file.
 * WHY:    The live log is where real attacks show up; .evtx files let you
 *         analyse a log copied from another machine, without admin rights.
 *         An XPath query makes Windows return only events 4624 and 4625,
 *         instead of every event in the log.
 * </summary>
 * <param name="filePath">an .evtx file to read, or null for the live Security log</param>
 * <param name="since">only read events newer than this, or null for all</param>
 */
[SupportedOSPlatform("windows")]
public sealed class WindowsEventLogSource(string? filePath, DateTimeOffset? since) : ILogonEventSource
{
	/** <inheritdoc /> */
	public string Description => filePath is null ? "Windows Security log" : Path.GetFileName(filePath);

	/**
	 * <summary>
	 * WHAT:   Reads the matching events.
	 * WHY:    Reading the live Security log needs administrator rights;
	 *         the error says so instead of showing an access exception.
	 * THROWS: SourceException with a message the user can act on
	 * RETURN: the logon events, oldest first
	 * </summary>
	 * <returns>the events</returns>
	 * <exception cref="SourceException">the log or file cannot be read</exception>
	 */
	public IEnumerable<LogonEvent> Read()
	{
		EventLogReader reader = Open();
		using (reader)
		{
			while (true)
			{
				EventRecord? record;
				try
				{
					record = reader.ReadEvent();
				}
				catch (EventLogException e)
				{
					throw new SourceException($"could not read {Description}: {e.Message}", e);
				}
				if (record is null)
				{
					yield break;
				}

				LogonEvent? logon;
				using (record)
				{
					logon = SecurityEventParser.Parse(record.ToXml());
				}
				if (logon is not null)
				{
					yield return logon;
				}
			}
		}
	}

	/**
	 * <summary>
	 * WHAT:   Builds the query and opens the log or file.
	 * THROWS: SourceException if there is no permission or the file is missing
	 * RETURN: the open reader
	 * </summary>
	 * <returns>the reader</returns>
	 * <exception cref="SourceException">the log or file cannot be opened</exception>
	 */
	private EventLogReader Open()
	{
		string condition = "EventID=4624 or EventID=4625";
		if (since is not null)
		{
			// timediff is in milliseconds from now; Windows filters before sending events
			long milliseconds = (long)Math.Max(0, (DateTimeOffset.UtcNow - since.Value).TotalMilliseconds);
			condition = $"({condition}) and TimeCreated[timediff(@SystemTime) <= {milliseconds}]";
		}
		string query = $"*[System[{condition}]]";

		try
		{
			EventLogQuery logQuery = filePath is null
				? new EventLogQuery("Security", PathType.LogName, query)
				: new EventLogQuery(filePath, PathType.FilePath, query);
			return new EventLogReader(logQuery);
		}
		catch (UnauthorizedAccessException e) when (filePath is null)
		{
			throw new SourceException(
				"reading the Security log needs administrator rights: open the terminal with "
				+ "\"Run as administrator\", or try --demo", e);
		}
		catch (UnauthorizedAccessException e)
		{
			throw new SourceException(
				$"no permission to read {filePath}: Windows locks its own log files, so export a copy "
				+ "(Event Viewer, \"Save All Events As\") and read that, or run as administrator", e);
		}
		catch (EventLogNotFoundException e)
		{
			throw new SourceException($"could not find {filePath ?? "the Security log"}: {e.Message}", e);
		}
		catch (EventLogException e)
		{
			throw new SourceException($"could not open {Description}: {e.Message}", e);
		}
	}
}
