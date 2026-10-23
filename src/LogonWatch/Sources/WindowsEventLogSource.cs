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
 * PRE:    runs on Windows (the event log API only exists there)
 * </summary>
 * <param name="filePath">an .evtx file to read, or null for the live Security log</param>
 * <param name="since">only read events newer than this, or null for all</param>
 */
[SupportedOSPlatform("windows")]
public sealed class WindowsEventLogSource(string? filePath, DateTimeOffset? since) : ILogonEventSource
{
	/**
	 * <summary>
	 * WHAT:   "Windows Security log", or the .evtx file's name.
	 * WHY:    Shown in the report and in error messages.
	 * PRE:    none
	 * RETURN: the description
	 * </summary>
	 */
	public string Description => filePath is null ? "Windows Security log" : Path.GetFileName(filePath);

	/**
	 * <summary>
	 * WHAT:   Reads the matching events.
	 * WHY:    Each record is disposed as soon as it is parsed, so even a
	 *         very large log is read with little memory.
	 * PRE:    none
	 * POST:   the log or file handle is closed
	 * RETURN: the logon events, oldest first
	 * THROWS: SourceException with a message the user can act on
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
				// 1. get the next record; null means the end of the log
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

				// 2. turn it into XML and parse it; free the record straight away
				LogonEvent? logon;
				using (record)
				{
					logon = SecurityEventParser.Parse(record.ToXml());
				}

				// 3. the parser returns null for anything that is not a trusted logon event
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
	 * WHY:    Each way opening can fail gets its own message: missing admin
	 *         rights for the live log, a locked file, or a missing file.
	 * PRE:    none
	 * RETURN: the open reader
	 * THROWS: SourceException if there is no permission or the file is missing
	 * </summary>
	 * <returns>the reader</returns>
	 * <exception cref="SourceException">the log or file cannot be opened</exception>
	 */
	private EventLogReader Open()
	{
		// 1. XPath filter: only logon events, and with --since only recent ones.
		//    timediff(@SystemTime) is "milliseconds ago", so Windows filters before sending anything.
		string condition = "EventID=4624 or EventID=4625";
		if (since is not null)
		{
			long milliseconds = (long)Math.Max(0, (DateTimeOffset.UtcNow - since.Value).TotalMilliseconds);
			condition = $"({condition}) and TimeCreated[timediff(@SystemTime) <= {milliseconds}]";
		}
		string query = $"*[System[{condition}]]";

		// 2. open the live "Security" log by name, or the .evtx file by path
		try
		{
			EventLogQuery logQuery = filePath is null
				? new EventLogQuery("Security", PathType.LogName, query)
				: new EventLogQuery(filePath, PathType.FilePath, query);
			return new EventLogReader(logQuery);
		}
		catch (UnauthorizedAccessException e) when (filePath is null)
		{
			// the live Security log is readable by administrators only
			throw new SourceException(
				"reading the Security log needs administrator rights: open the terminal with "
				+ "\"Run as administrator\", or try --demo", e);
		}
		catch (UnauthorizedAccessException e)
		{
			// Windows locks its own .evtx files while it writes to them
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
