using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using LogonWatch.Model;

namespace LogonWatch.Reporting;

/**
 * <summary>
 * WHAT:   Prints a report as readable text or as JSON.
 * WHY:    Text is for people; JSON is for scripts, SIEMs and dashboards.
 * </summary>
 */
public static class ReportWriter
{
	/**
	 * <summary>
	 * WHAT:   Indented camelCase JSON with enums as words ("Critical", not 3).
	 * WHY:    Readable by people and stable for scripts: a new Severity value
	 *         would not shift the numbers of existing ones.
	 * </summary>
	 */
	private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
	{
		WriteIndented = true,
		Converters = { new JsonStringEnumConverter() },
	};

	/**
	 * <summary>
	 * WHAT:   Writes the report as text: a summary, the alerts, then the top sources.
	 * WHY:    Alerts come first because they are what someone reading this
	 *         at 3 a.m. needs; times are UTC so reports from different
	 *         machines line up.
	 * PRE:    report and output are not null
	 * POST:   the text is written to output
	 * RETURN: nothing
	 * </summary>
	 * <param name="report">the report</param>
	 * <param name="output">where to write</param>
	 */
	public static void WriteText(Report report, TextWriter output)
	{
		// 1. one line saying what was read
		output.WriteLine($"logonwatch: {report.Events} logon events from {report.Input} "
			+ $"({report.Failures} failed, {report.Successes} successful)");
		output.WriteLine();

		// 2. the alerts, already sorted most severe first
		if (report.Alerts.Count == 0)
		{
			output.WriteLine("No attacks found.");
		}
		else
		{
			output.WriteLine($"{report.Alerts.Count} alert{(report.Alerts.Count == 1 ? "" : "s")}:");
			foreach (Alert alert in report.Alerts)
			{
				output.WriteLine();
				output.WriteLine($"  [{alert.Severity.ToString().ToUpperInvariant()}] {alert.Rule}");
				output.WriteLine($"    {alert.Summary}");
				output.WriteLine($"    from {Time(alert.First)} to {Time(alert.Last)} UTC");
			}
		}

		// 3. the noisiest sources, even when no rule fired, for a quick sense of the log
		if (report.TopSources.Count > 0)
		{
			output.WriteLine();
			output.WriteLine("Most failed logons by source:");
			foreach (SourceCount item in report.TopSources)
			{
				output.WriteLine($"  {item.Failures,6}  {(item.Source == "-" ? "this machine" : item.Source)}");
			}
		}
	}

	/**
	 * <summary>
	 * WHAT:   Writes the report as JSON.
	 * WHY:    Lets other tools (a SIEM, a dashboard, a script) use the results.
	 * PRE:    report and output are not null
	 * POST:   the JSON is written to output
	 * RETURN: nothing
	 * </summary>
	 * <param name="report">the report</param>
	 * <param name="output">where to write</param>
	 */
	public static void WriteJson(Report report, TextWriter output)
	{
		output.WriteLine(JsonSerializer.Serialize(report, JsonOptions));
	}

	/**
	 * <summary>
	 * WHAT:   Formats a time as "2026-10-21 10:01:03".
	 * WHY:    Sortable, unambiguous in every country, and always UTC.
	 * PRE:    none
	 * RETURN: the time in UTC
	 * </summary>
	 * <param name="time">the time</param>
	 * <returns>the formatted time</returns>
	 */
	private static string Time(DateTimeOffset time) =>
		time.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
}
