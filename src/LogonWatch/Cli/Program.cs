using System.Reflection;
using LogonWatch.Detection;
using LogonWatch.Model;
using LogonWatch.Reporting;
using LogonWatch.Sources;

namespace LogonWatch.Cli;

/**
 * <summary>
 * WHAT:   The command-line entry point.
 * WHY:    Run takes its output streams as parameters, so tests can run the
 *         whole program and check what it prints and its exit code.
 * </summary>
 */
internal static class Program
{
	/** <summary>WHAT: exit code when no alerts were found.</summary> */
	public const int NoAlerts = 0;

	/** <summary>WHAT: exit code when an input could not be read.</summary> */
	public const int Error = 1;

	/** <summary>WHAT: exit code for a bad command line.</summary> */
	public const int BadUsage = 2;

	/**
	 * <summary>
	 * WHAT:   Exit code when alerts were found.
	 * WHY:    Lets a scheduled task or script act on findings without
	 *         parsing the report.
	 * </summary>
	 */
	public const int AlertsFound = 3;

	/**
	 * <summary>
	 * WHAT:   Starts the program.
	 * RETURN: the exit code
	 * </summary>
	 * <param name="args">the command-line arguments</param>
	 * <returns>the exit code</returns>
	 */
	public static int Main(string[] args) => Run(args, Console.Out, Console.Error);

	/**
	 * <summary>
	 * WHAT:   Parses the arguments, reads the events, detects attacks and prints the report.
	 * WHY:    Nothing is written anywhere but output and error: logonwatch
	 *         only reads logs, never changes or stores them.
	 * RETURN: NoAlerts, AlertsFound, Error or BadUsage
	 * </summary>
	 * <param name="args">the command-line arguments</param>
	 * <param name="output">where the report goes</param>
	 * <param name="error">where error messages go</param>
	 * <returns>the exit code</returns>
	 */
	public static int Run(string[] args, TextWriter output, TextWriter error)
	{
		Options? options;
		try
		{
			options = OptionsParser.Parse(args, out bool showVersion);
			if (options is null)
			{
				output.Write(showVersion ? $"logonwatch {Version()}{Environment.NewLine}" : OptionsParser.Usage);
				return NoAlerts;
			}
		}
		catch (UsageException e)
		{
			error.WriteLine($"error: {e.Message}");
			error.WriteLine();
			error.Write(OptionsParser.Usage);
			return BadUsage;
		}

		try
		{
			ILogonEventSource source = CreateSource(options);
			List<LogonEvent> events = source.Read().ToList();

			// the demo is a fixed scenario from the past, so --since does not apply to it
			if (options.Since is not null && options.Input != InputKind.Demo)
			{
				DateTimeOffset cutoff = DateTimeOffset.UtcNow - options.Since.Value;
				events = events.Where(e => e.Time >= cutoff).ToList();
			}
			if (options.Redact)
			{
				Redactor redactor = new();
				events = events.Select(redactor.Redact).ToList();
			}

			List<LogonEvent> analysed = Detector.Prepare(events);
			List<Alert> alerts = Detector.Run(analysed, options.Settings);
			Report report = Report.Build(source.Description, analysed, alerts);

			if (options.Json)
			{
				ReportWriter.WriteJson(report, output);
			}
			else
			{
				ReportWriter.WriteText(report, output);
			}
			return alerts.Count == 0 ? NoAlerts : AlertsFound;
		}
		catch (SourceException e)
		{
			error.WriteLine($"error: {e.Message}");
			return Error;
		}
	}

	/**
	 * <summary>
	 * WHAT:   Creates the source the options ask for.
	 * WHY:    The Windows event log API only exists on Windows; elsewhere
	 *         --live and --file explain that instead of crashing.
	 * THROWS: SourceException for --live or --file on another operating system
	 * RETURN: the source
	 * </summary>
	 * <param name="options">the parsed options</param>
	 * <returns>the source</returns>
	 * <exception cref="SourceException">the input is not available on this system</exception>
	 */
	private static ILogonEventSource CreateSource(Options options)
	{
		switch (options.Input)
		{
			case InputKind.Demo:
				return new DemoSource();
			case InputKind.JsonLines:
				return JsonLinesSource.FromFile(options.Path!);
		}

		if (!OperatingSystem.IsWindows())
		{
			throw new SourceException("--live and --file read Windows event logs and only work on Windows; "
				+ "use --jsonl or --demo here");
		}
		DateTimeOffset? since = options.Since is null ? null : DateTimeOffset.UtcNow - options.Since.Value;
		return new WindowsEventLogSource(options.Input == InputKind.EventFile ? options.Path : null, since);
	}

	/**
	 * <summary>
	 * WHAT:   The program version from the project file.
	 * RETURN: e.g. "1.0.0"
	 * </summary>
	 * <returns>the version</returns>
	 */
	private static string Version() =>
		typeof(Program).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
			.Split('+')[0] ?? "unknown";
}
