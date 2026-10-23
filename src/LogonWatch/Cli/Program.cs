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
	/**
	 * <summary>
	 * WHAT:   Exit code when no alerts were found.
	 * WHY:    0 means "all good" to every shell and scheduler.
	 * </summary>
	 */
	public const int NoAlerts = 0;

	/**
	 * <summary>
	 * WHAT:   Exit code when an input could not be read.
	 * WHY:    Tells a script the check did not run, which is not the same as "no attacks".
	 * </summary>
	 */
	public const int Error = 1;

	/**
	 * <summary>
	 * WHAT:   Exit code for a bad command line.
	 * WHY:    The usual Unix convention for "you called it wrong".
	 * </summary>
	 */
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
	 * WHY:    A thin wrapper so Run can be tested with fake output streams.
	 * PRE:    none
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
	 * PRE:    args, output and error are not null
	 * POST:   the report or an error message has been written
	 * RETURN: NoAlerts, AlertsFound, Error or BadUsage
	 * </summary>
	 * <param name="args">the command-line arguments</param>
	 * <param name="output">where the report goes</param>
	 * <param name="error">where error messages go</param>
	 * <returns>the exit code</returns>
	 */
	public static int Run(string[] args, TextWriter output, TextWriter error)
	{
		// 1. parse the command line; help and version print and stop here
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
			// 2. read every event from the chosen input
			ILogonEventSource source = CreateSource(options);
			List<LogonEvent> events = source.Read().ToList();

			// 3. --since: keep only recent events (the demo is a fixed scenario from the past, so it is exempt)
			if (options.Since is not null && options.Input != InputKind.Demo)
			{
				DateTimeOffset cutoff = DateTimeOffset.UtcNow - options.Since.Value;
				events = events.Where(e => e.Time >= cutoff).ToList();
			}

			// 4. --redact: hide names and addresses before any rule or report sees them
			if (options.Redact)
			{
				Redactor redactor = new();
				events = events.Select(redactor.Redact).ToList();
			}

			// 5. clean the events, run the rules, and build the report from the same cleaned events
			List<LogonEvent> analysed = Detector.Prepare(events);
			List<Alert> alerts = Detector.Run(analysed, options.Settings);
			Report report = Report.Build(source.Description, analysed, alerts);

			// 6. print it, and say through the exit code whether anything was found
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
	 * PRE:    options were checked by OptionsParser
	 * RETURN: the source
	 * THROWS: SourceException for --live or --file on another operating system
	 * </summary>
	 * <param name="options">the parsed options</param>
	 * <returns>the source</returns>
	 * <exception cref="SourceException">the input is not available on this system</exception>
	 */
	private static ILogonEventSource CreateSource(Options options)
	{
		// the demo and JSON-lines work everywhere
		switch (options.Input)
		{
			case InputKind.Demo:
				return new DemoSource();
			case InputKind.JsonLines:
				return JsonLinesSource.FromFile(options.Path!);
		}

		// --live and --file need the Windows event log API
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
	 * WHY:    --version reads it from the assembly, so it can never disagree
	 *         with the build.
	 * PRE:    none
	 * RETURN: e.g. "1.0.0", without the "+commit" suffix .NET adds
	 * </summary>
	 * <returns>the version</returns>
	 */
	private static string Version() =>
		typeof(Program).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
			.Split('+')[0] ?? "unknown";
}
