using System.Globalization;
using LogonWatch.Detection;

namespace LogonWatch.Cli;

/**
 * <summary>
 * WHAT:   Where the events come from.
 * </summary>
 */
public enum InputKind
{
	/** <summary>WHAT: the live Windows Security log (needs admin).</summary> */
	Live,

	/** <summary>WHAT: an exported .evtx file.</summary> */
	EventFile,

	/** <summary>WHAT: a JSON-lines file.</summary> */
	JsonLines,

	/** <summary>WHAT: the built-in demo scenario.</summary> */
	Demo,
}

/**
 * <summary>
 * WHAT:   The parsed command line.
 * </summary>
 * <param name="Input">where the events come from</param>
 * <param name="Path">the file for EventFile and JsonLines, otherwise null</param>
 * <param name="Since">only analyse events this recent, or null for all</param>
 * <param name="Settings">the detection thresholds and windows</param>
 * <param name="Json">print JSON instead of text</param>
 * <param name="Redact">replace names and addresses with placeholders</param>
 */
public sealed record Options(
	InputKind Input,
	string? Path,
	TimeSpan? Since,
	DetectionSettings Settings,
	bool Json,
	bool Redact);

/**
 * <summary>
 * WHAT:   Thrown for a bad command line.
 * WHY:    Lets the program print the message with the usage and exit 2.
 * </summary>
 * <param name="message">what is wrong with the command line</param>
 */
public sealed class UsageException(string message) : Exception(message);

/**
 * <summary>
 * WHAT:   Reads the command-line arguments into Options.
 * WHY:    All checks happen before any log is opened, so a typo never
 *         starts a slow scan of the whole Security log.
 * </summary>
 */
public static class OptionsParser
{
	/** <summary>WHAT: the help text.</summary> */
	public const string Usage = """
		usage: logonwatch <input> [options]

		input (choose one):
		  --live               read the Windows Security log (run the terminal as administrator)
		  --file FILE.evtx     read an exported event log file
		  --jsonl FILE.jsonl   read logon events from a JSON-lines file
		  --demo               run the built-in attack scenario

		options:
		  --since DURATION     only events from the last DURATION, e.g. 30m, 24h, 7d
		  --threshold N        failed logons that count as brute force (default 10)
		  --window DURATION    time they must fall within (default 5m)
		  --json               print JSON instead of text
		  --redact             replace account names and IP addresses with placeholders
		  -h, --help           show this help
		      --version        show the version

		exit codes: 0 no alerts, 3 alerts found, 1 error, 2 bad command line
		""";

	/**
	 * <summary>
	 * WHAT:   Parses the arguments.
	 * WHY:    Returns null for --help and --version, which print and exit
	 *         without reading anything.
	 * THROWS: UsageException naming the problem
	 * RETURN: the options, or null when only help or the version was asked for
	 * </summary>
	 * <param name="args">the command-line arguments</param>
	 * <param name="showVersion">set to true when --version was given</param>
	 * <returns>the options, or null</returns>
	 * <exception cref="UsageException">the arguments are invalid</exception>
	 */
	public static Options? Parse(string[] args, out bool showVersion)
	{
		showVersion = false;
		InputKind? input = null;
		string? path = null;
		TimeSpan? since = null;
		DetectionSettings settings = new();
		bool json = false;
		bool redact = false;

		for (int i = 0; i < args.Length; i++)
		{
			string argument = args[i];
			switch (argument)
			{
				case "-h" or "--help":
					return null;
				case "--version":
					showVersion = true;
					return null;
				case "--live":
					SetInput(ref input, InputKind.Live);
					break;
				case "--demo":
					SetInput(ref input, InputKind.Demo);
					break;
				case "--file":
					SetInput(ref input, InputKind.EventFile);
					path = Value(args, ref i);
					break;
				case "--jsonl":
					SetInput(ref input, InputKind.JsonLines);
					path = Value(args, ref i);
					break;
				case "--since":
					since = ParseDuration(Value(args, ref i), argument);
					break;
				case "--threshold":
					settings = settings with { BruteForceThreshold = ParseCount(Value(args, ref i), argument) };
					break;
				case "--window":
					settings = settings with { BruteForceWindow = ParseDuration(Value(args, ref i), argument) };
					break;
				case "--json":
					json = true;
					break;
				case "--redact":
					redact = true;
					break;
				default:
					throw new UsageException($"unknown option {argument}");
			}
		}

		if (input is null)
		{
			if (args.Length == 0)
			{
				return null;
			}
			throw new UsageException("choose an input: --live, --file, --jsonl or --demo");
		}

		try
		{
			settings.Validate();
		}
		catch (ArgumentException e)
		{
			throw new UsageException(e.Message);
		}
		return new Options(input.Value, path, since, settings, json, redact);
	}

	/**
	 * <summary>
	 * WHAT:   Parses a duration such as "30s", "5m", "24h" or "7d".
	 * WHY:    Shorter to type than "00:05:00", and the unit is never ambiguous.
	 * THROWS: UsageException if the text is not a positive number with a unit
	 * RETURN: the duration
	 * </summary>
	 * <param name="text">the duration text</param>
	 * <param name="option">the option it belongs to, for the message</param>
	 * <returns>the duration</returns>
	 * <exception cref="UsageException">the text is not a valid duration</exception>
	 */
	public static TimeSpan ParseDuration(string text, string option)
	{
		if (text.Length >= 2
			&& int.TryParse(text.AsSpan(0, text.Length - 1), NumberStyles.None, CultureInfo.InvariantCulture, out int amount)
			&& amount > 0)
		{
			switch (char.ToLowerInvariant(text[^1]))
			{
				case 's': return TimeSpan.FromSeconds(amount);
				case 'm': return TimeSpan.FromMinutes(amount);
				case 'h': return TimeSpan.FromHours(amount);
				case 'd': return TimeSpan.FromDays(amount);
			}
		}
		throw new UsageException($"{option} needs a duration like 30s, 5m, 24h or 7d, got '{text}'");
	}

	/**
	 * <summary>
	 * WHAT:   Parses a whole number above zero.
	 * THROWS: UsageException otherwise
	 * RETURN: the number
	 * </summary>
	 * <param name="text">the text</param>
	 * <param name="option">the option it belongs to, for the message</param>
	 * <returns>the number</returns>
	 * <exception cref="UsageException">the text is not a positive whole number</exception>
	 */
	private static int ParseCount(string text, string option)
	{
		if (int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out int value) && value > 0)
		{
			return value;
		}
		throw new UsageException($"{option} needs a whole number above 0, got '{text}'");
	}

	/**
	 * <summary>
	 * WHAT:   Returns the value after an option and moves past it.
	 * THROWS: UsageException if the option is the last argument
	 * RETURN: the value
	 * </summary>
	 * <param name="args">the arguments</param>
	 * <param name="i">the option's index; moved to the value's index</param>
	 * <returns>the value</returns>
	 * <exception cref="UsageException">the value is missing</exception>
	 */
	private static string Value(string[] args, ref int i)
	{
		if (i + 1 >= args.Length)
		{
			throw new UsageException($"{args[i]} needs a value");
		}
		return args[++i];
	}

	/**
	 * <summary>
	 * WHAT:   Records the input, refusing a second one.
	 * THROWS: UsageException if an input was already chosen
	 * </summary>
	 * <param name="current">the input chosen so far</param>
	 * <param name="next">the new input</param>
	 * <exception cref="UsageException">two inputs were given</exception>
	 */
	private static void SetInput(ref InputKind? current, InputKind next)
	{
		if (current is not null)
		{
			throw new UsageException("choose only one input: --live, --file, --jsonl or --demo");
		}
		current = next;
	}
}
