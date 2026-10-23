using LogonWatch.Model;

namespace LogonWatch.Sources;

/**
 * <summary>
 * WHAT:   A built-in attack scenario, read from Samples/attack.jsonl inside
 *         the program.
 * WHY:    Anyone can see every rule fire with one command (--demo), without
 *         admin rights, a real attack, or a Windows machine. All data is
 *         fake: the addresses are from the documentation ranges (RFC 5737),
 *         so none is real.
 * </summary>
 */
public sealed class DemoSource : ILogonEventSource
{
	/**
	 * <summary>
	 * WHAT:   The embedded resource name.
	 * WHY:    Must match the LogicalName in LogonWatch.csproj.
	 * </summary>
	 */
	private const string ResourceName = "LogonWatch.Samples.attack.jsonl";

	/**
	 * <summary>
	 * WHAT:   "built-in demo scenario".
	 * WHY:    Shown in the report so nobody mistakes the demo for their own log.
	 * PRE:    none
	 * RETURN: the description
	 * </summary>
	 */
	public string Description => "built-in demo scenario";

	/**
	 * <summary>
	 * WHAT:   Reads the embedded scenario.
	 * WHY:    The file is inside the .exe, so the demo works from any folder.
	 * PRE:    none
	 * POST:   the resource stream is closed when reading ends
	 * RETURN: the scenario's events
	 * THROWS: SourceException if the resource is missing (a broken build)
	 * </summary>
	 * <returns>the events</returns>
	 * <exception cref="SourceException">the sample is not embedded</exception>
	 */
	public IEnumerable<LogonEvent> Read()
	{
		// the demo is a JSON-lines file, so the JSON-lines reader does the actual work
		Stream stream = typeof(DemoSource).Assembly.GetManifestResourceStream(ResourceName)
			?? throw new SourceException($"the demo data ({ResourceName}) is missing from this build");
		return new JsonLinesSource(new StreamReader(stream), "demo").Read();
	}
}
