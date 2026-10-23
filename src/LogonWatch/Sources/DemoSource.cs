using LogonWatch.Model;

namespace LogonWatch.Sources;

/**
 * <summary>
 * WHAT:   A built-in attack scenario, read from Samples/attack.jsonl inside
 *         the program.
 * WHY:    Anyone can see every rule fire with one command (--demo), without
 *         admin rights, a real attack, or a Windows machine. All addresses
 *         are from the documentation ranges (RFC 5737), so none is real.
 * </summary>
 */
public sealed class DemoSource : ILogonEventSource
{
	/** <summary>WHAT: the embedded resource name set in the project file.</summary> */
	private const string ResourceName = "LogonWatch.Samples.attack.jsonl";

	/** <inheritdoc /> */
	public string Description => "built-in demo scenario";

	/**
	 * <summary>
	 * WHAT:   Reads the embedded scenario.
	 * THROWS: SourceException if the resource is missing (a broken build)
	 * RETURN: the scenario's events
	 * </summary>
	 * <returns>the events</returns>
	 * <exception cref="SourceException">the sample is not embedded</exception>
	 */
	public IEnumerable<LogonEvent> Read()
	{
		Stream stream = typeof(DemoSource).Assembly.GetManifestResourceStream(ResourceName)
			?? throw new SourceException($"the demo data ({ResourceName}) is missing from this build");
		return new JsonLinesSource(new StreamReader(stream), "demo").Read();
	}
}
