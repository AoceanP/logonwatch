using LogonWatch.Model;

namespace LogonWatch.Sources;

/**
 * <summary>
 * WHAT:   Somewhere logon events can be read from.
 * WHY:    The live log, an .evtx file, a JSON-lines file and the demo all
 *         feed the same detector, so each is one small class.
 * </summary>
 */
public interface ILogonEventSource
{
	/** <summary>WHAT: a short description for the report, e.g. "Security log" or a file name.</summary> */
	string Description { get; }

	/**
	 * <summary>
	 * WHAT:   Reads the events.
	 * THROWS: SourceException with a message a user can act on
	 * RETURN: the logon events, in the order the source stores them
	 * </summary>
	 * <returns>the events</returns>
	 * <exception cref="SourceException">the source cannot be read</exception>
	 */
	IEnumerable<LogonEvent> Read();
}

/**
 * <summary>
 * WHAT:   A source could not be read: missing file, bad line, no permission.
 * WHY:    One exception type lets the program print the message and exit
 *         with code 1 instead of a stack trace.
 * </summary>
 * <param name="message">what went wrong and how to fix it</param>
 * <param name="inner">the original exception, if any</param>
 */
public sealed class SourceException(string message, Exception? inner = null) : Exception(message, inner);
