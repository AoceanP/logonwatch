using LogonWatch.Model;

namespace LogonWatch.Sources;

/**
 * <summary>
 * WHAT:   Somewhere logon events can be read from.
 * WHY:    The live log, an .evtx file, a JSON-lines file and the demo all
 *         feed the same detector, so each is one small class behind one
 *         interface, and the program never needs to know which it has.
 * </summary>
 */
public interface ILogonEventSource
{
	/**
	 * <summary>
	 * WHAT:   A short description of the input, e.g. "Windows Security log" or a file name.
	 * WHY:    The report's first line says where its data came from.
	 * PRE:    none
	 * RETURN: the description
	 * </summary>
	 */
	string Description { get; }

	/**
	 * <summary>
	 * WHAT:   Reads the events.
	 * WHY:    Returns them lazily (IEnumerable), so a huge log is not loaded
	 *         twice: the caller decides when to collect them.
	 * PRE:    none
	 * POST:   the underlying file or log handle is closed when reading ends
	 * RETURN: the logon events, in the order the source stores them
	 * THROWS: SourceException with a message a user can act on
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
 *         with code 1 instead of showing a stack trace.
 * PRE:    message explains what went wrong and how to fix it
 * </summary>
 * <param name="message">what went wrong and how to fix it</param>
 * <param name="inner">the original exception, if any</param>
 */
public sealed class SourceException(string message, Exception? inner = null) : Exception(message, inner);
