namespace LogonWatch.Detection;

/**
 * <summary>
 * WHAT:   Finds "bursts": stretches of time where a sliding window of events
 *         holds at least a threshold of events (or of distinct values,
 *         e.g. accounts), such as 10 failures within 5 minutes.
 * WHY:    Every rule is "too many of something, too close together"; one
 *         sliding-window algorithm serves all of them. Overlapping
 *         qualifying windows merge into one burst, so one attack gives one
 *         alert, not hundreds.
 * </summary>
 */
internal static class Bursts
{
	/**
	 * <summary>
	 * WHAT:   Returns each burst as the list of events it contains.
	 * WHY:    Two pointers keep the window at most `window` wide, and the
	 *         distinct values are counted as events enter and leave, so the
	 *         whole scan is linear: each event is added once and removed once.
	 *         (Recounting the window at every step made 100,000 events take
	 *         seconds instead of milliseconds.)
	 * PRE:    items is sorted by time, oldest first; threshold is at least 1
	 * RETURN: the bursts in time order; empty if no window qualifies
	 * </summary>
	 * <typeparam name="T">the event type</typeparam>
	 * <param name="items">the events, oldest first</param>
	 * <param name="time">gets an event's time</param>
	 * <param name="window">the longest span a qualifying window may cover</param>
	 * <param name="threshold">how many events (or distinct values) make a window suspicious</param>
	 * <param name="distinctBy">counts distinct values of this key instead of events, or null to count events;
	 *                          keys are compared ignoring case</param>
	 * <returns>the bursts</returns>
	 */
	public static List<List<T>> Find<T>(List<T> items, Func<T, DateTimeOffset> time, TimeSpan window, int threshold,
		Func<T, string>? distinctBy = null)
	{
		List<List<T>> bursts = [];
		Dictionary<string, int> keys = new(StringComparer.OrdinalIgnoreCase);
		int left = 0;
		int start = -1;
		int end = -1;

		for (int i = 0; i < items.Count; i++)
		{
			if (distinctBy is not null)
			{
				string key = distinctBy(items[i]);
				keys[key] = keys.GetValueOrDefault(key) + 1;
			}

			while (time(items[i]) - time(items[left]) > window)
			{
				if (distinctBy is not null)
				{
					string key = distinctBy(items[left]);
					if (--keys[key] == 0)
					{
						keys.Remove(key);
					}
				}
				left++;
			}

			// a gap longer than the window since the burst's last event ends that burst
			if (start >= 0 && time(items[i]) - time(items[end]) > window)
			{
				bursts.Add(items.GetRange(start, end - start + 1));
				start = -1;
			}

			int size = distinctBy is null ? i - left + 1 : keys.Count;
			if (size >= threshold)
			{
				if (start < 0)
				{
					start = left;
				}
				end = i;
			}
		}

		if (start >= 0)
		{
			bursts.Add(items.GetRange(start, end - start + 1));
		}
		return bursts;
	}
}
