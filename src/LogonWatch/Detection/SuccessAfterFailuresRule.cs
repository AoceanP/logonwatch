using LogonWatch.Model;

namespace LogonWatch.Detection;

/**
 * <summary>
 * WHAT:   A successful logon right after many failures, from the same
 *         source or for the same account.
 * WHY:    This is the alert that matters most: the other rules say someone
 *         is attacking; this one says the attack probably worked.
 * </summary>
 */
public sealed class SuccessAfterFailuresRule : IDetectionRule
{
	/**
	 * <summary>
	 * WHAT:   The rule's name in alerts: "success-after-failures".
	 * WHY:    Identifies the rule in reports and JSON.
	 * PRE:    none
	 * RETURN: "success-after-failures"
	 * </summary>
	 */
	public string Name => "success-after-failures";

	/**
	 * <summary>
	 * WHAT:   For each success, counts failures in the window before it that
	 *         share its source address or its account.
	 * WHY:    Matching on account too catches an attacker who guessed from
	 *         one address and logged in from another. Severity is Critical
	 *         for remote logons, High for local ones. After an alert, the
	 *         same source and account are not reported again within the
	 *         window, so one break-in gives one alert.
	 * PRE:    events are sorted by time
	 * POST:   events are not changed
	 * RETURN: one alert per suspicious success
	 * </summary>
	 * <param name="events">the logon events</param>
	 * <param name="settings">the thresholds and windows</param>
	 * <returns>the alerts</returns>
	 */
	public IEnumerable<Alert> Evaluate(IReadOnlyList<LogonEvent> events, DetectionSettings settings)
	{
		// failures stay sorted by time, which the binary search below relies on
		List<LogonEvent> failures = events.Where(e => e.IsFailure).ToList();

		// "source|user" -> time of the last alert, so one break-in is reported once
		Dictionary<string, DateTimeOffset> lastAlert = new(StringComparer.OrdinalIgnoreCase);

		foreach (LogonEvent success in events.Where(e => !e.IsFailure))
		{
			// 1. skip successes that belong to a break-in already reported
			string key = success.Source + "|" + success.User;
			if (lastAlert.TryGetValue(key, out DateTimeOffset previous)
				&& success.Time - previous <= settings.SuccessAfterFailuresWindow)
			{
				continue;
			}

			// 2. jump straight to the first failure inside the window instead of scanning the whole log,
			//    then walk forward to the success, keeping failures from the same source or account
			DateTimeOffset from = success.Time - settings.SuccessAfterFailuresWindow;
			List<LogonEvent> related = [];
			for (int i = FirstAtOrAfter(failures, from); i < failures.Count && failures[i].Time <= success.Time; i++)
			{
				LogonEvent failure = failures[i];
				if ((!success.IsLocal && string.Equals(failure.Source, success.Source, StringComparison.OrdinalIgnoreCase))
					|| string.Equals(failure.User, success.User, StringComparison.OrdinalIgnoreCase))
				{
					related.Add(failure);
				}
			}

			// 3. too few failures before it: an ordinary logon
			if (related.Count < settings.SuccessAfterFailuresThreshold)
			{
				continue;
			}

			// 4. report it and remember it, so later successes of the same break-in are skipped
			lastAlert[key] = success.Time;
			Severity severity = success.IsLocal ? Severity.High : Severity.Critical;
			yield return new Alert(Name, severity, success.Source, [success.User], related.Count, related[0].Time,
				success.Time,
				$"{success.User} logged on from {RuleText.Source(success.Source)} after {related.Count} failed attempts in "
				+ $"{RuleText.Duration(success.Time - related[0].Time)}: treat this account as compromised");
		}
	}

	/**
	 * <summary>
	 * WHAT:   Binary search for the first failure at or after a time.
	 * WHY:    Scanning every failure for every success was quadratic: on a
	 *         log of 100,000 events it took over half a minute. Halving the
	 *         search range each step needs only about 17 steps for 100,000.
	 * PRE:    failures is sorted by time
	 * RETURN: the index, or failures.Count if every failure is earlier
	 * </summary>
	 * <param name="failures">the failures, oldest first</param>
	 * <param name="time">the time to search for</param>
	 * <returns>the first index whose time is at or after time</returns>
	 */
	private static int FirstAtOrAfter(List<LogonEvent> failures, DateTimeOffset time)
	{
		// the answer is always inside [low, high); each step throws away half of that range
		int low = 0;
		int high = failures.Count;
		while (low < high)
		{
			int middle = low + (high - low) / 2; // written this way so low + high cannot overflow
			if (failures[middle].Time < time)
			{
				low = middle + 1; // middle is too early, so the answer is to its right
			}
			else
			{
				high = middle; // middle might be the answer, so keep it in the range
			}
		}
		return low;
	}
}
