using LogonWatch.Detection;
using LogonWatch.Model;
using LogonWatch.Reporting;
using LogonWatch.Sources;

namespace LogonWatch.Tests;

/**
 * WHAT:   Tests for the MITRE ATT&CK tags on alerts.
 * WHY:    A SIEM or analyst searching for "T1110.003" must find exactly the
 *         password-spray alerts; a wrong or missing ID silently hides them.
 */
public class AttackTests
{
	/**
	 * WHAT:   The demo, run through the detector once for the tests below.
	 * WHY:    It contains one attack of every kind, so it covers every rule.
	 */
	private static readonly List<Alert> DemoAlerts = Detector.Run(new DemoSource().Read(), new DetectionSettings());

	/**
	 * WHAT:   The technique IDs on the demo alert from one rule.
	 * PRE:    the demo raises exactly one alert for that rule
	 * RETURN: the IDs, in order
	 */
	private static List<string> IdsFor(string rule) =>
		Assert.Single(DemoAlerts, alert => alert.Rule == rule).Techniques.Select(t => t.Id).ToList();

	/**
	 * WHAT:   Each rule's alerts carry its technique.
	 * WHY:    This table is the mapping itself; changing one is a deliberate decision.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Theory]
	[InlineData("brute-force", "T1110.001")]
	[InlineData("password-spray", "T1110.003")]
	[InlineData("distributed-attack", "T1110.001")]
	[InlineData("injection-attempt", "T1190")]
	public void RuleMapsToTechnique(string rule, string id)
	{
		Assert.Equal([id], IdsFor(rule));
	}

	/**
	 * WHAT:   The demo break-in was a Remote Desktop logon (type 10).
	 * WHY:    It is valid-account use after brute force, and an interactive
	 *         RDP session, so all three apply, most specific first.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void BreakInOverRdpGetsThreeTechniques()
	{
		Assert.Equal(["T1078", "T1110", "T1021.001"], IdsFor("success-after-failures"));
	}

	/**
	 * WHAT:   The same break-in over a network logon (type 3, e.g. SMB).
	 * WHY:    No RDP session happened, so T1021.001 must not be claimed.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void BreakInOverNetworkHasNoRdp()
	{
		List<LogonEvent> events = TestData.Failures(6, spacing: 10);
		events.Add(TestData.Success(70, logonType: 3));

		Alert alert = Assert.Single(Detector.Run(events, new DetectionSettings()), a => a.Rule == "success-after-failures");
		Assert.Equal(["T1078", "T1110"], alert.Techniques.Select(t => t.Id));
	}

	/**
	 * WHAT:   Every alert from the detector has at least one technique.
	 * WHY:    A new rule that forgets its mapping should fail here, not ship untagged.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void EveryRuleDeclaresTechniques()
	{
		Assert.All(Detector.Rules, rule => Assert.NotEmpty(rule.Techniques));
		Assert.All(DemoAlerts, alert => Assert.NotEmpty(alert.Techniques));
	}

	/**
	 * WHAT:   The link to the technique's page.
	 * WHY:    MITRE writes sub-techniques as /T1110/003/, not /T1110.003/.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void UrlUsesMitrePathFormat()
	{
		Assert.Equal("https://attack.mitre.org/techniques/T1110/003/", Attack.PasswordSpraying.Url);
		Assert.Equal("https://attack.mitre.org/techniques/T1190/", Attack.ExploitPublicFacing.Url);
	}

	/**
	 * WHAT:   The text report shows the techniques under each alert and a summary.
	 * WHY:    An analyst reading the text should not need the JSON to see them.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void TextReportShowsTechniques()
	{
		StringWriter output = new();
		ReportWriter.WriteText(Report.Build("demo", [], DemoAlerts), output);
		string text = output.ToString();

		Assert.Contains("ATT&CK: T1110.003 Password Spraying (Credential Access)", text);
		Assert.Contains("MITRE ATT&CK techniques seen:", text);
		Assert.Matches(@"T1110\.001\s+Password Guessing\s+2 alerts", text);
	}

	/**
	 * WHAT:   The JSON report has id, name, tactic and url for each technique.
	 * WHY:    SIEMs index alerts by these fields.
	 * PRE:    none
	 * RETURN: nothing; the test fails if an assertion does not hold
	 */
	[Fact]
	public void JsonReportHasTechniqueFields()
	{
		StringWriter output = new();
		ReportWriter.WriteJson(Report.Build("demo", [], DemoAlerts), output);
		string json = output.ToString();

		Assert.Contains("\"id\": \"T1110.003\"", json);
		Assert.Contains("\"tactic\": \"Credential Access\"", json);
		Assert.Contains("\"url\": \"https://attack.mitre.org/techniques/T1110/003/\"", json);
	}
}
