// Pure comparison of two runs from GET /api/runs/{id}. No DOM, so the Node tests evaluate this file alone.
(() => {
  'use strict';

  const SEVERITIES = ['FAIL', 'WARN', 'INFO', 'PASS'];
  const VERDICTS = ['FAIL', 'PASS_WITH_WARNINGS', 'PASS'];

  function stepStatus(step) {
    return step.details.status || (step.ok ? 'passed' : 'failed');
  }

  /** The first failed step other than diagnostics, as in RunVerdict. */
  function brokeAt(run) {
    const failed = run.steps.find(s => s.stepId !== 'diagnostics' && stepStatus(s) === 'failed');
    return failed ? failed.stepId : null;
  }

  /** Same rule as RunVerdict.status: a failing check or a broken step fails the run. */
  function verdictOf(run) {
    if (brokeAt(run) || run.findings.some(f => f.severity === 'FAIL')) return 'FAIL';
    return run.findings.some(f => f.severity === 'WARN') ? 'PASS_WITH_WARNINGS' : 'PASS';
  }

  /** Severity rank, lower is worse. */
  function rank(severity) {
    return SEVERITIES.indexOf(severity);
  }

  /** The most severe finding per checkId. */
  function worstByCheck(findings) {
    const worst = new Map();
    for (const f of findings) {
      const seen = worst.get(f.checkId);
      if (!seen || rank(f.severity) < rank(seen.severity)) worst.set(f.checkId, f);
    }
    return worst;
  }

  /** Lower ranks are worse. */
  function direction(before, after) {
    if (after < before) return 'worse';
    return after > before ? 'better' : 'unchanged';
  }

  /**
   * Pure comparison of two runs as returned by GET /api/runs/{id}: what changed from before to after.
   * A severity or step status is null when that run did not report it; checks reported by only one run
   * are listed in oneSided rather than ranked as better or worse.
   */
  function compareRuns(before, after) {
    const was = worstByCheck(before.findings);
    const now = worstByCheck(after.findings);
    const checks = [...new Set([...was.keys(), ...now.keys()])].map(checkId => {
      const b = was.get(checkId);
      const a = now.get(checkId);
      return { checkId, title: (a || b).title, before: b ? b.severity : null, after: a ? a.severity : null };
    }).sort((x, y) => rank(x.after || x.before) - rank(y.after || y.before)
      || rank(x.before || x.after) - rank(y.before || y.after) || x.checkId.localeCompare(y.checkId));
    const both = checks.filter(c => c.before && c.after);
    const statuses = run => new Map(run.steps.map(s => [s.stepId, stepStatus(s)]));
    const stepsBefore = statuses(before);
    const stepsAfter = statuses(after);
    const steps = [...new Set([...stepsBefore.keys(), ...stepsAfter.keys()])]
      .map(stepId => ({ stepId, before: stepsBefore.get(stepId) || null, after: stepsAfter.get(stepId) || null }))
      .filter(s => s.before !== s.after);
    const verdictBefore = verdictOf(before);
    const verdictAfter = verdictOf(after);
    return {
      before: before.runId,
      after: after.runId,
      verdict: { before: verdictBefore, after: verdictAfter,
        change: direction(VERDICTS.indexOf(verdictBefore), VERDICTS.indexOf(verdictAfter)) },
      brokeAt: { before: brokeAt(before), after: brokeAt(after) },
      steps,
      worse: both.filter(c => rank(c.after) < rank(c.before)),
      better: both.filter(c => rank(c.after) > rank(c.before)),
      unchanged: both.filter(c => rank(c.after) === rank(c.before)),
      oneSided: checks.filter(c => !c.before || !c.after),
    };
  }

  globalThis.PayerWorkbench = Object.freeze({ SEVERITIES, compareRuns, brokeAt, verdictOf, stepStatus });
})();
