(() => {
  "use strict";

  const PLAYER_INTERVAL_MS = 1850;
  const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
  const state = {
    data: null,
    scenarioIndex: 2,
    stepIndex: 0,
    timer: null,
    pendingRun: false,
  };

  const player = document.querySelector(".player-shell");
  const loading = document.querySelector("[data-player-loading]");
  const content = document.querySelector("[data-player-content]");
  if (!player || !loading || !content) return;

  const ui = {
    selector: document.querySelector("[data-scenario-selector]"),
    phase: document.querySelector("[data-scenario-phase]"),
    title: document.querySelector("[data-scenario-title]"),
    summary: document.querySelector("[data-scenario-summary]"),
    status: document.querySelector("[data-scenario-status]"),
    stageRail: document.querySelector("[data-stage-rail]"),
    scene: document.querySelector("[data-decision-scene]"),
    signals: document.querySelector("[data-signal-stack]"),
    riskDial: document.querySelector("[data-risk-dial]"),
    riskValue: document.querySelector("[data-risk-value]"),
    outcomeSymbol: document.querySelector("[data-outcome-symbol]"),
    outcomeLabel: document.querySelector("[data-outcome-label]"),
    outcomeMode: document.querySelector("[data-outcome-mode]"),
    narrationStep: document.querySelector("[data-narration-step]"),
    narrationTitle: document.querySelector("[data-narration-title]"),
    narrationBody: document.querySelector("[data-narration-body]"),
    playButton: document.querySelector('[data-action="play"]'),
    playIcon: document.querySelector("[data-play-icon]"),
    playLabel: document.querySelector("[data-play-label]"),
    decisionResult: document.querySelector('[data-result="decision"]'),
    effectResult: document.querySelector('[data-result="effect"]'),
    evaluationResult: document.querySelector('[data-result="evaluation"]'),
    policyRule: document.querySelector("[data-policy-rule]"),
    actions: document.querySelector("[data-counterfactual-actions]"),
    source: document.querySelector("[data-scenario-source]"),
    executionBoundary: document.querySelector("[data-execution-boundary]"),
    transcript: document.querySelector("[data-transcript]"),
  };

  const phaseLabels = {
    PHASE_2_READ_ONLY: "Phase 2 · Offline read-only replay",
    V0_1_SYNTHETIC_SIMULATOR: "V0.1 · Synthetic in-memory simulator",
  };

  const effectLabels = {
    NOT_ATTEMPTED_READ_ONLY: "Suppressed read-only",
    VERIFIED: "Verified",
    FAILED: "Failed",
    UNKNOWN: "Unknown",
  };

  const evaluationLabels = {
    MATCHED_EXPECTATION: "Matched expectation",
    MISMATCHED_EXPECTATION: "Did not match",
    NOT_EVALUATED: "Not evaluated",
  };

  const outcomeSymbols = {
    NO_ACTION: "○",
    INVESTIGATE: "?",
    CONTAIN_REVERSIBLE: "✓",
    ESCALATE_HUMAN: "↑",
  };

  function element(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function setExternalLink(anchor, href) {
    anchor.href = href;
    anchor.target = "_blank";
    anchor.rel = "noreferrer noopener";
  }

  function shortCommit(commit) {
    return commit.slice(0, 9);
  }

  function percentage(value, digits = 1) {
    return `${(value * 100).toFixed(digits)}%`;
  }

  function readableAction(action) {
    return action.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
  }

  function currentScenario() {
    return state.data.scenarios[state.scenarioIndex];
  }

  function buildSteps(scenario) {
    const risk = percentage(scenario.model.compromise_probability, 1);
    const evidence = scenario.model.evidence_quality === null
      ? "not reported"
      : percentage(scenario.model.evidence_quality, 1);

    if (scenario.phase === "V0_1_SYNTHETIC_SIMULATOR") {
      return [
        {
          label: "Case",
          visual: "case",
          title: "Synthetic case received.",
          body: scenario.summary,
        },
        {
          label: "Evidence",
          visual: "evidence",
          title: "Evidence is assessed.",
          body: `Evidence quality is ${evidence}. The presented signals support a bounded simulator decision.`,
        },
        {
          label: "Model",
          visual: "model",
          title: "The model advises.",
          body: `Estimated risk is ${risk}. The score remains advisory and cannot call the target directly.`,
        },
        {
          label: "Policy",
          visual: "policy",
          title: "Policy authorizes bounded simulator actions.",
          body: scenario.decision.explanation,
        },
        {
          label: "Verify",
          visual: "verify",
          title: "Independent checks approve the proposed action set.",
          body: "Authorization is scoped to the case and the three allow-listed reversible simulator actions.",
        },
        {
          label: "Act",
          visual: "verify",
          title: "The in-memory simulator applies the actions.",
          body: "Session revocation and increased monitoring succeed, while forced step-up authentication does not change state.",
        },
        {
          label: "Readback",
          visual: "result",
          title: "Post-action verification detects the failed effect.",
          body: scenario.effect.explanation,
          effectFailed: true,
        },
        {
          label: "Record",
          visual: "result",
          title: "The system records failure—not success.",
          body: scenario.evaluation.explanation,
          effectFailed: true,
        },
      ];
    }

    const isInvestigation = scenario.decision.disposition === "INVESTIGATE";
    return [
      {
        label: "Receive",
        visual: "case",
        title: "The case enters the decision boundary.",
        body: scenario.summary,
      },
      {
        label: "Evidence",
        visual: "evidence",
        title: isInvestigation ? "Evidence conflict is detected." : "Evidence quality is assessed.",
        body: isInvestigation
          ? `Evidence quality is ${evidence}, but independent telemetry conflicts. The evidence gate holds automation.`
          : `Evidence quality is ${evidence}. Provenance, integrity, freshness, and corroboration are evaluated before the score can matter.`,
      },
      {
        label: "Model",
        visual: "model",
        title: "The model provides an advisory estimate.",
        body: `Estimated compromise probability is ${risk}. Confidence is visible, but it grants no authority.`,
      },
      {
        label: "Policy",
        visual: "policy",
        title: `Policy proposes: ${scenario.decision.label}.`,
        body: scenario.decision.explanation,
      },
      {
        label: "Verify",
        visual: "verify",
        title: "An independent, non-model control checks the proposal.",
        body: "The verifier checks cited evidence, action allowlists, thresholds, conflicts, criticality, and rollback requirements.",
      },
      {
        label: "Suppress",
        visual: "verify",
        title: "Execution remains structurally suppressed.",
        body: scenario.effect.explanation,
      },
      {
        label: "Authority",
        visual: "verify",
        title: "Authorization is evaluated without issuing a token.",
        body: "Offline read-only replay constructs no action broker or operational target. Proposed actions remain counterfactual.",
      },
      {
        label: "Finalize",
        visual: "result",
        title: `${scenario.evaluation.label}: ${scenario.decision.label}.`,
        body: scenario.evaluation.explanation,
      },
    ];
  }

  function stopPlayback() {
    if (state.timer) window.clearInterval(state.timer);
    state.timer = null;
    ui.playButton.setAttribute("aria-pressed", "false");
    ui.playIcon.textContent = "▶";
    ui.playLabel.textContent = state.stepIndex === buildSteps(currentScenario()).length - 1
      ? "Play again"
      : "Play decision";
  }

  function startPlayback() {
    if (state.timer) {
      stopPlayback();
      return;
    }
    const steps = buildSteps(currentScenario());
    if (state.stepIndex === steps.length - 1) {
      state.stepIndex = 0;
      renderStage();
    }
    ui.playButton.setAttribute("aria-pressed", "true");
    ui.playIcon.textContent = "Ⅱ";
    ui.playLabel.textContent = "Pause";
    const interval = prefersReducedMotion.matches ? 2600 : PLAYER_INTERVAL_MS;
    state.timer = window.setInterval(() => {
      if (state.stepIndex >= steps.length - 1) {
        stopPlayback();
        return;
      }
      state.stepIndex += 1;
      renderStage();
    }, interval);
  }

  function runDecision() {
    if (!state.data) {
      state.pendingRun = true;
      return;
    }
    state.pendingRun = false;
    stopPlayback();
    state.stepIndex = 0;
    renderStage();
    startPlayback();
  }

  function setGate(gateName, status, text) {
    const gate = player.querySelector(`[data-gate="${gateName}"]`);
    gate.classList.remove("is-pass", "is-held");
    const icon = gate.querySelector("i");
    const label = gate.querySelector("b");
    if (status === "pass") {
      gate.classList.add("is-pass");
      icon.textContent = "✓";
      label.textContent = text || "Passed";
    } else if (status === "held") {
      gate.classList.add("is-held");
      icon.textContent = "!";
      label.textContent = text || "Held";
    } else {
      icon.textContent = gateName === "evidence" ? "1" : gateName === "policy" ? "2" : "3";
      label.textContent = "Waiting";
    }
  }

  function renderGateState(scenario) {
    const step = state.stepIndex;
    const isInvestigation = scenario.decision.disposition === "INVESTIGATE";
    setGate("evidence", step >= 1 ? (isInvestigation ? "held" : "pass") : "waiting", isInvestigation ? "Conflict" : "Passed");
    setGate("policy", step >= 3 ? "pass" : "waiting", isInvestigation ? "Abstain" : "Passed");
    setGate("verify", step >= 4 ? "pass" : "waiting", "Passed");
  }

  function renderStageRail(steps) {
    ui.stageRail.replaceChildren();
    steps.forEach((step, index) => {
      const button = element("button");
      button.type = "button";
      button.dataset.stepIndex = String(index);
      button.classList.toggle("is-active", index === state.stepIndex);
      button.classList.toggle("is-complete", index < state.stepIndex);
      button.setAttribute("aria-label", `Step ${index + 1}: ${step.label}`);
      button.setAttribute("aria-current", index === state.stepIndex ? "step" : "false");
      button.append(element("i", "", index < state.stepIndex ? "✓" : String(index + 1)));
      button.append(element("span", "", step.label));
      ui.stageRail.append(button);
    });
  }

  function renderStage() {
    const scenario = currentScenario();
    const steps = buildSteps(scenario);
    const step = steps[state.stepIndex];
    renderStageRail(steps);

    ui.scene.className = "decision-scene";
    ui.scene.classList.add(`stage-${step.visual}`);
    if (step.effectFailed) ui.scene.classList.add("effect-failed");
    ui.narrationStep.textContent = `${String(state.stepIndex + 1).padStart(2, "0")} / ${String(steps.length).padStart(2, "0")}`;
    ui.narrationTitle.textContent = step.title;
    ui.narrationBody.textContent = step.body;
    renderGateState(scenario);

    const finalStep = state.stepIndex === steps.length - 1;
    const proposalVisible = state.stepIndex >= 3;
    ui.outcomeSymbol.textContent = finalStep ? (scenario.effect.status === "FAILED" ? "×" : outcomeSymbols[scenario.decision.disposition]) : "…";
    ui.outcomeLabel.textContent = finalStep
      ? (scenario.effect.status === "FAILED" ? "Effect failed" : scenario.decision.label)
      : proposalVisible
        ? `${scenario.decision.label} proposed`
        : "Pending checks";
    ui.outcomeMode.textContent = finalStep
      ? effectLabels[scenario.effect.status]
      : proposalVisible
        ? "Awaiting finalization"
        : "Decision not finalized";
  }

  function resultClass(node, name) {
    node.classList.remove("is-pass", "is-held", "is-failed");
    node.classList.add(name);
  }

  function fillResult(node, value, explanation) {
    node.querySelector("strong").textContent = value;
    node.querySelector("p").textContent = explanation;
  }

  function renderScenarioButtons() {
    ui.selector.replaceChildren();
    state.data.scenarios.forEach((scenario, index) => {
      const button = element("button", "", scenario.title);
      button.type = "button";
      button.setAttribute("role", "radio");
      button.dataset.scenarioIndex = String(index);
      button.setAttribute("aria-checked", index === state.scenarioIndex ? "true" : "false");
      button.tabIndex = index === state.scenarioIndex ? 0 : -1;
      ui.selector.append(button);
    });
  }

  function renderScenario() {
    stopPlayback();
    const scenario = currentScenario();
    state.stepIndex = Math.min(state.stepIndex, buildSteps(scenario).length - 1);
    renderScenarioButtons();
    ui.phase.textContent = phaseLabels[scenario.phase];
    ui.title.textContent = scenario.title;
    ui.summary.textContent = scenario.summary;
    ui.status.textContent = scenario.effect.status === "FAILED"
      ? "Effect failure · Synthetic"
      : `${scenario.evaluation.label} · Synthetic`;
    ui.status.className = `status-chip ${scenario.effect.status === "FAILED" ? "status-failure" : "status-observed"}`;

    ui.signals.replaceChildren();
    scenario.signals.forEach((signal) => {
      const card = element("div", "signal-card");
      card.dataset.stance = signal.stance;
      card.append(element("i"));
      card.append(element("span", "", signal.label));
      ui.signals.append(card);
    });

    ui.riskValue.textContent = percentage(scenario.model.compromise_probability, 1);

    fillResult(ui.decisionResult, scenario.decision.label, scenario.decision.explanation);
    resultClass(ui.decisionResult, scenario.decision.disposition === "INVESTIGATE" ? "is-held" : "is-pass");
    fillResult(ui.effectResult, effectLabels[scenario.effect.status], scenario.effect.explanation);
    resultClass(ui.effectResult, scenario.effect.status === "FAILED" ? "is-failed" : scenario.effect.status === "VERIFIED" ? "is-pass" : "is-held");
    fillResult(ui.evaluationResult, evaluationLabels[scenario.evaluation.status], scenario.evaluation.explanation);
    resultClass(ui.evaluationResult, scenario.evaluation.status === "MATCHED_EXPECTATION" ? "is-pass" : scenario.evaluation.status === "MISMATCHED_EXPECTATION" ? "is-failed" : "is-held");

    ui.policyRule.textContent = scenario.decision.policy_rule;
    ui.actions.textContent = scenario.decision.counterfactual_actions.length
      ? scenario.decision.counterfactual_actions.map(readableAction).join(" · ")
      : "None";
    setExternalLink(ui.source, scenario.source_url);
    ui.executionBoundary.textContent = scenario.phase === "PHASE_2_READ_ONLY"
      ? `No authorization token · ${scenario.effect.broker_invocations} broker calls · ${scenario.effect.operational_effects} operational effects`
      : `${scenario.effect.broker_invocations} simulator action attempts · ${scenario.effect.operational_effects} verified simulator effects`;

    ui.transcript.replaceChildren();
    buildSteps(scenario).forEach((step) => {
      const item = element("li");
      item.append(element("strong", "", `${step.label}: `));
      item.append(document.createTextNode(`${step.title} ${step.body}`));
      ui.transcript.append(item);
    });
    renderStage();
  }

  function chooseScenario(index) {
    if (index < 0 || index >= state.data.scenarios.length) return;
    state.scenarioIndex = index;
    state.stepIndex = 0;
    renderScenario();
    const selected = ui.selector.querySelector(`[data-scenario-index="${index}"]`);
    if (selected) selected.focus({ preventScroll: true });
  }

  function renderVersionLedger() {
    const ledger = document.querySelector("[data-version-ledger]");
    ledger.replaceChildren();
    const baseline = state.data.site_status.evidence_baseline;
    const baselineCard = element("article", "version-card is-published");
    const baselineTop = element("div", "version-card-top");
    baselineTop.append(element("span", "version-card-label", baseline.label));
    baselineTop.append(element("span", "version-status", "Observed"));
    baselineCard.append(baselineTop, element("h3", "", baseline.version));
    baselineCard.append(element("p", "", `Latest supported controlled-behavior claim: ${baseline.latest_claim_id}.`));
    const baselineMeta = element("div", "version-meta");
    baselineMeta.append(element("span", "", `Published ${shortCommit(baseline.publication_commit)}`));
    baselineMeta.append(element("span", "", new Date(baseline.evaluated_at).toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric", timeZone: "UTC" })));
    baselineCard.append(baselineMeta);
    const baselineLink = element("a", "", "Open evidence record ↗");
    setExternalLink(baselineLink, baseline.source_url);
    baselineCard.append(baselineLink);
    ledger.append(baselineCard);

    const candidate = state.data.site_status.candidate;
    if (candidate) {
      const candidateCard = element("article", "version-card is-candidate");
      const candidateTop = element("div", "version-card-top");
      candidateTop.append(element("span", "version-card-label", candidate.label));
      candidateTop.append(element("span", "version-status", "Not evaluated"));
      candidateCard.append(candidateTop, element("h3", "", candidate.version));
      candidateCard.append(element("p", "", `${candidate.claim_id} has a design plan but no completed evidence package. No pass count is shown.`));
      const candidateMeta = element("div", "version-meta");
      candidateMeta.append(element("span", "", `Design ${shortCommit(candidate.design_commit)}`));
      candidateMeta.append(element("span", "", "CE-0 · NOT_EVALUATED"));
      candidateCard.append(candidateMeta);
      const candidateLink = element("a", "", "Open design commit ↗");
      setExternalLink(candidateLink, `https://github.com/redxking/ai-decision-firewall/commit/${candidate.design_commit}`);
      candidateCard.append(candidateLink);
      ledger.append(candidateCard);
    }
  }

  function renderClaims() {
    const grid = document.querySelector("[data-claim-grid]");
    grid.replaceChildren();
    state.data.claims.forEach((claim) => {
      const card = element("article", "claim-card");
      const header = element("div", "claim-card-header");
      const identity = element("div");
      identity.append(element("span", "claim-id", claim.claim_id));
      identity.append(element("h3", "", claim.title));
      header.append(identity, element("span", "evidence-level", `${claim.evidence_level} · ${claim.review_type}`));
      card.append(header);

      const score = element("div", "claim-score");
      score.append(element("strong", "", `${claim.results.passed}/${claim.results.denominator}`));
      score.append(element("span", "", "fixed synthetic observations matched project-authored expectations"));
      card.append(score);

      const list = element("ul", "claim-highlights");
      claim.highlights.forEach((highlight) => list.append(element("li", "", highlight)));
      card.append(list);
      card.append(element("p", "claim-limitation", `Limitation: ${claim.limitation}`));
      const link = element("a", "", `Inspect ${claim.claim_id} evidence ↗`);
      setExternalLink(link, claim.source_url);
      card.append(link);
      grid.append(card);
    });
  }

  function renderModelSnapshot() {
    const snapshot = state.data.model_snapshot;
    document.querySelector("[data-model-label]").textContent = `${snapshot.version} · ${snapshot.evaluated_cases} synthetic cases`;
    document.querySelector("[data-model-interpretation]").textContent = snapshot.interpretation;
    setExternalLink(document.querySelector("[data-model-source]"), snapshot.source_url);
    const metrics = [
      [percentage(snapshot.metrics.accuracy_at_0_5), "Model accuracy at 0.5"],
      [snapshot.metrics.brier_score.toFixed(4), "Brier score"],
      [percentage(snapshot.metrics.roc_auc), "ROC AUC"],
      [percentage(snapshot.metrics.expected_disposition_match_rate), "Expected disposition match"],
      [String(snapshot.metrics.false_containment_count), "False containments"],
      [percentage(snapshot.metrics.post_action_verification_pass_rate), "Complete post-action verification"],
    ];
    const grid = document.querySelector("[data-metric-grid]");
    grid.replaceChildren();
    metrics.forEach(([value, label]) => {
      const card = element("div", "metric");
      card.append(element("strong", "", value), element("span", "", label));
      grid.append(card);
    });
  }

  function renderBoundaries() {
    const list = document.querySelector("[data-non-inferences]");
    list.replaceChildren();
    state.data.non_inferences.forEach((statement) => list.append(element("li", "", statement)));
  }

  function renderAll() {
    renderScenario();
    renderVersionLedger();
    renderClaims();
    renderModelSnapshot();
    renderBoundaries();
  }

  player.addEventListener("click", (event) => {
    const scenarioButton = event.target.closest("[data-scenario-index]");
    if (scenarioButton) {
      chooseScenario(Number(scenarioButton.dataset.scenarioIndex));
      return;
    }
    const stepButton = event.target.closest("[data-step-index]");
    if (stepButton) {
      stopPlayback();
      state.stepIndex = Number(stepButton.dataset.stepIndex);
      renderStage();
      return;
    }
    const control = event.target.closest("[data-action]");
    if (!control) return;
    const steps = buildSteps(currentScenario());
    if (control.dataset.action === "play") {
      startPlayback();
    } else if (control.dataset.action === "replay") {
      runDecision();
    } else {
      stopPlayback();
      state.stepIndex = control.dataset.action === "next"
        ? Math.min(steps.length - 1, state.stepIndex + 1)
        : Math.max(0, state.stepIndex - 1);
      renderStage();
    }
  });

  document.addEventListener("click", (event) => {
    const trigger = event.target.closest?.("[data-run-decision]");
    if (!trigger) return;
    runDecision();
  });

  ui.selector.addEventListener("keydown", (event) => {
    if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
    event.preventDefault();
    let next = state.scenarioIndex;
    if (event.key === "ArrowLeft") next = (next - 1 + state.data.scenarios.length) % state.data.scenarios.length;
    if (event.key === "ArrowRight") next = (next + 1) % state.data.scenarios.length;
    if (event.key === "Home") next = 0;
    if (event.key === "End") next = state.data.scenarios.length - 1;
    chooseScenario(next);
  });

  fetch("./data/public-results.json", { cache: "no-store" })
    .then((response) => {
      if (!response.ok) throw new Error(`Evidence bundle returned ${response.status}`);
      return response.json();
    })
    .then((data) => {
      state.data = data;
      state.scenarioIndex = Math.min(2, data.scenarios.length - 1);
      loading.hidden = true;
      content.hidden = false;
      renderAll();
      if (state.pendingRun) runDecision();
    })
    .catch(() => {
      loading.classList.add("is-error");
      loading.querySelector("span").textContent = "!";
      loading.querySelector("p").textContent = "The validated public evidence bundle could not be loaded. No result will be presented.";
    });
})();
