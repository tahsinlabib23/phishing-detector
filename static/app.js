(() => {
  const securityIntro = document.querySelector("#security-intro");
  const pageShell = document.querySelector(".page-shell");
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  if (securityIntro && !reduceMotion) {
    securityIntro.hidden = false;
    pageShell?.setAttribute("inert", "");

    let introDismissed = false;
    const hideIntro = () => {
      if (introDismissed) return;
      introDismissed = true;
      securityIntro.classList.add("is-leaving");
      window.setTimeout(() => {
        securityIntro.hidden = true;
        pageShell?.removeAttribute("inert");
        document.querySelector("#page-title")?.focus({ preventScroll: true });
      }, 470);
    };

    window.setTimeout(hideIntro, 3000);
  } else {
    securityIntro?.remove();
  }

  const form = document.querySelector("#scan-form");
  const fromField = document.querySelector("#email-from");
  const subjectField = document.querySelector("#email-subject");
  const textarea = document.querySelector("#email-body");
  const error = document.querySelector("#email-error");
  const count = document.querySelector("#character-count");
  const button = document.querySelector("#scan-button");
  let analysisPanel = document.querySelector("#analysis-panel");

  if (analysisPanel?.dataset.scanComplete === "true") {
    window.history.replaceState({ scanComplete: true }, "", "/");
  }

  const animateConfidence = (panel) => {
    const confidenceValue = panel?.querySelector("[data-confidence-value]");
    const confidenceFill = panel?.querySelector("[data-confidence-fill]");
    if (!confidenceValue || !confidenceFill || reduceMotion) return;

    const target = Number(confidenceValue.dataset.confidenceValue);
    const start = performance.now();
    const duration = 820;
    confidenceValue.textContent = "0.0%";
    confidenceFill.style.width = "0%";

    const animateConfidence = (now) => {
      const progress = Math.min((now - start) / duration, 1);
      const eased = 1 - (1 - progress) ** 3;
      confidenceValue.textContent = `${(target * eased).toFixed(1)}%`;
      confidenceFill.style.width = `${target * eased}%`;
      if (progress < 1) requestAnimationFrame(animateConfidence);
    };

    requestAnimationFrame(animateConfidence);
  };

  animateConfidence(analysisPanel);

  if (!form || !fromField || !subjectField || !textarea || !error || !count || !button) return;

  const setSubmitting = (isSubmitting) => {
    form.classList.toggle("is-scanning", isSubmitting);
    analysisPanel?.classList.toggle("is-scanning", isSubmitting);
    if (analysisPanel) analysisPanel.setAttribute("aria-busy", String(isSubmitting));
    button.disabled = isSubmitting;
    button.setAttribute("aria-busy", String(isSubmitting));
    button.querySelector(".button-label").textContent = isSubmitting
      ? "Inspecting email…"
      : "[ scan email ]";
    [fromField, subjectField, textarea].forEach((field) => {
      field.disabled = isSubmitting;
    });
    if (isSubmitting) {
      analysisPanel?.querySelector("#analysis-status")?.replaceChildren(
        document.createTextNode("Inspecting message…"),
      );
    }
  };

  const syncValidation = (parsedPage) => {
    const returnedError = parsedPage.querySelector("#email-error");
    const message = returnedError?.textContent.trim() || "";
    error.textContent = message;
    error.hidden = !message;

    [fromField, subjectField, textarea].forEach((field) => {
      const returnedField = parsedPage.getElementById(field.id);
      if (returnedField?.getAttribute("aria-invalid") === "true") {
        field.setAttribute("aria-invalid", "true");
      } else {
        field.removeAttribute("aria-invalid");
      }
    });
  };

  const showConnectionError = () => {
    if (!analysisPanel) return;
    analysisPanel.classList.remove(
      "analysis-panel--phishing",
      "analysis-panel--legitimate",
      "analysis-panel--input",
      "analysis-panel--model-missing",
    );
    analysisPanel.classList.add("analysis-panel--model-error");
    analysisPanel.dataset.scanComplete = "false";
    analysisPanel.querySelector(".verdict-animation")?.remove();
    analysisPanel.querySelector(".result-content, .empty-state")?.remove();

    const state = document.createElement("div");
    state.className = "empty-state empty-state--model-error";
    const graphic = document.createElement("div");
    graphic.className = "empty-graphic empty-graphic--alert";
    graphic.setAttribute("aria-hidden", "true");
    const symbol = document.createElement("span");
    symbol.className = "empty-symbol";
    symbol.textContent = "×";
    graphic.append(symbol);

    const kicker = document.createElement("p");
    kicker.className = "result-kicker";
    kicker.textContent = "Connection error";
    const heading = document.createElement("h2");
    heading.id = "result-heading";
    heading.textContent = "Scan could not finish";
    const description = document.createElement("p");
    description.className = "result-description";
    description.textContent = "Could not reach the Flask server. Check that it is running, then scan again.";
    state.append(graphic, kicker, heading, description);
    analysisPanel.insertBefore(state, analysisPanel.querySelector(".analysis-footer"));
    const status = analysisPanel.querySelector("#analysis-status");
    if (status) status.textContent = "Scan failed";
  };

  const maxCharacters = Number(textarea.maxLength);
  const emailText = () => {
    const parts = [];
    if (fromField.value.trim()) parts.push(`From: ${fromField.value.trim()}`);
    if (subjectField.value.trim()) parts.push(`Subject: ${subjectField.value.trim()}`);
    const body = textarea.value.trim();
    const headers = parts.join("\n");
    return body ? (headers ? `${headers}\n\n${body}` : body) : headers;
  };

  const updateCount = () => {
    count.textContent = String(emailText().length);
  };

  const clearError = () => {
    if (error.hidden) return;
    error.hidden = true;
    error.textContent = "";
    fromField.removeAttribute("aria-invalid");
    subjectField.removeAttribute("aria-invalid");
    textarea.removeAttribute("aria-invalid");
  };

  [fromField, subjectField, textarea].forEach((field) => field.addEventListener("input", () => {
    updateCount();
    clearError();
  }));

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (button.disabled) return;

    if (!fromField.value.trim()) {
      error.textContent = "Enter the sender shown in the email’s From field.";
      error.hidden = false;
      fromField.setAttribute("aria-invalid", "true");
      fromField.focus();
      return;
    }

    if (!textarea.value.trim()) {
      error.textContent = "Paste the email message body before scanning.";
      error.hidden = false;
      textarea.setAttribute("aria-invalid", "true");
      textarea.focus();
      return;
    }

    if (emailText().length > maxCharacters) {
      error.textContent = `Keep the combined email under ${maxCharacters.toLocaleString()} characters.`;
      error.hidden = false;
      textarea.setAttribute("aria-invalid", "true");
      textarea.focus();
      return;
    }

    clearError();
    const formData = new FormData(form);
    setSubmitting(true);

    try {
      if (!reduceMotion) {
        await new Promise((resolve) => window.setTimeout(resolve, 840));
      }
      const response = await window.fetch(form.action, {
        method: "POST",
        body: formData,
        headers: { "X-Requested-With": "XMLHttpRequest" },
        credentials: "same-origin",
      });
      const responseHtml = await response.text();
      const parsedPage = new DOMParser().parseFromString(responseHtml, "text/html");
      const nextPanel = parsedPage.querySelector("#analysis-panel");
      if (!nextPanel) throw new Error("The server response did not include the result panel.");

      syncValidation(parsedPage);
      analysisPanel?.replaceWith(document.importNode(nextPanel, true));
      analysisPanel = document.querySelector("#analysis-panel");
      animateConfidence(analysisPanel);
    } catch (scanError) {
      console.error("Email scan request failed", scanError);
      error.textContent = "The scan request failed. Check that the Flask server is running and try again.";
      error.hidden = false;
      showConnectionError();
    } finally {
      setSubmitting(false);
      updateCount();
    }
  });

  updateCount();
})();
