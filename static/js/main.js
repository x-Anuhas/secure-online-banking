/* Browser interactions, validation, account security, receipts, and visualizers. */

(() => {
  "use strict";

  const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || "";
  const deviceStorageKey = "finbest-demo-device-id";
  document.documentElement.classList.add("motion-ready");
  const themeStorageKey = "finbest-theme-cyberbank";
  let savedTheme = "dark";
  try {
    savedTheme = localStorage.getItem(themeStorageKey) || "dark";
  } catch {
    savedTheme = "light";
  }
  const themeToggle = document.querySelector("[data-theme-toggle]");
  const applyTheme = (theme) => {
    document.documentElement.dataset.theme = theme;
    if (themeToggle) {
      const dark = theme === "dark";
      themeToggle.setAttribute("aria-pressed", String(dark));
      themeToggle.setAttribute("aria-label", `Switch to ${dark ? "light" : "dark"} mode`);
      themeToggle.querySelector("[data-theme-icon]").textContent = dark ? "☀" : "◐";
    }
  };
  applyTheme(savedTheme === "dark" ? "dark" : "light");
  themeToggle?.addEventListener("click", () => {
    const theme = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    try {
      localStorage.setItem(themeStorageKey, theme);
    } catch {
      showMessage(
        document.querySelector("#global-message"),
        "Theme preference could not be saved in this browser.",
        "error",
      );
    }
    applyTheme(theme);
  });

  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const revealElements = document.querySelectorAll(".reveal");
  if ("IntersectionObserver" in window && !reducedMotion) {
    const revealObserver = new IntersectionObserver((entries, observer) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        entry.target.classList.add("is-visible");
        observer.unobserve(entry.target);
      });
    }, { threshold: 0.14 });
    revealElements.forEach((element) => revealObserver.observe(element));
    const revealVisibleElements = () => {
      revealElements.forEach((element) => {
        if (element.classList.contains("is-visible")) return;
        const bounds = element.getBoundingClientRect();
        if (bounds.top < window.innerHeight * 0.92 && bounds.bottom > 0) {
          element.classList.add("is-visible");
          revealObserver.unobserve(element);
        }
      });
    };
    requestAnimationFrame(revealVisibleElements);
    window.addEventListener("scroll", revealVisibleElements, { passive: true });
    window.addEventListener("resize", revealVisibleElements, { passive: true });
  } else {
    revealElements.forEach((element) => element.classList.add("is-visible"));
  }

  const parallaxHeadings = document.querySelectorAll(".landing-main .section-heading");
  if (parallaxHeadings.length && !reducedMotion) {
    let parallaxFrame = 0;
    const updateParallax = () => {
      parallaxFrame = 0;
      const viewportCenter = window.innerHeight / 2;
      parallaxHeadings.forEach((heading) => {
        const bounds = heading.getBoundingClientRect();
        if (bounds.bottom < 0 || bounds.top > window.innerHeight) {
          heading.style.removeProperty("--scroll-parallax-y");
          return;
        }
        const centerOffset = bounds.top + bounds.height / 2 - viewportCenter;
        const translateY = Math.max(-8, Math.min(8, centerOffset / window.innerHeight * -12));
        heading.style.setProperty("--scroll-parallax-y", `${translateY.toFixed(2)}px`);
      });
    };
    const requestParallaxUpdate = () => {
      if (parallaxFrame) return;
      parallaxFrame = requestAnimationFrame(updateParallax);
    };
    updateParallax();
    window.addEventListener("scroll", requestParallaxUpdate, { passive: true });
    window.addEventListener("resize", requestParallaxUpdate, { passive: true });
  }

  const header = document.querySelector("#site-header");
  if (header) {
    const updateHeader = () => header.classList.toggle("scrolled", window.scrollY > 12);
    updateHeader();
    window.addEventListener("scroll", updateHeader, { passive: true });
  }

  const menuToggle = document.querySelector("#menu-toggle");
  const mainNav = document.querySelector("#main-nav");
  if (menuToggle && mainNav) {
    menuToggle.addEventListener("click", () => {
      const expanded = menuToggle.getAttribute("aria-expanded") === "true";
      menuToggle.setAttribute("aria-expanded", String(!expanded));
      menuToggle.setAttribute(
        "aria-label",
        expanded ? "Open navigation menu" : "Close navigation menu",
      );
      mainNav.classList.toggle("open", !expanded);
    });
    mainNav.querySelectorAll("a").forEach((link) => {
      link.addEventListener("click", () => {
        mainNav.classList.remove("open");
        menuToggle.setAttribute("aria-expanded", "false");
        menuToggle.setAttribute("aria-label", "Open navigation menu");
      });
    });
  }

  const counters = document.querySelectorAll(".count-up[data-count]");
  if (counters.length) {
    const animateCounter = (element) => {
      const target = Number(element.dataset.count);
      if (!Number.isFinite(target)) return;
      if (reducedMotion) {
        element.textContent = target.toLocaleString();
        return;
      }
      const duration = 1100;
      const start = performance.now();
      const update = (now) => {
        const progress = Math.min((now - start) / duration, 1);
        const eased = 1 - (1 - progress) ** 3;
        element.textContent = Math.round(target * eased).toLocaleString();
        if (progress < 1) requestAnimationFrame(update);
      };
      requestAnimationFrame(update);
    };
    if ("IntersectionObserver" in window && !reducedMotion) {
      const counterObserver = new IntersectionObserver((entries, observer) => {
        entries.forEach((entry) => {
          if (!entry.isIntersecting) return;
          animateCounter(entry.target);
          observer.unobserve(entry.target);
        });
      }, { threshold: 0.6 });
      counters.forEach((counter) => counterObserver.observe(counter));
    } else {
      counters.forEach(animateCounter);
    }
  }

  const finePointer = window.matchMedia("(hover: hover) and (pointer: fine)").matches;
  const cardScene = document.querySelector(".demo-card-scene");
  if (finePointer && !reducedMotion && cardScene) {
    cardScene.addEventListener("pointermove", (event) => {
      if (event.pointerType !== "mouse") return;
      const bounds = cardScene.getBoundingClientRect();
      const horizontal = (event.clientX - bounds.left) / bounds.width - 0.5;
      const vertical = (event.clientY - bounds.top) / bounds.height - 0.5;
      cardScene.style.setProperty("--card-tilt-x", `${(-vertical * 8).toFixed(2)}deg`);
      cardScene.style.setProperty("--card-tilt-y", `${(horizontal * 10).toFixed(2)}deg`);
      cardScene.style.setProperty("--glare-x", `${((horizontal + 0.5) * 100).toFixed(1)}%`);
      cardScene.style.setProperty("--glare-y", `${((vertical + 0.5) * 100).toFixed(1)}%`);
      cardScene.style.setProperty("--glare-angle", `${(115 + horizontal * 35).toFixed(1)}deg`);
      cardScene.classList.add("is-card-tilting");
    }, { passive: true });
    cardScene.addEventListener("pointerleave", () => {
      cardScene.classList.remove("is-card-tilting");
      cardScene.style.removeProperty("--card-tilt-x");
      cardScene.style.removeProperty("--card-tilt-y");
      cardScene.style.removeProperty("--glare-x");
      cardScene.style.removeProperty("--glare-y");
      cardScene.style.removeProperty("--glare-angle");
    });
  }

  if (finePointer && !reducedMotion) {
    document.querySelectorAll(".spotlight-card").forEach((card) => {
      const glow = document.createElement("span");
      glow.className = "spotlight-glow";
      glow.setAttribute("aria-hidden", "true");
      card.prepend(glow);

      card.addEventListener("pointermove", (event) => {
        if (event.pointerType !== "mouse") return;
        const bounds = card.getBoundingClientRect();
        const x = event.clientX - bounds.left;
        const y = event.clientY - bounds.top;
        glow.style.setProperty("--spotlight-x", `${x}px`);
        glow.style.setProperty("--spotlight-y", `${y}px`);
        card.style.setProperty(
          "--card-tilt-x",
          `${(((y / bounds.height) - 0.5) * -2.4).toFixed(2)}deg`,
        );
        card.style.setProperty(
          "--card-tilt-y",
          `${(((x / bounds.width) - 0.5) * 2.8).toFixed(2)}deg`,
        );
        card.classList.add("is-pointer-active");
      }, { passive: true });

      card.addEventListener("pointerleave", () => {
        card.classList.remove("is-pointer-active");
        card.style.removeProperty("--card-tilt-x");
        card.style.removeProperty("--card-tilt-y");
      });
    });

    document.querySelectorAll(".hero-primary").forEach((button) => {
      button.addEventListener("pointermove", (event) => {
        if (event.pointerType !== "mouse") return;
        const bounds = button.getBoundingClientRect();
        const x = event.clientX - bounds.left - bounds.width / 2;
        const y = event.clientY - bounds.top - bounds.height / 2;
        button.style.setProperty("--magnetic-x", `${(x * 0.08).toFixed(2)}px`);
        button.style.setProperty("--magnetic-y", `${(y * 0.12).toFixed(2)}px`);
      }, { passive: true });

      button.addEventListener("pointerleave", () => {
        button.style.removeProperty("--magnetic-x");
        button.style.removeProperty("--magnetic-y");
      });

      button.addEventListener("pointerdown", (event) => {
        if (event.pointerType !== "mouse") return;
        const bounds = button.getBoundingClientRect();
        const ripple = document.createElement("span");
        ripple.className = "button-ripple";
        ripple.style.left = `${event.clientX - bounds.left}px`;
        ripple.style.top = `${event.clientY - bounds.top}px`;
        button.append(ripple);
        ripple.addEventListener("animationend", () => ripple.remove(), { once: true });
      });
    });
  }

  const sandbox = document.querySelector("[data-transfer-sandbox]");
  const sandboxAmount = sandbox?.querySelector("[data-sandbox-amount]");
  if (sandbox && sandboxAmount) {
    const senderBalance = sandbox.querySelector("[data-sandbox-sender]");
    const recipientBalance = sandbox.querySelector("[data-sandbox-recipient]");
    const statusText = sandbox.querySelector("[data-sandbox-status-text]");
    const startingSender = Number(sandbox.dataset.senderStart);
    const startingRecipient = Number(sandbox.dataset.recipientStart);
    const formatCurrency = (amount) => `$${amount.toLocaleString("en-US", {
      minimumFractionDigits: 2,
      maximumFractionDigits: 2,
    })}`;

    const updateSandbox = () => {
      const amount = Number(sandboxAmount.value);
      const valid = sandboxAmount.checkValidity()
        && Number.isFinite(amount)
        && amount <= startingSender;
      sandboxAmount.setAttribute("aria-invalid", String(!valid));
      sandbox.classList.toggle("is-invalid", !valid);

      if (!valid) {
        statusText.textContent = "Enter $100–$500";
        return;
      }

      senderBalance.textContent = formatCurrency(startingSender - amount);
      recipientBalance.textContent = formatCurrency(startingRecipient + amount);
      statusText.textContent = "Preview updated";
      sandbox.classList.remove("is-updated");
      requestAnimationFrame(() => sandbox.classList.add("is-updated"));
    };

    sandboxAmount.addEventListener("input", updateSandbox);
  }

  function browserDeviceId() {
    try {
      let value = localStorage.getItem(deviceStorageKey);
      if (!value) {
        value = crypto.randomUUID().replaceAll("-", "");
        localStorage.setItem(deviceStorageKey, value);
      }
      return value;
    } catch {
      return crypto.randomUUID().replaceAll("-", "");
    }
  }

  function showMessage(element, message, kind = "") {
    if (!element) return;
    element.textContent = message;
    element.className = `form-message visible ${kind}`.trim();
    element.setAttribute("role", "status");
  }

  async function api(path, payload = {}, method = "POST") {
    const response = await fetch(path, {
      method,
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": csrfToken,
      },
      body: method === "GET" ? undefined : JSON.stringify(payload),
    });
    let data;
    try {
      data = await response.json();
    } catch {
      throw new Error("The server returned an unreadable response.");
    }
    if (!response.ok) {
      const error = new Error(data.error || "The request could not be completed.");
      error.data = data;
      throw error;
    }
    return data;
  }

  const adminRiskForm = document.querySelector("#admin-risk-form");
  adminRiskForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const thresholdInput = adminRiskForm.querySelector('[name="amount_ratio_limit"]');
    const message = document.querySelector("#admin-risk-message");
    if (!validateField(thresholdInput)) {
      showMessage(message, "Enter a whole-number threshold from 1 to 100.", "error");
      return;
    }
    try {
      const result = await api("/api/admin/transfer-risk", {
        amount_ratio_limit: thresholdInput.value,
      });
      showMessage(message, result.message, "success");
    } catch (error) {
      showMessage(message, error.message, "error");
    }
  });

  document.querySelector("#locked-account-rows")?.addEventListener("click", async (event) => {
    const button = event.target instanceof Element
      ? event.target.closest("[data-unlock-account]")
      : null;
    if (!button) return;
    button.disabled = true;
    try {
      const result = await api(
        `/api/admin/accounts/${encodeURIComponent(button.dataset.unlockAccount)}/unlock`,
      );
      button.closest("[data-locked-account]")?.remove();
      const rows = document.querySelector("#locked-account-rows");
      if (rows && !rows.children.length) {
        rows.closest(".table-wrap").replaceWith(
          Object.assign(document.createElement("p"), {
            id: "locked-account-empty",
            textContent: "There are no locked accounts.",
          }),
        );
      }
      showMessage(document.querySelector("#admin-account-message"), result.message, "success");
    } catch (error) {
      button.disabled = false;
      showMessage(document.querySelector("#admin-account-message"), error.message, "error");
    }
  });

  document.querySelector("#admin-customer-rows")?.addEventListener("click", async (event) => {
    const button = event.target instanceof Element
      ? event.target.closest("[data-toggle-transfer-access]")
      : null;
    if (!button) return;
    const currentlyEnabled = button.dataset.canTransfer === "true";
    button.disabled = true;
    try {
      const result = await api(
        `/api/admin/accounts/${encodeURIComponent(button.dataset.toggleTransferAccess)}/transfer-access`,
        { can_transfer: !currentlyEnabled },
      );
      button.dataset.canTransfer = String(result.can_transfer);
      button.textContent = result.can_transfer ? "Block transfers" : "Enable transfers";
      const transferState = button.closest("[data-customer-account]")
        ?.querySelector("[data-transfer-state]");
      if (transferState) {
        transferState.textContent = result.can_transfer ? "Enabled" : "Blocked";
      }
      showMessage(
        document.querySelector("#admin-transfer-access-message"),
        result.message,
        "success",
      );
    } catch (error) {
      showMessage(
        document.querySelector("#admin-transfer-access-message"),
        error.message,
        "error",
      );
    } finally {
      button.disabled = false;
    }
  });

  document.querySelector("#verify-audit-chain")?.addEventListener("click", async () => {
    const status = document.querySelector("#audit-chain-status");
    const button = document.querySelector("#verify-audit-chain");
    button.disabled = true;
    try {
      const result = await api("/api/admin/audit-chain/verify", {}, "GET");
      status.dataset.auditValid = String(result.valid);
      status.textContent = result.valid
        ? `Verified · ${result.entries_checked} entries checked`
        : `Integrity failure · first invalid entry: ${result.first_invalid_id}`;
      showMessage(status, status.textContent, result.valid ? "success" : "error");
    } catch (error) {
      showMessage(status, error.message, "error");
    } finally {
      button.disabled = false;
    }
  });

  function validateField(input) {
    if (!input || !input.willValidate) return true;
    const valid = input.checkValidity();
    input.setAttribute("aria-invalid", String(!valid));
    return valid;
  }

  document.querySelectorAll("input").forEach((input) => {
    input.addEventListener("input", () => validateField(input));
    input.addEventListener("blur", () => validateField(input));
  });

  async function geolocationForLogin(form) {
    const consent = form.querySelector('[name="share_location"]');
    if (!consent?.checked || !navigator.geolocation) return {};
    return new Promise((resolve) => {
      navigator.geolocation.getCurrentPosition(
        ({ coords }) => resolve({
          latitude: coords.latitude,
          longitude: coords.longitude,
        }),
        () => resolve({}),
        { maximumAge: 300000, timeout: 4000 },
      );
    });
  }

  const authForm = document.querySelector("#auth-form");
  if (authForm) {
    authForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const message = document.querySelector("#auth-message");
      if (![...authForm.querySelectorAll("input")].every(validateField)) {
        showMessage(message, "Please correct the highlighted fields.", "error");
        return;
      }
      const formData = new FormData(authForm);
      const payload = Object.fromEntries(formData.entries());
      try {
        const result = await api("/api/register", payload);
        showMessage(
          message,
          `${result.message} Your new account number is ${result.account_number}.`,
          "success",
        );
        authForm.querySelector('[name="password"]').value = "";
      } catch (error) {
        showMessage(message, error.message, "error");
      }
    });
  }

  const loginForm = document.querySelector("#auth-form-login");
  if (loginForm) {
    const verificationForm = document.querySelector("#login-verification-form");
    let loginChallengeId = "";
    let loginVerificationMethod = "payment_pin";
    const finishLogin = (result) => {
      if (
        typeof result.redirect !== "string"
        || !result.redirect.startsWith("/")
        || result.redirect.startsWith("//")
      ) {
        throw new Error(
          "The server returned an outdated sign-in response. Restart the app, then sign in again.",
        );
      }
      window.location.assign(result.redirect);
    };

    loginForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const message = document.querySelector("#auth-message");
      if (![...loginForm.querySelectorAll("input")].every(validateField)) {
        showMessage(message, "Please correct the highlighted fields.", "error");
        return;
      }
      const payload = Object.fromEntries(new FormData(loginForm).entries());
      payload.device_id = browserDeviceId();
      try {
        Object.assign(payload, await geolocationForLogin(loginForm));
        const result = await api("/api/login", payload);
        if (result.verification_required === true) {
          if (typeof result.challenge_id !== "string" || !verificationForm) {
            throw new Error("The sign-in verification challenge could not be started.");
          }
          loginChallengeId = result.challenge_id;
          loginVerificationMethod = result.verification_method;
          loginForm.hidden = true;
          verificationForm.hidden = false;
          const factorLabel = verificationForm.querySelector("#login-factor-label");
          const factorInput = verificationForm.querySelector('[name="factor_code"]');
          const isTotp = loginVerificationMethod === "totp";
          factorLabel.textContent = isTotp
            ? "Authenticator or recovery code"
            : "Payment Password";
          factorInput.type = isTotp ? "text" : "password";
          factorInput.inputMode = isTotp ? "text" : "numeric";
          factorInput.placeholder = isTotp
            ? "Six-digit code or 16-character recovery code"
            : "Enter your six-digit PIN";
          verificationForm.querySelector("#login-step-up-reason").textContent =
            `Additional verification is required: ${(result.risk?.reasons || []).join(" ")}`;
          factorInput.focus();
          return;
        }
        finishLogin(result);
      } catch (error) {
        showMessage(message, error.message, "error");
      }
    });

    verificationForm?.addEventListener("submit", async (event) => {
      event.preventDefault();
      const factorInput = verificationForm.querySelector('[name="factor_code"]');
      const message = document.querySelector("#login-verification-message");
      if (!validateField(factorInput) || !loginChallengeId) {
        showMessage(message, "Enter a valid verification code.", "error");
        return;
      }
      const submitButton = verificationForm.querySelector('[type="submit"]');
      submitButton.disabled = true;
      try {
        const verificationPayload = loginVerificationMethod === "totp"
          ? { totp_code: factorInput.value }
          : { payment_pin: factorInput.value };
        const result = await api("/api/login/verify", {
          challenge_id: loginChallengeId,
          ...verificationPayload,
        });
        finishLogin(result);
      } catch (error) {
        showMessage(message, error.message, "error");
        factorInput.value = "";
        factorInput.focus();
      } finally {
        submitButton.disabled = false;
      }
    });

    document.querySelector("#cancel-login-verification")?.addEventListener("click", () => {
      loginChallengeId = "";
      loginVerificationMethod = "payment_pin";
      verificationForm.hidden = true;
      verificationForm.reset();
      loginForm.hidden = false;
      loginForm.querySelector('[name="username"]').focus();
    });
  }

  const transferForm = document.querySelector("#transfer-form");
  if (transferForm) {
    const balanceDisplay = document.querySelector(".sum-card.balance .sum-v");
    let pendingTransfer = null;
    const idempotencyStorageKey = "finbest-transfer-request";
    const transferRequestKeys = new Map();
    const transferFingerprint = (payload) => JSON.stringify([
      String(payload.recipient || "").trim(),
      String(payload.amount || "").trim(),
      String(payload.reference || "").trim(),
    ]);
    const transferRequestKey = (payload) => {
      const fingerprint = transferFingerprint(payload);
      if (transferRequestKeys.has(fingerprint)) {
        return transferRequestKeys.get(fingerprint);
      }
      try {
        const saved = JSON.parse(sessionStorage.getItem(idempotencyStorageKey) || "null");
        if (saved?.fingerprint === fingerprint && /^[A-Za-z0-9_-]{16,80}$/.test(saved.key)) {
          transferRequestKeys.set(fingerprint, saved.key);
          return saved.key;
        }
      } catch {
        // Keep the request key in memory when browser storage is unavailable.
      }
      const key = crypto.randomUUID();
      transferRequestKeys.set(fingerprint, key);
      try {
        sessionStorage.setItem(idempotencyStorageKey, JSON.stringify({ fingerprint, key }));
      } catch {
        // The key remains reusable for retries until this page is closed.
      }
      return key;
    };

    transferForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const message = document.querySelector("#transfer-message");
      if (![...transferForm.querySelectorAll("input")].every(validateField)) {
        showMessage(message, "Please correct the highlighted fields.", "error");
        return;
      }
      const payload = Object.fromEntries(new FormData(transferForm).entries());
      const confirmationModal = document.getElementById("transfer-confirm-modal");
      if (!confirmationModal) {
        showMessage(message, "Transfer authorization is unavailable. Reload the page and try again.", "error");
        return;
      }
      pendingTransfer = {
        ...payload,
        idempotency_key: transferRequestKey(payload),
      };
      const amount = Number(pendingTransfer.amount);
      confirmationModal.querySelector("[data-confirm-recipient]").textContent =
        pendingTransfer.recipient.trim();
      confirmationModal.querySelector("[data-confirm-amount]").textContent =
        Number.isFinite(amount)
          ? new Intl.NumberFormat(undefined, { style: "currency", currency: "USD" }).format(amount)
          : "—";
      confirmationModal.querySelector("[data-confirm-reference]").textContent =
        pendingTransfer.reference.trim() || "None";
      confirmationModal.querySelector("[data-transfer-icon]").classList.remove("is-success");
      confirmationModal.querySelector("#transfer-payment-pin").value = "";
      const totpInput = confirmationModal.querySelector("#transfer-totp-code");
      if (totpInput) totpInput.value = "";
      confirmationModal.querySelector("#transfer-confirm-title").textContent = "Confirm this transfer";
      confirmationModal.querySelector("[data-transfer-status]").textContent =
        "Review the details carefully before sending.";
      const confirmButton = confirmationModal.querySelector("#confirm-transfer");
      const doneButton = confirmationModal.querySelector(".transfer-confirm-done");
      confirmButton.hidden = false;
      doneButton.hidden = true;
      confirmButton.disabled = false;
      confirmButton.innerHTML = 'Confirm transfer <span aria-hidden="true">→</span>';
      confirmationModal.hidden = false;
      confirmationModal.classList.add("visible");
      confirmButton.focus();
    });

    document.addEventListener("click", async (event) => {
      const target = event.target instanceof Element
        ? event.target.closest("#confirm-transfer")
        : null;
      if (!target) return;
      const confirmationModal = document.getElementById("transfer-confirm-modal");
      const confirmationStatus = confirmationModal?.querySelector("[data-transfer-status]");
      const confirmButton = target;
      if (!pendingTransfer) return;
      if (!confirmationModal || !confirmationStatus) {
        showMessage(
          document.querySelector("#transfer-message"),
          "Transfer authorization is unavailable. Reload the page and try again.",
          "error",
        );
        return;
      }
      const doneButton = confirmationModal.querySelector(".transfer-confirm-done");
      const pinInput = confirmationModal.querySelector("#transfer-payment-pin");
      const paymentPin = pinInput.value.trim();
      if (!/^[0-9]{6}$/.test(paymentPin)) {
        pinInput.setAttribute("aria-invalid", "true");
        confirmationStatus.textContent = "Enter your six-digit Payment Password to continue.";
        pinInput.focus();
        return;
      }
      pinInput.removeAttribute("aria-invalid");
      const totpInput = confirmationModal.querySelector("#transfer-totp-code");
      const highValueTransfer = Number(pendingTransfer.amount) >= 1000;
      const totpCode = totpInput?.value.trim() || "";
      if (
        highValueTransfer
        && totpInput
        && !/^(?:[0-9]{6}|[A-Fa-f0-9]{16})$/.test(totpCode)
      ) {
        totpInput.setAttribute("aria-invalid", "true");
        confirmationStatus.textContent =
          "Enter a six-digit authenticator code or a 16-character recovery code.";
        totpInput.focus();
        return;
      }
      totpInput?.removeAttribute("aria-invalid");
      confirmButton.disabled = true;
      confirmButton.textContent = "Authorizing securely…";
      try {
        const result = await api("/api/transfer", {
          ...pendingTransfer,
          payment_pin: paymentPin,
          ...(highValueTransfer && totpCode ? { totp_code: totpCode } : {}),
        });
        pinInput.value = "";
        if (totpInput) totpInput.value = "";
        showMessage(document.querySelector("#transfer-message"), result.message, "success");
        if (balanceDisplay && Number.isFinite(Number(result.balance))) {
          balanceDisplay.textContent = new Intl.NumberFormat(undefined, {
            style: "currency",
            currency: "USD",
          }).format(Number(result.balance));
        }
        confirmationModal.querySelector("[data-transfer-icon]").classList.add("is-success");
        confirmationModal.querySelector("#transfer-confirm-title").textContent = "Transfer completed";
        confirmationStatus.textContent = "The transfer was recorded successfully.";
        confirmButton.hidden = true;
        doneButton.hidden = false;
        transferRequestKeys.delete(transferFingerprint(pendingTransfer));
        try {
          sessionStorage.removeItem(idempotencyStorageKey);
        } catch {
          // The completed request key is no longer used in this page.
        }
        pendingTransfer = null;
        try {
          const receipt = await api(
            `/api/receipt/${encodeURIComponent(result.receipt_id)}`,
            {},
            "GET",
          );
          renderReceipt(receipt);
        } catch (receiptError) {
          confirmationStatus.textContent =
            `Transfer completed. The receipt could not be loaded: ${receiptError.message}`;
        }
      } catch (error) {
        pinInput.value = "";
        confirmationStatus.textContent = error.message;
        confirmButton.disabled = false;
        confirmButton.innerHTML = 'Try again <span aria-hidden="true">↻</span>';
        pinInput.focus();
      }
    });
  }

  function renderReceipt(receipt) {
    const modal = document.querySelector("#receipt-modal");
    if (!modal) return;
    const setText = (selector, value) => {
      modal.querySelector(selector).textContent = value;
    };
    setText("[data-receipt-date]", new Date(receipt.created_at * 1000).toLocaleString());
    setText("[data-receipt-id]", receipt.transaction_id);
    setText("[data-receipt-sender]", receipt.sender_name);
    setText("[data-receipt-sender-account]", `Account ${receipt.sender_account}`);
    setText("[data-receipt-recipient]", receipt.recipient_name);
    setText("[data-receipt-recipient-account]", `Account ${receipt.recipient_account}`);
    setText("[data-receipt-amount]", `$${receipt.amount}`);
    setText("[data-receipt-fee]", `$${receipt.fee}`);
    setText("[data-receipt-reference]", receipt.reference || "—");
    modal.querySelector("[data-receipt-qr]").src = receipt.qr_data;
    modal.dataset.receiptId = receipt.transaction_id;
    modal.dataset.receiptAmount = receipt.amount;
    modal.dataset.receiptUrl = receipt.verification_url;
    modal.dataset.receipt = JSON.stringify(receipt);
    modal.hidden = false;
    modal.classList.add("visible");
    modal.querySelector("[data-receipt-back]").focus();
  }

  const profileMessage = document.querySelector("#profile-message");
  const mfaSetupButton = document.querySelector("#mfa-setup-button");
  mfaSetupButton?.addEventListener("click", async () => {
    const message = document.querySelector("#mfa-message");
    mfaSetupButton.disabled = true;
    try {
      const result = await api("/api/mfa/setup");
      document.querySelector("#mfa-qr-code").src = result.qr_code;
      document.querySelector("#mfa-manual-secret").textContent = result.secret;
      document.querySelector("#mfa-setup-panel").hidden = false;
      showMessage(message, result.message, "success");
    } catch (error) {
      showMessage(message, error.message, "error");
    } finally {
      mfaSetupButton.disabled = false;
    }
  });

  document.querySelector("#mfa-enable-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const code = form.querySelector('[name="totp_code"]');
    const message = document.querySelector("#mfa-message");
    if (!validateField(code)) {
      showMessage(message, "Enter the six-digit code from your authenticator app.", "error");
      return;
    }
    try {
      const result = await api("/api/mfa/enable", { totp_code: code.value });
      document.querySelector("#mfa-status").textContent = "Authenticator MFA is enabled.";
      document.querySelector("#mfa-setup-button").hidden = true;
      document.querySelector("#mfa-setup-panel").hidden = true;
      const recoveryPanel = document.querySelector("#mfa-recovery-codes");
      recoveryPanel.querySelector("pre").textContent = result.recovery_codes.join("\n");
      recoveryPanel.hidden = false;
      showMessage(message, result.message, "success");
    } catch (error) {
      showMessage(message, error.message, "error");
    }
  });

  document.querySelector("#mfa-disable-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const message = document.querySelector("#mfa-message");
    if (![...form.querySelectorAll("input")].every(validateField)) {
      showMessage(message, "Enter your current password and a valid authenticator or recovery code.", "error");
      return;
    }
    try {
      const result = await api(
        "/api/mfa/disable",
        Object.fromEntries(new FormData(form).entries()),
      );
      showMessage(message, result.message, "success");
      window.location.reload();
    } catch (error) {
      showMessage(message, error.message, "error");
    }
  });

  const profileFormRoutes = [
    ["#profile-phone-form", "/api/profile/phone"],
    ["#profile-password-form", "/api/profile/password"],
  ];
  profileFormRoutes.forEach(([selector, endpoint]) => {
    const form = document.querySelector(selector);
    form?.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (![...form.querySelectorAll("input")].every(validateField)) {
        showMessage(profileMessage, "Please correct the highlighted fields.", "error");
        return;
      }
      try {
        const result = await api(endpoint, Object.fromEntries(new FormData(form).entries()));
        showMessage(profileMessage, result.message, "success");
        form.reset();
        if (selector === "#profile-phone-form") {
          form.querySelector('[name="phone"]').value = result.phone;
        }
      } catch (error) {
        showMessage(profileMessage, error.message, "error");
      }
    });
  });

  const profilePhotoInput = document.querySelector("#profile-photo");
  profilePhotoInput?.addEventListener("change", async () => {
    const file = profilePhotoInput.files?.[0];
    if (!file) return;
    if (file.size > 2 * 1024 * 1024) {
      showMessage(profileMessage, "Profile images must be 2 MB or smaller.", "error");
      profilePhotoInput.value = "";
      return;
    }
    const formData = new FormData();
    formData.append("photo", file);
    try {
      const response = await fetch("/api/profile/photo", {
        method: "POST",
        credentials: "same-origin",
        headers: { "X-CSRF-Token": csrfToken },
        body: formData,
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || "Could not update profile picture.");
      const currentAvatar = document.querySelector("#profile-avatar");
      const image = document.createElement("img");
      image.className = "profile-avatar";
      image.id = "profile-avatar";
      image.alt = "Your profile picture";
      image.src = result.image_url;
      currentAvatar.replaceWith(image);
      const headerAvatar = document.querySelector(".user-chip .user-avatar");
      if (headerAvatar) {
        const headerImage = document.createElement("img");
        headerImage.className = "user-avatar";
        headerImage.src = result.image_url;
        headerImage.alt = "";
        headerAvatar.replaceWith(headerImage);
      }
      showMessage(profileMessage, result.message, "success");
    } catch (error) {
      showMessage(profileMessage, error.message, "error");
    } finally {
      profilePhotoInput.value = "";
    }
  });

  document.querySelector("[data-download-receipt]")?.addEventListener("click", () => {
    const modal = document.querySelector("#receipt-modal");
    if (!modal) return;
    const receipt = JSON.parse(modal.dataset.receipt || "{}");
    const lines = [
      "FinBest - PAYMENT RECEIPT",
      "Status: SUCCESSFUL",
      `Transaction ID: ${modal.dataset.receiptId}`,
      `Date/time: ${new Date(receipt.created_at * 1000).toLocaleString()}`,
      `Sender: ${receipt.sender_name} / ${receipt.sender_account}`,
      `Recipient: ${receipt.recipient_name} / ${receipt.recipient_account}`,
      `Amount: $${modal.dataset.receiptAmount}`,
      `Fee: $${receipt.fee}`,
      `Reference: ${receipt.reference || "—"}`,
      `Verification: ${modal.dataset.receiptUrl}`,
      "FinBest activity record only. This is not proof of a payment through a financial institution.",
    ];
    const link = document.createElement("a");
    link.href = URL.createObjectURL(new Blob([lines.join("\n")], { type: "text/plain" }));
    link.download = `${modal.dataset.receiptId || "finbest-receipt"}.txt`;
    link.click();
    URL.revokeObjectURL(link.href);
  });

  const logoutButton = document.querySelector("#logout-button");
  if (logoutButton) {
    logoutButton.addEventListener("click", async () => {
      try {
        const result = await api("/api/logout", {});
        window.location.assign(result.redirect);
      } catch (error) {
        showMessage(document.querySelector("#global-message"), error.message, "error");
      }
    });
  }

  const copyAccountButton = document.querySelector("#copy-account");
  if (copyAccountButton) {
    copyAccountButton.addEventListener("click", async () => {
      const accountNumber = copyAccountButton.dataset.copy;
      try {
        await navigator.clipboard.writeText(accountNumber);
        copyAccountButton.innerHTML = "<span aria-hidden=\"true\">✓</span> Copied";
        window.setTimeout(() => {
          copyAccountButton.innerHTML = "<span aria-hidden=\"true\">▣</span> Copy number";
        }, 1600);
      } catch {
        showMessage(
          document.querySelector("#global-message"),
          "Clipboard access is unavailable. Select and copy the account number.",
          "error",
        );
      }
    });
  }

  const transactionSearch = document.querySelector("#transaction-search");
  const transactionFilter = document.querySelector("#transaction-filter");
  const transactionRows = [...document.querySelectorAll("#transaction-rows tr")];
  if (transactionRows.length && (transactionSearch || transactionFilter)) {
    const emptyFiltered = document.querySelector("#transaction-empty-filter");
    const filterRows = () => {
      const query = transactionSearch?.value.trim().toLocaleLowerCase() || "";
      const direction = transactionFilter?.value || "all";
      let visibleCount = 0;
      transactionRows.forEach((row) => {
        const matchesText = (row.dataset.search || "").includes(query);
        const matchesType = direction === "all" || row.dataset.direction === direction;
        const visible = matchesText && matchesType;
        row.hidden = !visible;
        if (visible) visibleCount += 1;
      });
      if (emptyFiltered) emptyFiltered.hidden = visibleCount !== 0;
    };
    transactionSearch?.addEventListener("input", filterRows);
    transactionFilter?.addEventListener("change", filterRows);
  }

  document.addEventListener("click", (event) => {
    const button = event.target instanceof Element
      ? event.target.closest("[data-close-modal]")
      : null;
    if (button) {
      const modalSelector = button.dataset.closeModal;
      const modal = modalSelector?.startsWith("#")
        ? document.getElementById(modalSelector.slice(1))
        : document.querySelector(modalSelector);
      if (!modal) return;
      modal.classList.remove("visible");
      modal.hidden = true;
      if (modal.id === "transfer-confirm-modal") {
        modal.querySelector("#transfer-payment-pin").value = "";
        document.querySelector("#transfer-form [type='submit']")?.focus();
      } else if (modal.id === "receipt-modal") {
        document.querySelector("#transfer-form [type='submit']")?.focus();
      }
    }
  });

  document.addEventListener("keydown", (event) => {
    if (event.key !== "Escape") return;
    const confirmationModal = document.getElementById("transfer-confirm-modal");
    if (confirmationModal?.classList.contains("visible")) {
      confirmationModal.classList.remove("visible");
      confirmationModal.hidden = true;
      confirmationModal.querySelector("#transfer-payment-pin").value = "";
      document.querySelector("#transfer-form [type='submit']")?.focus();
      return;
    }
    const receiptModal = document.querySelector("#receipt-modal.visible");
    if (receiptModal) {
      receiptModal.classList.remove("visible");
      receiptModal.hidden = true;
      document.querySelector("#transfer-form [type='submit']")?.focus();
      return;
    }
  });

  function renderGraph(graph) {
    const svg = document.querySelector("#access-graph");
    if (!svg) return;
    while (svg.firstChild) svg.removeChild(svg.firstChild);
    const namespace = "http://www.w3.org/2000/svg";
    const definitions = document.createElementNS(namespace, "defs");
    const marker = document.createElementNS(namespace, "marker");
    marker.setAttribute("id", "arrow");
    marker.setAttribute("markerWidth", "10");
    marker.setAttribute("markerHeight", "10");
    marker.setAttribute("refX", "8");
    marker.setAttribute("refY", "3");
    marker.setAttribute("orient", "auto");
    const arrow = document.createElementNS(namespace, "path");
    arrow.setAttribute("d", "M0,0 L0,6 L9,3 z");
    arrow.setAttribute("fill", "#8aa2b2");
    marker.appendChild(arrow);
    definitions.appendChild(marker);
    svg.appendChild(definitions);

    const nodes = graph.nodes.length ? graph.nodes : ["No recorded access events"];
    const positions = new Map();
    const centerX = 300;
    const centerY = 110;
    const radiusX = Math.min(220, 30 + nodes.length * 28);
    const radiusY = 76;
    nodes.forEach((node, index) => {
      const angle = -Math.PI / 2 + (2 * Math.PI * index) / nodes.length;
      positions.set(node, {
        x: centerX + radiusX * Math.cos(angle),
        y: centerY + radiusY * Math.sin(angle),
      });
    });

    graph.edges.forEach(([source, destination]) => {
      const from = positions.get(source);
      const to = positions.get(destination);
      if (!from || !to) return;
      const line = document.createElementNS(namespace, "line");
      line.setAttribute("x1", String(from.x));
      line.setAttribute("y1", String(from.y));
      line.setAttribute("x2", String(to.x));
      line.setAttribute("y2", String(to.y));
      line.setAttribute("class", "edge-line");
      svg.appendChild(line);
    });

    nodes.forEach((node) => {
      const point = positions.get(node);
      const circle = document.createElementNS(namespace, "circle");
      circle.setAttribute("cx", String(point.x));
      circle.setAttribute("cy", String(point.y));
      circle.setAttribute("r", "24");
      circle.setAttribute("class", "graph-node");
      const label = document.createElementNS(namespace, "text");
      label.setAttribute("x", String(point.x));
      label.setAttribute("y", String(point.y + 4));
      label.setAttribute("class", "graph-label");
      label.textContent = node.length > 16 ? `${node.slice(0, 13)}...` : node;
      svg.append(circle, label);
    });
  }

  function renderAvl(shape) {
    const svg = document.querySelector("#avl-graph");
    if (!svg) return;
    while (svg.firstChild) svg.removeChild(svg.firstChild);
    const namespace = "http://www.w3.org/2000/svg";
    const positions = new Map();
    const width = 800;
    const top = 28;
    const verticalGap = 48;
    shape.nodes.forEach((node) => {
      const slots = 2 ** node.depth;
      positions.set(node.id, {
        x: width * (node.position + 1) / (slots + 1),
        y: top + node.depth * verticalGap,
      });
    });
    shape.edges.forEach((edge) => {
      const source = positions.get(edge.source);
      const target = positions.get(edge.target);
      if (!source || !target) return;
      const line = document.createElementNS(namespace, "line");
      line.setAttribute("x1", String(source.x));
      line.setAttribute("y1", String(source.y));
      line.setAttribute("x2", String(target.x));
      line.setAttribute("y2", String(target.y));
      line.setAttribute("class", "edge-line");
      svg.appendChild(line);
    });
    shape.nodes.forEach((node) => {
      const point = positions.get(node.id);
      const circle = document.createElementNS(namespace, "circle");
      circle.setAttribute("cx", String(point.x));
      circle.setAttribute("cy", String(point.y));
      circle.setAttribute("r", "17");
      circle.setAttribute("class", "graph-node");
      const label = document.createElementNS(namespace, "text");
      label.setAttribute("x", String(point.x));
      label.setAttribute("y", String(point.y + 4));
      label.setAttribute("class", "graph-label");
      label.textContent = "acct";
      svg.append(circle, label);
    });
  }

  const riskContainer = document.querySelector("#risk-data");
  if (riskContainer) {
    api("/api/risk-data", {}, "GET")
      .then((data) => {
        renderGraph(data.graph);
        document.querySelector("#bfs-order").textContent =
          data.graph.bfs.join(" → ") || "No events";
        document.querySelector("#dfs-order").textContent =
          data.graph.dfs.join(" → ") || "No events";
        document.querySelector("#avl-count").textContent =
          String(data.avl.account_count);
        document.querySelector("#avl-height").textContent =
          String(data.avl.height);
        renderAvl(data.avl.shape);
        const warning = document.querySelector("#graph-warning");
        if (data.graph.suspicious_paths.length) {
          showMessage(
            warning,
            `Suspicious path detected: ${data.graph.suspicious_paths[0].join(" → ")}`,
            "error",
          );
        } else {
          showMessage(warning, "No modeled privileged-access path was found.", "success");
        }
        const controls = document.querySelector("#risk-controls");
        data.risk_controls.forEach((control) => {
          const item = document.createElement("article");
          item.className = "control-item";
          const icon = document.createElement("span");
          icon.className = "control-check";
          icon.textContent = "✓";
          const text = document.createElement("p");
          text.textContent = control;
          item.append(icon, text);
          controls.appendChild(item);
        });
        const controlsOn = document.querySelector("#controls-on");
        if (controlsOn) {
          controlsOn.textContent = `${data.risk_controls.length} / ${data.risk_controls.length}`;
        }
      })
      .catch((error) => showMessage(
        document.querySelector("#risk-load-message"),
        error.message,
        "error",
      ));
  }
})();
