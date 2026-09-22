/**
 * Generator page interactions:
 * - Generate password via API with configurable options
 * - Real-time zxcvbn strength meter for generated and checked passwords
 * - Copy generated password
 * - Length slider live update
 */

const STRENGTH_COLORS = ['#dc3545', '#dc3545', '#ffc107', '#0d6efd', '#198754'];
const STRENGTH_LABELS = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong'];
const STRENGTH_WIDTHS = ['5%', '25%', '50%', '75%', '100%'];


document.addEventListener('DOMContentLoaded', () => {
    initGenerator();
    initPasswordChecker();
});


// --- Password Generator ---

function initGenerator() {
    const lengthSlider = document.getElementById('lengthSlider');
    const lengthValue = document.getElementById('lengthValue');
    const generateBtn = document.getElementById('generateBtn');
    const copyBtn = document.getElementById('copyGenerated');
    const passwordField = document.getElementById('generatedPassword');

    if (!generateBtn) return;

    // Length slider live update
    lengthSlider.addEventListener('input', () => {
        lengthValue.textContent = lengthSlider.value;
    });

    // Generate button
    generateBtn.addEventListener('click', async () => {
        generateBtn.disabled = true;
        generateBtn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Generating...';

        try {
            const resp = await fetch('/api/generate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    length: parseInt(lengthSlider.value),
                    use_upper: document.getElementById('useUpper').checked,
                    use_lower: document.getElementById('useLower').checked,
                    use_digits: document.getElementById('useDigits').checked,
                    use_symbols: document.getElementById('useSymbols').checked,
                    exclude_similar: document.getElementById('excludeSimilar').checked,
                }),
            });

            const data = await resp.json();
            if (data.error) {
                passwordField.value = '';
                alert(data.error);
            } else {
                passwordField.value = data.password;
                updateStrengthMeter(data.password, 'genStrengthBar', 'genStrengthLabel', 'genStrengthDetail');
                showStrengthBreakdown(data.password);
            }
        } catch (err) {
            console.error('Generate failed:', err);
        }

        generateBtn.disabled = false;
        generateBtn.innerHTML = '<i class="bi bi-arrow-repeat"></i> Generate Password';
    });

    // Copy generated password
    copyBtn.addEventListener('click', async () => {
        const text = passwordField.value;
        if (!text) return;

        try {
            if (navigator.clipboard && window.isSecureContext) {
                await navigator.clipboard.writeText(text);
            } else {
                const ta = document.createElement('textarea');
                ta.value = text;
                ta.style.position = 'fixed';
                ta.style.opacity = '0';
                document.body.appendChild(ta);
                ta.select();
                document.execCommand('copy');
                ta.remove();
            }
            showCopyFeedback(copyBtn);
        } catch (err) {
            console.error('Copy failed:', err);
        }
    });

    // Auto-generate on load
    generateBtn.click();
}


// --- Password Checker (bottom card) ---

function initPasswordChecker() {
    const input = document.getElementById('checkPasswordInput');
    if (!input) return;

    input.addEventListener('input', () => {
        const password = input.value;
        if (!password) {
            clearStrengthMeter('checkStrengthBar', 'checkStrengthLabel', 'checkStrengthDetail');
            document.getElementById('checkFeedback').innerHTML = '';
            return;
        }
        updateStrengthMeter(password, 'checkStrengthBar', 'checkStrengthLabel', 'checkStrengthDetail');

        // Show zxcvbn feedback
        const result = zxcvbn(password);
        const feedbackEl = document.getElementById('checkFeedback');
        let html = '';

        if (result.feedback.warning) {
            html += `<div class="alert alert-warning py-1 px-2 small mb-1"><i class="bi bi-exclamation-triangle"></i> ${result.feedback.warning}</div>`;
        }
        result.feedback.suggestions.forEach(s => {
            html += `<div class="text-secondary small"><i class="bi bi-lightbulb"></i> ${s}</div>`;
        });

        // Crack time
        const crackTime = result.crack_times_display.offline_slow_hashing_1e4_per_second;
        html += `<div class="text-secondary small mt-1"><i class="bi bi-clock"></i> Estimated crack time: <strong>${crackTime}</strong></div>`;

        feedbackEl.innerHTML = html;
    });
}


// --- Shared Strength Meter ---

function updateStrengthMeter(password, barId, labelId, detailId) {
    if (typeof zxcvbn === 'undefined') return;

    const result = zxcvbn(password);
    const score = result.score;

    const bar = document.getElementById(barId);
    const label = document.getElementById(labelId);
    const detail = document.getElementById(detailId);

    bar.style.width = STRENGTH_WIDTHS[score];
    bar.style.backgroundColor = STRENGTH_COLORS[score];
    label.textContent = STRENGTH_LABELS[score];
    label.style.color = STRENGTH_COLORS[score];

    if (detail) {
        const crackTime = result.crack_times_display.offline_slow_hashing_1e4_per_second;
        detail.textContent = `Crack time: ${crackTime}`;
    }
}

function clearStrengthMeter(barId, labelId, detailId) {
    document.getElementById(barId).style.width = '0%';
    document.getElementById(labelId).textContent = '';
    if (detailId) document.getElementById(detailId).textContent = '';
}


// --- Strength Breakdown (generator page) ---

function showStrengthBreakdown(password) {
    const container = document.getElementById('strengthBreakdown');
    const feedback = document.getElementById('strengthFeedback');
    if (!container || !feedback) return;

    const result = zxcvbn(password);
    container.classList.remove('d-none');

    let html = `<div class="small">`;
    html += `<span class="badge bg-${result.score >= 3 ? 'success' : result.score >= 2 ? 'warning' : 'danger'} mb-2">${STRENGTH_LABELS[result.score]} (${result.score}/4)</span>`;
    html += `<div class="text-secondary mb-1"><i class="bi bi-clock"></i> Crack time (offline, slow hash): <strong>${result.crack_times_display.offline_slow_hashing_1e4_per_second}</strong></div>`;
    html += `<div class="text-secondary mb-1"><i class="bi bi-speedometer2"></i> Crack time (online, throttled): <strong>${result.crack_times_display.online_throttling_100_per_hour}</strong></div>`;

    if (result.feedback.warning) {
        html += `<div class="alert alert-warning py-1 px-2 mt-2 mb-1"><i class="bi bi-exclamation-triangle"></i> ${result.feedback.warning}</div>`;
    }

    result.feedback.suggestions.forEach(s => {
        html += `<div class="text-secondary"><i class="bi bi-lightbulb"></i> ${s}</div>`;
    });

    if (!result.feedback.warning && result.feedback.suggestions.length === 0) {
        html += `<div class="text-success"><i class="bi bi-check-circle"></i> No weaknesses detected.</div>`;
    }

    html += `</div>`;
    feedback.innerHTML = html;
}
