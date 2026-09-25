/**
 * Vault dashboard UI interactions:
 * - Password visibility toggle (cards + modals)
 * - Copy to clipboard with auto-clear + toast notifications
 * - Edit modal population
 * - Quick generate button in add modal
 */


// --- Modal Password Visibility Toggle ---

function togglePasswordVisibility(inputId, btn) {
    const input = document.getElementById(inputId);
    const icon = btn.querySelector('i');
    if (input.type === 'password') {
        input.type = 'text';
        icon.className = 'bi bi-eye-slash';
    } else {
        input.type = 'password';
        icon.className = 'bi bi-eye';
    }
}


// --- Toast Helper ---

let clipboardClearTimer = null;
let clipboardCountdownInterval = null;

function showToast(message, type = 'info', duration = 3000) {
    const container = document.getElementById('toastContainer');
    if (!container) return;

    const icons = {
        success: 'bi-check-circle-fill',
        info: 'bi-info-circle-fill',
        warning: 'bi-exclamation-triangle-fill',
        danger: 'bi-x-circle-fill',
    };

    const html = `
        <div class="toast show border-${type}" role="alert">
            <div class="toast-header">
                <i class="bi ${icons[type] || icons.info} text-${type} me-2"></i>
                <strong class="me-auto">${type === 'success' ? 'Success' : 'Notice'}</strong>
                <button type="button" class="btn-close" data-bs-dismiss="toast"></button>
            </div>
            <div class="toast-body">${message}</div>
        </div>`;
    const wrapper = document.createElement('div');
    wrapper.innerHTML = html;
    const toastNode = wrapper.firstElementChild;
    container.appendChild(toastNode);

    const toast = new bootstrap.Toast(toastNode, { delay: duration });
    toast.show();
    toastNode.addEventListener('hidden.bs.toast', () => toastNode.remove());
}

function showClipboardToast(clearSeconds) {
    const container = document.getElementById('toastContainer');
    if (!container) return;

    // Remove any existing clipboard toast
    const existing = document.getElementById('clipboardToast');
    if (existing) existing.remove();

    const html = `
        <div class="toast show border-success" role="alert" id="clipboardToast">
            <div class="toast-header">
                <i class="bi bi-clipboard-check text-success me-2"></i>
                <strong class="me-auto">Copied!</strong>
                <button type="button" class="btn-close" data-bs-dismiss="toast"></button>
            </div>
            <div class="toast-body">
                Copied to clipboard. Auto-clearing in <strong id="clipClearCountdown">${clearSeconds}</strong>s.
            </div>
        </div>`;
    const wrapper = document.createElement('div');
    wrapper.innerHTML = html;
    const toastNode = wrapper.firstElementChild;
    container.appendChild(toastNode);

    const toast = new bootstrap.Toast(toastNode, { autohide: false });
    toast.show();

    // Countdown
    let remaining = clearSeconds;
    const countdownEl = toastNode.querySelector('#clipClearCountdown');

    if (clipboardCountdownInterval) clearInterval(clipboardCountdownInterval);
    clipboardCountdownInterval = setInterval(() => {
        remaining--;
        if (countdownEl) countdownEl.textContent = Math.max(0, remaining);
        if (remaining <= 0) {
            clearInterval(clipboardCountdownInterval);
            clipboardCountdownInterval = null;
            toast.hide();
        }
    }, 1000);

    toastNode.addEventListener('hidden.bs.toast', () => toastNode.remove());
}


document.addEventListener('DOMContentLoaded', () => {
    initPasswordToggles();
    initCopyButtons();
    initQuickGenerate();
});


// --- Password Visibility Toggle (cards) ---

function initPasswordToggles() {
    document.querySelectorAll('.toggle-password-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const codeEl = btn.closest('.d-flex').querySelector('.password-masked');
            const icon = btn.querySelector('i');
            const realPassword = codeEl.dataset.password;

            if (codeEl.textContent === '••••••••') {
                codeEl.textContent = realPassword;
                icon.className = 'bi bi-eye-slash';
            } else {
                codeEl.textContent = '••••••••';
                icon.className = 'bi bi-eye';
            }
        });
    });
}


// --- Copy to Clipboard with auto-clear ---

// Read the clear timeout from the page (injected via context processor)
const CLIPBOARD_CLEAR_SECONDS = parseInt(
    document.body.dataset.clipboardClear || '30', 10
);

async function copyToClipboard(text) {
    try {
        if (navigator.clipboard && window.isSecureContext) {
            await navigator.clipboard.writeText(text);
        } else {
            // Fallback for non-HTTPS localhost
            const ta = document.createElement('textarea');
            ta.value = text;
            ta.style.position = 'fixed';
            ta.style.opacity = '0';
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            ta.remove();
        }

        // Show toast with countdown
        showClipboardToast(CLIPBOARD_CLEAR_SECONDS);

        // Schedule auto-clear
        if (clipboardClearTimer) clearTimeout(clipboardClearTimer);
        clipboardClearTimer = setTimeout(async () => {
            try {
                if (navigator.clipboard && window.isSecureContext) {
                    await navigator.clipboard.writeText('');
                }
            } catch (e) {
                // Clipboard clear failed - browser may not allow writing without user gesture
            }
            clipboardClearTimer = null;
        }, CLIPBOARD_CLEAR_SECONDS * 1000);

        return true;
    } catch (err) {
        console.error('Copy failed:', err);
        showToast('Failed to copy to clipboard.', 'danger');
        return false;
    }
}

function initCopyButtons() {
    document.querySelectorAll('.copy-btn').forEach(btn => {
        btn.addEventListener('click', async () => {
            const text = btn.dataset.copy;
            const success = await copyToClipboard(text);
            if (success) showCopyFeedback(btn);
        });
    });
}

function showCopyFeedback(btn) {
    const original = btn.innerHTML;
    btn.innerHTML = '<i class="bi bi-check-lg"></i>';
    btn.classList.remove('btn-outline-secondary');
    btn.classList.add('btn-success');

    setTimeout(() => {
        btn.innerHTML = original;
        btn.classList.remove('btn-success');
        btn.classList.add('btn-outline-secondary');
    }, 1500);
}


// --- Edit Modal ---

function openEditModal(id, title, username, password, url, notes, categoryId) {
    document.getElementById('editForm').action = `/vault/edit/${id}`;
    document.getElementById('edit-title').value = title;
    document.getElementById('edit-username').value = username;
    document.getElementById('edit-password').value = password;
    document.getElementById('edit-url').value = url;
    document.getElementById('edit-notes').value = notes;

    const catSelect = document.getElementById('edit-category');
    catSelect.value = categoryId || '';

    const modal = new bootstrap.Modal(document.getElementById('editModal'));
    modal.show();
}


// --- Quick Generate in Add Modal ---

function initQuickGenerate() {
    const genBtn = document.getElementById('addGenBtn');
    if (!genBtn) return;

    genBtn.addEventListener('click', async () => {
        try {
            const resp = await fetch('/api/generate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ length: 16 }),
            });
            const data = await resp.json();
            if (data.password) {
                document.getElementById('add-password').value = data.password;
            }
        } catch (err) {
            console.error('Generate failed:', err);
        }
    });
}
