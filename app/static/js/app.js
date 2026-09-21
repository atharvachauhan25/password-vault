/**
 * Vault dashboard UI interactions:
 * - Password visibility toggle
 * - Copy to clipboard (basic — enhanced in Milestone 10)
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

document.addEventListener('DOMContentLoaded', () => {
    initPasswordToggles();
    initCopyButtons();
    initQuickGenerate();
});


// --- Password Visibility Toggle ---

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


// --- Copy to Clipboard (basic version) ---

function initCopyButtons() {
    document.querySelectorAll('.copy-btn').forEach(btn => {
        btn.addEventListener('click', async () => {
            const text = btn.dataset.copy;
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
                showCopyFeedback(btn);
            } catch (err) {
                console.error('Copy failed:', err);
            }
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
