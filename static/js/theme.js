const applyTheme = (theme) => {
    document.body.classList.remove('light', 'dark');
    document.body.classList.add(theme === 'light' ? 'light' : 'dark');
};

applyTheme(localStorage.getItem('user-theme') || 'dark');

document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('formThemes');
    const savedTheme = localStorage.getItem('user-theme') || 'dark';
    const radioToCheck = document.querySelector(`input[value="${savedTheme}"]`);

    if (radioToCheck) radioToCheck.checked = true;

    if (!form) return;

    form.addEventListener('change', () => {
        const selectedTheme = document.querySelector('input[name="theme"]:checked').value;

        applyTheme(selectedTheme);
        localStorage.setItem('user-theme', selectedTheme);
    });
});