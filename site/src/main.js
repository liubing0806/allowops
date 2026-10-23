// Tab panels and the copy button. The page works without this script; only the first tab is shown.
for (const box of document.querySelectorAll('[data-tabs]')) {
  const buttons = box.querySelectorAll('[data-tab]');
  const panes = box.querySelectorAll('[data-pane]');
  for (const btn of buttons) {
    btn.addEventListener('click', () => {
      for (const b of buttons) b.setAttribute('aria-selected', String(b === btn));
      for (const p of panes) {
        const on = p.dataset.pane === btn.dataset.tab;
        p.classList.toggle('on', on);
        p.hidden = !on;
      }
    });
  }
}
for (const btn of document.querySelectorAll('[data-copy]')) {
  btn.addEventListener('click', async () => {
    const text = document.querySelector(btn.dataset.copy).textContent;
    await navigator.clipboard.writeText(text);
    const label = btn.textContent;
    btn.textContent = btn.dataset.done;
    setTimeout(() => { btn.textContent = label; }, 1500);
  });
}
