(function () {
  const sidebar = document.querySelector('#sidebar');
  const toggle = document.querySelector('.nav-toggle');
  const search = document.querySelector('#doc-search');
  const sections = Array.from(document.querySelectorAll('main section'));
  const tocLinks = Array.from(document.querySelectorAll('.toc a'));
  const toTop = document.querySelector('.to-top');

  document.querySelectorAll('pre').forEach((block) => {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'copy-button';
    button.textContent = 'Copy';
    button.addEventListener('click', async () => {
      const code = block.querySelector('code');
      const text = code ? code.innerText : block.innerText;
      try {
        await navigator.clipboard.writeText(text.trimEnd());
        button.textContent = 'Copied';
      } catch (error) {
        const range = document.createRange();
        range.selectNodeContents(code || block);
        const selection = window.getSelection();
        selection.removeAllRanges();
        selection.addRange(range);
        button.textContent = 'Select';
      }
      window.setTimeout(() => { button.textContent = 'Copy'; }, 1600);
    });
    block.appendChild(button);
  });

  if (toggle && sidebar) {
    toggle.addEventListener('click', () => {
      const expanded = toggle.getAttribute('aria-expanded') === 'true';
      toggle.setAttribute('aria-expanded', String(!expanded));
      sidebar.classList.toggle('open', !expanded);
    });
  }

  if (search) {
    search.addEventListener('input', () => {
      const query = search.value.trim().toLowerCase();
      sections.forEach((section) => {
        const haystack = `${section.dataset.title || ''} ${section.innerText}`.toLowerCase();
        section.classList.toggle('is-hidden', query.length > 0 && !haystack.includes(query));
      });
    });
  }

  const sectionById = new Map(sections.map((section) => [section.id, section]));
  const observer = new IntersectionObserver((entries) => {
    const visible = entries
      .filter((entry) => entry.isIntersecting)
      .sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
    if (!visible) return;
    tocLinks.forEach((link) => {
      link.classList.toggle('active', link.getAttribute('href') === `#${visible.target.id}`);
    });
  }, { rootMargin: '-20% 0px -65% 0px', threshold: [0.1, 0.25, 0.5] });
  sections.forEach((section) => observer.observe(section));

  tocLinks.forEach((link) => {
    link.addEventListener('click', () => {
      if (sidebar && toggle && window.matchMedia('(max-width: 980px)').matches) {
        sidebar.classList.remove('open');
        toggle.setAttribute('aria-expanded', 'false');
      }
      const id = link.getAttribute('href').slice(1);
      if (!sectionById.has(id)) return;
      sectionById.get(id).classList.remove('is-hidden');
    });
  });

  window.addEventListener('scroll', () => {
    if (!toTop) return;
    toTop.classList.toggle('visible', window.scrollY > 700);
  }, { passive: true });

  if (toTop) {
    toTop.addEventListener('click', () => window.scrollTo({ top: 0, behavior: 'smooth' }));
  }
})();
