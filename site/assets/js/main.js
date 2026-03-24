/**
 * Straylight-AI — main.js
 * No frameworks. No jQuery. Pure vanilla JS.
 *
 * Modules:
 *   1. Mobile nav toggle
 *   2. Scroll-triggered animations (IntersectionObserver)
 *   3. Smooth scroll for anchor links
 *   4. Copy-to-clipboard for code blocks and inline commands
 *   5. Auto-generate table of contents (doc pages)
 */

(function () {
  'use strict';

  /* --------------------------------------------------------------------------
     1. Mobile Navigation Toggle
     -------------------------------------------------------------------------- */
  function initNavToggle() {
    var toggleBtn = document.querySelector('.nav-toggle');
    var navMenu = document.getElementById('nav-menu');

    if (!toggleBtn || !navMenu) return;

    toggleBtn.addEventListener('click', function () {
      var isExpanded = toggleBtn.getAttribute('aria-expanded') === 'true';
      toggleBtn.setAttribute('aria-expanded', String(!isExpanded));
      navMenu.classList.toggle('is-open', !isExpanded);

      // Prevent body scroll when menu is open
      document.body.style.overflow = !isExpanded ? 'hidden' : '';
    });

    // Close menu when a link is clicked
    navMenu.querySelectorAll('a').forEach(function (link) {
      link.addEventListener('click', function () {
        toggleBtn.setAttribute('aria-expanded', 'false');
        navMenu.classList.remove('is-open');
        document.body.style.overflow = '';
      });
    });

    // Close menu on escape key
    document.addEventListener('keydown', function (event) {
      if (event.key === 'Escape' && navMenu.classList.contains('is-open')) {
        toggleBtn.setAttribute('aria-expanded', 'false');
        navMenu.classList.remove('is-open');
        document.body.style.overflow = '';
        toggleBtn.focus();
      }
    });
  }

  /* --------------------------------------------------------------------------
     2. Scroll-Triggered Animations (IntersectionObserver)
     -------------------------------------------------------------------------- */
  function initScrollAnimations() {
    var elements = document.querySelectorAll(
      '.feature-card, .problem-card, .flow-step, .security-layer, ' +
      '.service-chip, .install-step, .arch-component, .animate-on-scroll'
    );

    if (!elements.length || !window.IntersectionObserver) {
      // Fallback: make everything visible if IntersectionObserver is unsupported
      elements.forEach(function (el) {
        el.classList.add('is-visible');
      });
      return;
    }

    // Add animation class
    elements.forEach(function (el) {
      el.classList.add('animate-on-scroll');
    });

    var observer = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) {
            entry.target.classList.add('is-visible');
            observer.unobserve(entry.target);
          }
        });
      },
      {
        threshold: 0.12,
        rootMargin: '0px 0px -40px 0px'
      }
    );

    elements.forEach(function (el) {
      observer.observe(el);
    });
  }

  /* --------------------------------------------------------------------------
     3. Smooth Scroll for Anchor Links
     -------------------------------------------------------------------------- */
  function initSmoothScroll() {
    var NAV_OFFSET = 80; // nav height + breathing room

    document.querySelectorAll('a[href^="#"]').forEach(function (anchor) {
      anchor.addEventListener('click', function (event) {
        var hash = anchor.getAttribute('href');
        if (!hash || hash === '#') return;

        var target = document.querySelector(hash);
        if (!target) return;

        event.preventDefault();

        var targetTop = target.getBoundingClientRect().top + window.pageYOffset - NAV_OFFSET;

        window.scrollTo({
          top: targetTop,
          behavior: 'smooth'
        });

        // Update URL hash without jumping
        history.pushState(null, '', hash);

        // Move focus to target for accessibility
        if (!target.getAttribute('tabindex')) {
          target.setAttribute('tabindex', '-1');
        }
        target.focus({ preventScroll: true });
      });
    });
  }

  /* --------------------------------------------------------------------------
     4. Copy-to-Clipboard
     -------------------------------------------------------------------------- */
  function initCopyButtons() {
    // Handle inline copy buttons (hero install, terminal lines)
    document.querySelectorAll('.copy-btn').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var text = btn.getAttribute('data-copy');
        if (!text) {
          // Try to read sibling code element
          var codeEl = btn.parentElement.querySelector('code');
          if (codeEl) text = codeEl.textContent;
        }
        if (!text) return;

        copyToClipboard(text, btn);
      });
    });

    // Auto-add copy buttons to pre > code blocks in doc pages
    document.querySelectorAll('.doc-body pre').forEach(function (pre) {
      if (pre.querySelector('.copy-btn')) return; // already has one

      var btn = document.createElement('button');
      btn.className = 'copy-btn doc-copy-btn';
      btn.setAttribute('aria-label', 'Copy code');
      btn.setAttribute('title', 'Copy to clipboard');
      btn.innerHTML =
        '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
        '<rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>' +
        '<path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>' +
        '</svg>';

      pre.style.position = 'relative';
      Object.assign(btn.style, {
        position: 'absolute',
        top: '10px',
        right: '10px',
        color: 'rgba(255,255,255,0.4)',
        padding: '4px',
        borderRadius: '4px',
        transition: 'color 150ms, background 150ms'
      });

      btn.addEventListener('mouseenter', function () {
        btn.style.color = 'rgba(255,255,255,0.8)';
        btn.style.background = 'rgba(255,255,255,0.08)';
      });
      btn.addEventListener('mouseleave', function () {
        btn.style.color = 'rgba(255,255,255,0.4)';
        btn.style.background = '';
      });

      btn.addEventListener('click', function () {
        var codeEl = pre.querySelector('code');
        var text = codeEl ? codeEl.textContent : pre.textContent;
        copyToClipboard(text.trim(), btn);
      });

      pre.appendChild(btn);
    });
  }

  function copyToClipboard(text, triggerElement) {
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(function () {
        showCopied(triggerElement);
      }).catch(function () {
        fallbackCopy(text, triggerElement);
      });
    } else {
      fallbackCopy(text, triggerElement);
    }
  }

  function fallbackCopy(text, triggerElement) {
    var textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.cssText = 'position:fixed;top:-9999px;left:-9999px;opacity:0';
    document.body.appendChild(textarea);
    textarea.select();
    try {
      document.execCommand('copy');
      showCopied(triggerElement);
    } catch (_) {
      // Silent fail — clipboard not available
    }
    document.body.removeChild(textarea);
  }

  function showCopied(btn) {
    if (!btn) return;
    btn.classList.add('copied');
    var originalHTML = btn.innerHTML;
    btn.innerHTML =
      '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
      '<polyline points="20 6 9 17 4 12"></polyline>' +
      '</svg>';

    setTimeout(function () {
      btn.classList.remove('copied');
      btn.innerHTML = originalHTML;
    }, 2000);
  }

  /* --------------------------------------------------------------------------
     5. Table of Contents Generator (doc pages)
     -------------------------------------------------------------------------- */
  function initToc() {
    var tocContainer = document.getElementById('toc-nav');
    if (!tocContainer) return;

    var docBody = document.querySelector('.doc-body');
    if (!docBody) return;

    var headings = docBody.querySelectorAll('h2, h3');
    if (headings.length < 2) {
      var tocWrapper = document.querySelector('.toc');
      if (tocWrapper) tocWrapper.style.display = 'none';
      return;
    }

    var nav = document.createElement('ol');
    nav.style.cssText = 'list-style:none;margin:0;padding:0;';

    headings.forEach(function (heading) {
      // Auto-generate IDs for headings that lack them
      if (!heading.id) {
        heading.id = heading.textContent
          .toLowerCase()
          .replace(/[^a-z0-9]+/g, '-')
          .replace(/^-|-$/g, '');
      }

      var li = document.createElement('li');
      li.style.marginBottom = heading.tagName === 'H2' ? '4px' : '2px';

      var a = document.createElement('a');
      a.href = '#' + heading.id;
      a.textContent = heading.textContent;
      a.style.cssText =
        'display:block;font-size:0.8125rem;color:var(--color-text-secondary);' +
        'text-decoration:none;padding:2px 0;' +
        'padding-left:' + (heading.tagName === 'H3' ? '12px' : '0') + ';' +
        'transition:color 150ms;';

      a.addEventListener('mouseenter', function () {
        a.style.color = 'var(--color-primary)';
      });
      a.addEventListener('mouseleave', function () {
        a.style.color = 'var(--color-text-secondary)';
      });

      li.appendChild(a);
      nav.appendChild(li);
    });

    tocContainer.appendChild(nav);

    // Highlight active section on scroll
    var observer = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) {
            tocContainer.querySelectorAll('a').forEach(function (a) {
              a.style.color = 'var(--color-text-secondary)';
              a.style.fontWeight = 'normal';
            });
            var activeLink = tocContainer.querySelector('a[href="#' + entry.target.id + '"]');
            if (activeLink) {
              activeLink.style.color = 'var(--color-primary)';
              activeLink.style.fontWeight = '600';
            }
          }
        });
      },
      {
        rootMargin: '-80px 0px -70% 0px',
        threshold: 0
      }
    );

    headings.forEach(function (h) { observer.observe(h); });
  }

  /* --------------------------------------------------------------------------
     Init on DOMContentLoaded
     -------------------------------------------------------------------------- */
  function init() {
    initNavToggle();
    initScrollAnimations();
    initSmoothScroll();
    initCopyButtons();
    initToc();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
