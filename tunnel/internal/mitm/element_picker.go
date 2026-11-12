package mitm

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ElementRuleListener is notified whenever the user blocks an element via the picker.
type ElementRuleListener interface {
	OnElementRuleAdded(domain string, selector string)
}

var (
	elementRuleListener   ElementRuleListener
	elementRuleListenerMu sync.RWMutex
	pickerActiveUntil     atomic.Int64
)

// SetElementRuleListener registers the callback for newly created cosmetic element rules.
func SetElementRuleListener(l ElementRuleListener) {
	elementRuleListenerMu.Lock()
	elementRuleListener = l
	elementRuleListenerMu.Unlock()
}

// SetElementPickerActive activates the element picker for the specified duration (in seconds).
// If seconds <= 0, the picker is deactivated.
func SetElementPickerActive(seconds int) {
	if seconds <= 0 {
		pickerActiveUntil.Store(0)
		logf("[Picker] Deactivated")
	} else {
		until := time.Now().Add(time.Duration(seconds) * time.Second).Unix()
		pickerActiveUntil.Store(until)
		logf("[Picker] Activated for %d seconds (until %d)", seconds, until)
	}
}

// IsElementPickerActive reports whether the element picker is currently active.
func IsElementPickerActive() bool {
	until := pickerActiveUntil.Load()
	return until > 0 && time.Now().Unix() < until
}

func serveElementPicker(req *http.Request) *http.Response {
	return buildTextResponse(req, 200, "application/javascript; charset=utf-8", ElementPickerJS)
}

type elementRulePayload struct {
	Domain   string `json:"domain"`
	Selector string `json:"selector"`
}

func handleAddElementRule(req *http.Request) *http.Response {
	if req.Method != http.MethodPost {
		return buildTextResponse(req, 405, "text/plain", "Method Not Allowed")
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return buildTextResponse(req, 400, "application/json", `{"error":"read_failed"}`)
	}

	var p elementRulePayload
	if err := json.Unmarshal(body, &p); err != nil {
		return buildTextResponse(req, 400, "application/json", `{"error":"invalid_json"}`)
	}

	domain := strings.ToLower(strings.TrimSpace(p.Domain))
	selector := strings.TrimSpace(p.Selector)
	if selector == "" {
		return buildTextResponse(req, 400, "application/json", `{"error":"empty_selector"}`)
	}

	// 1. Add rule to in-memory cosmetic store immediately
	cssRule := selector + " { display: none !important; }"
	defaultCosmeticStore.AddHostCSS(domain, cssRule)
	logf("[Picker] New cosmetic rule added for '%s': %s", domain, selector)

	// 2. Deactivate the picker mode
	SetElementPickerActive(0)

	// 3. Notify Kotlin callback
	elementRuleListenerMu.RLock()
	listener := elementRuleListener
	elementRuleListenerMu.RUnlock()
	if listener != nil {
		go listener.OnElementRuleAdded(domain, selector)
	}

	return buildTextResponse(req, 200, "application/json; charset=utf-8", `{"status":"ok","domain":"`+domain+`"}`)
}

func handlePickerStatus(req *http.Request) *http.Response {
	active := IsElementPickerActive()
	if active {
		return buildTextResponse(req, 200, "application/json", `{"active":true}`)
	}
	return buildTextResponse(req, 200, "application/json", `{"active":false}`)
}

// ElementPickerJS is the embedded, sleek modern element picker script.
const ElementPickerJS = `/**
 * BlockAds Modern Element Picker
 * Sleek glassmorphism toolbar, capture-phase touch interception, and instant rule saving.
 */
(function () {
  'use strict';

  if (window.__blockadsPickerActive__) return;
  window.__blockadsPickerActive__ = true;

  var state = {
    selected: null,
    history: []
  };

  var highlight = null;
  var toolbar = null;
  var selectorLabel = null;
  var hintText = null;

  function isPickerOwned(el) {
    if (!el) return false;
    if (highlight && highlight.contains(el)) return true;
    if (toolbar && toolbar.contains(el)) return true;
    if (typeof el.closest === 'function') {
      return !!(el.closest('#__blockads_toolbar__') || el.closest('#__blockads_highlight__') || el.closest('#__blockads_toast__'));
    }
    return false;
  }

  function getRoot() {
    return document.body || document.documentElement;
  }

  function generateSelector(el) {
    if (!el || el === document.body || el === document.documentElement) return '';
    if (el.id && /^[a-zA-Z][\w\-]*$/.test(el.id)) {
      return '#' + el.id;
    }

    var tag = el.tagName.toLowerCase();
    var validClasses = [];
    for (var i = 0; i < el.classList.length; i++) {
      var c = el.classList[i];
      if (c && /^[a-zA-Z][\w\-]*$/.test(c) && !c.startsWith('__blockads')) {
        validClasses.push('.' + c);
      }
    }

    if (validClasses.length > 0 && validClasses.length <= 3) {
      var classSel = tag + validClasses.join('');
      try {
        if (document.querySelectorAll(classSel).length <= 6) return classSel;
      } catch (e) {}
    }

    var parent = el.parentElement;
    if (parent && parent !== document.body && parent !== document.documentElement) {
      if (parent.id && /^[a-zA-Z][\w\-]*$/.test(parent.id)) {
        return '#' + parent.id + ' > ' + tag;
      }
      var idx = Array.prototype.indexOf.call(parent.children, el) + 1;
      return tag + ':nth-child(' + idx + ')';
    }

    return tag;
  }

  function ensureHighlight() {
    if (highlight) return;
    highlight = document.createElement('div');
    highlight.id = '__blockads_highlight__';
    Object.assign(highlight.style, {
      position: 'fixed',
      zIndex: '2147483646',
      pointerEvents: 'none',
      border: '2px solid #10B981',
      background: 'rgba(16, 185, 129, 0.22)',
      borderRadius: '6px',
      boxSizing: 'border-box',
      display: 'none',
      boxShadow: '0 0 0 1px rgba(255,255,255,0.4), inset 0 0 14px rgba(16,185,129,0.35)',
      transition: 'top 0.12s ease, left 0.12s ease, width 0.12s ease, height 0.12s ease'
    });
    getRoot().appendChild(highlight);
  }

  function updateHighlight(el) {
    if (!el) {
      if (highlight) highlight.style.display = 'none';
      return;
    }
    ensureHighlight();
    var r = el.getBoundingClientRect();
    Object.assign(highlight.style, {
      display: 'block',
      top: r.top + 'px',
      left: r.left + 'px',
      width: r.width + 'px',
      height: r.height + 'px'
    });
  }

  function showToast(msg) {
    var toast = document.createElement('div');
    toast.id = '__blockads_toast__';
    toast.textContent = msg;
    Object.assign(toast.style, {
      position: 'fixed',
      top: '24px',
      left: '50%',
      transform: 'translateX(-50%)',
      zIndex: '2147483647',
      background: 'rgba(16, 185, 129, 0.95)',
      color: '#FFFFFF',
      padding: '10px 22px',
      borderRadius: '24px',
      fontWeight: '600',
      fontSize: '13px',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
      boxShadow: '0 10px 28px rgba(0,0,0,0.45)',
      pointerEvents: 'none',
      opacity: '1',
      transition: 'opacity 0.35s ease, transform 0.35s ease'
    });
    getRoot().appendChild(toast);
    setTimeout(function () {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(-50%) translateY(-10px)';
      setTimeout(function () {
        if (toast.parentNode) toast.parentNode.removeChild(toast);
      }, 350);
    }, 2200);
  }

  function ensureToolbar() {
    if (toolbar) return;
    toolbar = document.createElement('div');
    toolbar.id = '__blockads_toolbar__';
    Object.assign(toolbar.style, {
      position: 'fixed',
      zIndex: '2147483647',
      bottom: '68px',
      left: '50%',
      transform: 'translateX(-50%)',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      gap: '8px',
      background: 'rgba(15, 23, 42, 0.94)',
      backdropFilter: 'blur(20px)',
      webkitBackdropFilter: 'blur(20px)',
      border: '1px solid rgba(255, 255, 255, 0.18)',
      borderRadius: '26px',
      padding: '10px 16px',
      boxShadow: '0 16px 48px rgba(0, 0, 0, 0.8), 0 0 0 1px rgba(255, 255, 255, 0.08)',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
      boxSizing: 'border-box',
      maxWidth: '94vw',
      transition: 'bottom 0.15s ease, top 0.15s ease'
    });

    selectorLabel = document.createElement('div');
    Object.assign(selectorLabel.style, {
      color: '#6EE7B7',
      fontFamily: 'monospace',
      fontSize: '11px',
      fontWeight: '600',
      maxWidth: '280px',
      overflow: 'hidden',
      textOverflow: 'ellipsis',
      whiteSpace: 'nowrap',
      padding: '3px 10px',
      background: 'rgba(16, 185, 129, 0.16)',
      border: '1px solid rgba(16, 185, 129, 0.3)',
      borderRadius: '10px',
      display: 'none'
    });
    toolbar.appendChild(selectorLabel);

    var btnContainer = document.createElement('div');
    Object.assign(btnContainer.style, {
      display: 'flex',
      gap: '8px',
      alignItems: 'center'
    });

    hintText = document.createElement('div');
    hintText.textContent = '🎯 Tap an ad to block it';
    Object.assign(hintText.style, {
      color: '#E2E8F0',
      fontSize: '13px',
      fontWeight: '600',
      padding: '4px 8px',
      whiteSpace: 'nowrap'
    });
    btnContainer.appendChild(hintText);

    function makeBtn(id, text, bg, textColor, onClick) {
      var b = document.createElement('button');
      b.id = id;
      b.textContent = text;
      Object.assign(b.style, {
        padding: '8px 14px',
        borderRadius: '18px',
        border: 'none',
        cursor: 'pointer',
        fontWeight: '600',
        fontSize: '12px',
        background: bg,
        color: textColor,
        whiteSpace: 'nowrap',
        boxShadow: '0 2px 10px rgba(0,0,0,0.25)',
        outline: 'none',
        webkitTapHighlightColor: 'transparent',
        touchAction: 'manipulation'
      });
      function trigger(e) {
        e.preventDefault();
        e.stopPropagation();
        e.stopImmediatePropagation();
        onClick();
      }
      b.addEventListener('click', trigger);
      b.addEventListener('touchend', trigger);
      return b;
    }

    var btnCancel = makeBtn('__btn_cancel__', '✕ Cancel', '#334155', '#F8FAFC', cancel);
    var btnParent = makeBtn('__btn_parent__', '↑ Wider', '#1E293B', '#E2E8F0', goParent);
    var btnChild  = makeBtn('__btn_child__',  '↓ Narrower', '#1E293B', '#E2E8F0', goChild);
    var btnBlock  = makeBtn('__btn_block__',  '🚫 Block Ad', 'linear-gradient(135deg, #10B981 0%, #059669 100%)', '#FFFFFF', confirmBlock);

    btnParent.style.display = 'none';
    btnChild.style.display  = 'none';
    btnBlock.style.display  = 'none';

    btnContainer.appendChild(btnCancel);
    btnContainer.appendChild(btnParent);
    btnContainer.appendChild(btnChild);
    btnContainer.appendChild(btnBlock);
    toolbar.appendChild(btnContainer);

    getRoot().appendChild(toolbar);
  }

  function updateToolbarState() {
    ensureToolbar();
    var p = document.getElementById('__btn_parent__');
    var c = document.getElementById('__btn_child__');
    var b = document.getElementById('__btn_block__');

    if (state.selected) {
      if (hintText) hintText.style.display = 'none';
      if (p) p.style.display = 'inline-block';
      if (c) c.style.display = 'inline-block';
      if (b) b.style.display = 'inline-block';
      if (selectorLabel) {
        selectorLabel.style.display = 'block';
        selectorLabel.textContent = generateSelector(state.selected) || state.selected.tagName.toLowerCase();
      }

      var r = state.selected.getBoundingClientRect();
      if (r.bottom > window.innerHeight - 150) {
        toolbar.style.top = '24px';
        toolbar.style.bottom = 'auto';
      } else {
        toolbar.style.bottom = '68px';
        toolbar.style.top = 'auto';
      }
    } else {
      if (hintText) hintText.style.display = 'block';
      if (p) p.style.display = 'none';
      if (c) c.style.display = 'none';
      if (b) b.style.display = 'none';
      if (selectorLabel) selectorLabel.style.display = 'none';
      toolbar.style.bottom = '68px';
      toolbar.style.top = 'auto';
    }
  }

  function selectElement(el) {
    if (!el || el === document.body || el === document.documentElement) return;
    state.history = [];
    state.selected = el;
    updateHighlight(el);
    updateToolbarState();
  }

  function goParent() {
    if (!state.selected) return;
    var parent = state.selected.parentElement;
    if (!parent || parent === document.body || parent === document.documentElement) return;
    state.history.push(state.selected);
    state.selected = parent;
    updateHighlight(parent);
    updateToolbarState();
  }

  function goChild() {
    if (!state.selected) return;
    var prev = state.history.pop();
    if (prev) {
      state.selected = prev;
      updateHighlight(prev);
      updateToolbarState();
    }
  }

  function trapAndSelect(e) {
    if (isPickerOwned(e.target)) return;
    e.preventDefault();
    e.stopPropagation();
    e.stopImmediatePropagation();
    var target = e.target;
    if (target && target !== document.body && target !== document.documentElement) {
      selectElement(target);
    }
  }

  function suppressEvent(e) {
    if (isPickerOwned(e.target)) return;
    e.preventDefault();
    e.stopPropagation();
    e.stopImmediatePropagation();
  }

  var eventOptions = { capture: true, passive: false };
  window.addEventListener('click', trapAndSelect, eventOptions);
  window.addEventListener('mousedown', suppressEvent, eventOptions);
  window.addEventListener('mouseup', suppressEvent, eventOptions);
  window.addEventListener('touchstart', suppressEvent, eventOptions);
  window.addEventListener('touchend', trapAndSelect, eventOptions);
  window.addEventListener('pointerdown', suppressEvent, eventOptions);
  window.addEventListener('pointerup', trapAndSelect, eventOptions);

  function confirmBlock() {
    if (!state.selected) return;
    var selector = generateSelector(state.selected);
    var target = state.selected;
    var domain = window.location.hostname || '';

    try {
      target.style.transition = 'opacity 0.25s ease, transform 0.25s ease';
      target.style.opacity = '0';
      target.style.transform = 'scale(0.95)';
      setTimeout(function () {
        try { target.style.setProperty('display', 'none', 'important'); } catch (e) {}
      }, 260);
    } catch (e) {}

    cleanup();
    showToast('✨ Ad blocked & rule saved!');

    if (window.blockadsPickerProxy && window.blockadsPickerProxy.onPickerCompleted) {
      try {
        window.blockadsPickerProxy.onPickerCompleted(selector, domain);
      } catch (e) {}
    }

    try {
      fetch('https://local.pwhs.app/api/add-element-rule', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: domain, selector: selector })
      }).catch(function (err) {
        console.error('[BlockAds] add-element-rule error:', err);
      });
    } catch (e) {}
  }

  function cancel() {
    cleanup();
    if (window.blockadsPickerProxy && window.blockadsPickerProxy.onPickerDismissed) {
      try {
        window.blockadsPickerProxy.onPickerDismissed();
      } catch (e) {}
    }
  }

  function cleanup() {
    window.__blockadsPickerActive__ = false;
    window.removeEventListener('click', trapAndSelect, eventOptions);
    window.removeEventListener('mousedown', suppressEvent, eventOptions);
    window.removeEventListener('mouseup', suppressEvent, eventOptions);
    window.removeEventListener('touchstart', suppressEvent, eventOptions);
    window.removeEventListener('touchend', trapAndSelect, eventOptions);
    window.removeEventListener('pointerdown', suppressEvent, eventOptions);
    window.removeEventListener('pointerup', trapAndSelect, eventOptions);

    if (highlight && highlight.parentNode) highlight.parentNode.removeChild(highlight);
    if (toolbar && toolbar.parentNode) toolbar.parentNode.removeChild(toolbar);
    highlight = null;
    toolbar = null;
    selectorLabel = null;
    hintText = null;
    state.selected = null;
    state.history = [];
  }

  window.addEventListener('scroll', function () {
    if (state.selected) updateHighlight(state.selected);
  }, { passive: true });
  window.addEventListener('resize', function () {
    if (state.selected) updateHighlight(state.selected);
  });

  ensureToolbar();
  updateToolbarState();
  window.__blockadsPickerCancel__ = cancel;
})();
`
