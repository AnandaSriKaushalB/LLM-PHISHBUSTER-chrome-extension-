/* content.js - Gmail Phishing Detector with Clean Architecture */

// ═════════════════════════════════════════════════════════════════════════════
// STATE MANAGEMENT
// ═════════════════════════════════════════════════════════════════════════════

const AppState = {
  currentEmailId: null,
  analysisCache: new Map(),
  debounceTimer: null,
  lastUrl: location.href,
  observerStarted: false
};

// ═════════════════════════════════════════════════════════════════════════════
// CONFIGURATION
// ═════════════════════════════════════════════════════════════════════════════

const Config = {
  DEBOUNCE_DELAY: 500,
  EMAIL_CLICK_DELAY: 300,
  OBSERVER_RETRY_DELAY: 800,
  ALERT_DISPLAY_DURATION: 10000,
  ALERT_FADE_DURATION: 300,
  
  RISK_THRESHOLDS: {
    HIGH: 0.7,
    MEDIUM: 0.4
  },
  
  URGENCY_WORDS: [
    'urgent', 'immediate', 'asap', 'now', 'quickly', 'expire',
    'suspended', 'verify', 'confirm', 'act now', 'limited time'
  ],
  
  BODY_SELECTORS: [
    'div.a3s',
    'div[role="listitem"] div.a3s',
    'div[role="main"] .adn',
    'div.gs',
    'div.if'
  ],
  
  EXCLUDED_ELEMENTS: [
    'script',
    'style',
    'blockquote',
    '.gmail_quote',
    '.gmail_extra',
    '.ii.gt'
  ]
};

// ═════════════════════════════════════════════════════════════════════════════
// DOM UTILITIES
// ═════════════════════════════════════════════════════════════════════════════

const DOMUtils = {
  /**
   * Get element by ID with null safety
   */
  getElementById(id) {
    return document.getElementById(id);
  },

  /**
   * Query selector with null safety
   */
  querySelector(selector) {
    return document.querySelector(selector);
  },

  /**
   * Remove element safely
   */
  removeElement(element) {
    if (element && element.parentNode) {
      element.parentNode.removeChild(element);
    }
  },

  /**
   * Create element with properties
   */
  createElement(tag, props = {}) {
    const el = document.createElement(tag);
    Object.entries(props).forEach(([key, value]) => {
      if (key === 'className') el.className = value;
      else if (key === 'innerHTML') el.innerHTML = value;
      else if (key === 'textContent') el.textContent = value;
      else el.setAttribute(key, value);
    });
    return el;
  }
};

// ═════════════════════════════════════════════════════════════════════════════
// EMAIL EXTRACTION
// ═════════════════════════════════════════════════════════════════════════════

const EmailExtractor = {
  /**
   * Extract email ID from URL hash
   */
  extractEmailId() {
    const urlParams = new URLSearchParams(window.location.hash.substring(1));
    return urlParams.get('message_id') || window.location.hash || null;
  },

  /**
   * Get visible text content from element
   */
  getVisibleText(element) {
    if (!element) return '';
    
    const clone = element.cloneNode(true);
    const excludeSelector = Config.EXCLUDED_ELEMENTS.join(', ');
    clone.querySelectorAll(excludeSelector).forEach(node => node.remove());
    
    return clone.innerText.trim();
  },

  /**
   * Find email subject element
   */
  findSubjectElement() {
    return (
      DOMUtils.querySelector('h2.hP') ||
      DOMUtils.querySelector('h2[role="heading"]') ||
      DOMUtils.querySelector('h2')
    );
  },

  /**
   * Find email body element
   */
  findBodyElement() {
    // Try common selectors first
    for (const selector of Config.BODY_SELECTORS) {
      const element = DOMUtils.querySelector(selector);
      if (element && element.innerText && element.innerText.length > 10) {
        return element;
      }
    }

    // Fallback: search for large div in main area
    const main = DOMUtils.querySelector('div[role="main"]');
    if (main) {
      const largeDiv = Array.from(main.querySelectorAll('div')).find(
        div => div.innerText && div.innerText.length > 50
      );
      if (largeDiv) return largeDiv;
    }

    return null;
  },

  /**
   * Extract complete email data
   */
  extractEmail() {
    const subjectEl = this.findSubjectElement();
    const bodyEl = this.findBodyElement();

    return {
      subject: subjectEl ? subjectEl.innerText.trim() : '',
      body: bodyEl ? this.getVisibleText(bodyEl) : '',
      subjectEl,
      bodyEl
    };
  }
};

// ═════════════════════════════════════════════════════════════════════════════
// FEATURE ANALYSIS
// ═════════════════════════════════════════════════════════════════════════════

const FeatureAnalyzer = {
  /**
   * Extract URLs from text
   */
  extractUrls(text) {
    const urlPattern = /https?:\/\/[^\s]+/gi;
    return text.match(urlPattern) || [];
  },

  /**
   * Find urgency words in text
   */
  findUrgencyWords(text) {
    const lowerText = text.toLowerCase();
    return Config.URGENCY_WORDS.filter(word => lowerText.includes(word));
  },

  /**
   * Count exclamation marks
   */
  countExclamations(text) {
    return (text.match(/!/g) || []).length;
  },

  /**
   * Calculate capital letter ratio
   */
  calculateCapitalRatio(text) {
    if (!text.length) return 0;
    
    const capitalCount = text.split('').filter(
      char => char === char.toUpperCase() && char !== char.toLowerCase()
    ).length;
    
    return (capitalCount / text.length * 100).toFixed(1);
  },

  /**
   * Count words in text
   */
  countWords(text) {
    return text.split(/\s+/).filter(word => word.length > 0).length;
  },

  /**
   * Extract all features from email text
   */
  analyze(text) {
    const urls = this.extractUrls(text);
    
    return {
      urlCount: urls.length,
      urls: urls.slice(0, 3), // Show first 3 URLs
      urgencyWords: this.findUrgencyWords(text),
      exclamationCount: this.countExclamations(text),
      capitalRatio: this.calculateCapitalRatio(text),
      textLength: text.length,
      wordCount: this.countWords(text)
    };
  }
};

// ═════════════════════════════════════════════════════════════════════════════
// RISK ASSESSMENT
// ═════════════════════════════════════════════════════════════════════════════

const RiskAssessor = {
  /**
   * Determine risk level from probability
   */
  assessRiskLevel(probability) {
    if (probability >= Config.RISK_THRESHOLDS.HIGH) return 1;      // High
    if (probability >= Config.RISK_THRESHOLDS.MEDIUM) return 0.5;  // Medium
    return 0;                                                       // Low
  },

  /**
   * Get status information for risk level
   */
  getStatusInfo(prediction) {
    const statusMap = {
      1: { class: 'phishbuster-high', text: 'Fraudulent', alert: true },
      0.5: { class: 'phishbuster-medium', text: 'Suspicious', alert: false },
      0: { class: 'phishbuster-low', text: 'Safe', alert: false },
      null: { class: 'phishbuster-analyzing', text: 'Analyzing', alert: false }
    };

    return statusMap[prediction] || { 
      class: 'phishbuster-unknown', 
      text: 'Unknown', 
      alert: false 
    };
  },

  /**
   * Identify risk indicators from features
   */
  identifyRiskIndicators(features, prediction) {
    const risks = [];

    if (features.urlCount > 3) {
      risks.push('⚠️ Multiple URLs detected (Suspicious)');
    }
    if (features.urgencyWords.length > 2) {
      risks.push('⚠️ High urgency language (Suspicious)');
    }
    if (features.exclamationCount > 3) {
      risks.push('⚠️ Excessive punctuation (Suspicious)');
    }
    if (parseFloat(features.capitalRatio) > 15) {
      risks.push('⚠️ Unusual capitalization (Suspicious)');
    }
    if (prediction === 1) {
      risks.push('🔴 LLM marked as High Risk (Fraudulent)');
    }

    return risks;
  }
};

// ═════════════════════════════════════════════════════════════════════════════
// UI BUILDER (Enhanced)
// ═════════════════════════════════════════════════════════════════════════════

const UIBuilder = {
  /**
   * Build risk assessment section with enhanced styling
   */
  buildRiskAssessmentSection(statusText, probability, prediction) {
    const prob = parseFloat(probability);
    
    // Determine badge class
    const badgeClass = prediction === 1 ? 'phishbuster-badge-high' :
                      prediction === 0.5 ? 'phishbuster-badge-medium' :
                      'phishbuster-badge-low';
    
    // Color for progress bar
    const barColorMap = {
      1: '#dc2626',
      0.5: '#d97706',
      0: '#059669'
    };
    const barColor = barColorMap[prediction] || '#6b7280';

    return `
      <div class="phishbuster-section">
        <div class="phishbuster-section-title">
          <span>📊</span> Risk Assessment
        </div>
        <div class="phishbuster-section-content">
          <div class="phishbuster-info-row">
            <span class="phishbuster-info-label">Status</span>
            <span class="phishbuster-badge ${badgeClass}">${statusText}</span>
          </div>
          <div class="phishbuster-info-row">
            <span class="phishbuster-info-label">Confidence</span>
            <span class="phishbuster-info-value">${(prob * 100).toFixed(1)}%</span>
          </div>
          <div class="phishbuster-progress-container">
            <div class="phishbuster-progress-label">Risk Level</div>
            <div class="phishbuster-progress-bar">
              <div class="phishbuster-progress-fill" style="width: ${prob * 100}%; background: ${barColor};"></div>
            </div>
          </div>
        </div>
      </div>
    `;
  },

  /**
   * Build email analysis section with organized metrics
   */
  buildEmailAnalysisSection(features) {
    let html = `
      <div class="phishbuster-section">
        <div class="phishbuster-section-title">
          <span>✉️</span> Email Analysis
        </div>
        <div class="phishbuster-section-content">
          <div class="phishbuster-info-row">
            <span class="phishbuster-info-label">📝 Word Count</span>
            <span class="phishbuster-info-value">${features.wordCount}</span>
          </div>
          <div class="phishbuster-info-row">
            <span class="phishbuster-info-label">🔗 URLs Found</span>
            <span class="phishbuster-info-value">${features.urlCount}</span>
          </div>
          <div class="phishbuster-info-row">
            <span class="phishbuster-info-label">⚠️ Urgency Words</span>
            <span class="phishbuster-info-value">${features.urgencyWords.length}</span>
          </div>
          <div class="phishbuster-info-row">
            <span class="phishbuster-info-label">❗ Exclamation Marks</span>
            <span class="phishbuster-info-value">${features.exclamationCount}</span>
          </div>
          <div class="phishbuster-info-row">
            <span class="phishbuster-info-label">🔤 Capital Ratio</span>
            <span class="phishbuster-info-value">${features.capitalRatio}%</span>
          </div>
        </div>
    `;

    // URLs list if present
    if (features.urls && features.urls.length > 0) {
      html += '<div style="margin-top: 12px;">';
      html += '<div class="phishbuster-info-label" style="margin-bottom: 8px;">🔗 Detected Links:</div>';
      html += '<div class="phishbuster-url-list">';
      features.urls.forEach(url => {
        const shortUrl = url.length > 45 ? url.substring(0, 45) + '...' : url;
        html += `<div class="phishbuster-url-item">${shortUrl}</div>`;
      });
      html += '</div></div>';
    }

    // Urgency words if present
    if (features.urgencyWords.length > 0) {
      html += '<div style="margin-top: 12px;">';
      html += '<div class="phishbuster-info-label" style="margin-bottom: 8px;">⚠️ Urgency Keywords:</div>';
      html += '<div class="phishbuster-list-item" style="background: #fef3c7; color: #92400e;">';
      html += `<span>${features.urgencyWords.join(', ')}</span>`;
      html += '</div></div>';
    }

    html += '</div>'; // Close section
    return html;
  },

  /**
   * Build risk indicators section with visual indicators
   */
  buildRiskIndicatorsSection(risks) {
    let html = `
      <div class="phishbuster-section">
        <div class="phishbuster-section-title">
          <span>🔍</span> Risk Indicators
        </div>
        <div class="phishbuster-section-content">
    `;

    if (risks.length > 0) {
      risks.forEach(risk => {
        html += `<div class="phishbuster-risk-item">${risk}</div>`;
      });
    } else {
      html += '<div class="phishbuster-safe-item">✅ No major risk indicators found</div>';
    }

    html += '</div></div>';
    return html;
  },

  /**
   * Build complete analysis HTML with enhanced structure
   */
  buildAnalysisHTML(analysisData, statusText, prediction) {
    if (!analysisData) {
      return `
        <div class="phishbuster-dropdown-content">
          <div class="phishbuster-list-item">
            <span class="phishbuster-list-item-icon">⏳</span>
            <span>Analysis in progress...</span>
          </div>
        </div>
      `;
    }

    const { features, prediction_prob } = analysisData;
    const risks = RiskAssessor.identifyRiskIndicators(features, prediction);
    const timestamp = new Date().toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });

    let html = '<div class="phishbuster-dropdown-header">Phishing Detector Active</div>';
    html += '<div class="phishbuster-dropdown-content">';
    
    // Add all sections
    html += this.buildRiskAssessmentSection(statusText, prediction_prob, prediction);
    html += this.buildEmailAnalysisSection(features);
    html += this.buildRiskIndicatorsSection(risks);
    
    // Timestamp
    html += `<div class="phishbuster-timestamp">🕒 Analyzed at ${timestamp}</div>`;
    html += '</div>';

    return html;
  }
};

// ═════════════════════════════════════════════════════════════════════════════
// UI MANAGER
// ═════════════════════════════════════════════════════════════════════════════

const UIManager = {
  /**
   * Get or create status panel
   */
  getOrCreatePanel() {
    let panel = DOMUtils.getElementById('phishbuster-inline-panel');
    
    if (!panel) {
      panel = DOMUtils.createElement('div', {
        id: 'phishbuster-inline-panel',
        className: 'phishbuster-panel',
        innerHTML: `
          <div class="phishbuster-status-badge" id="phishbuster-badge">Analyzing</div>
          <div class="phishbuster-dropdown" id="phishbuster-dropdown"></div>
        `
      });

      document.body.appendChild(panel);
      this.attachEventListeners(panel);
    }

    return panel;
  },

  /**
   * Attach event listeners to panel
   */
  attachEventListeners(panel) {
    const badge = panel.querySelector('#phishbuster-badge');
    const dropdown = panel.querySelector('#phishbuster-dropdown');

    // Toggle dropdown on badge click
    badge.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();

      const isOpening = !dropdown.classList.contains('show');
      dropdown.classList.toggle('show');

      // Populate content when opening
      if (isOpening) {
        const storedData = JSON.parse(panel.getAttribute('data-analysis') || '{}');
        dropdown.innerHTML = UIBuilder.buildAnalysisHTML(
          storedData.analysisData,
          storedData.statusText,
          storedData.prediction
        );
      }
    });

    // Prevent clicks inside dropdown from closing it
    dropdown.addEventListener('click', (e) => {
      e.stopPropagation();
    });
  },

  /**
   * Update status badge
   */
  updateStatusBadge(prediction, analysisData) {
    const { subjectEl } = EmailExtractor.extractEmail();
    
    if (!subjectEl) {
      this.removePanel();
      return;
    }

    const statusInfo = RiskAssessor.getStatusInfo(prediction);
    const panel = this.getOrCreatePanel();
    const badge = panel.querySelector('#phishbuster-badge');
    const dropdown = panel.querySelector('#phishbuster-dropdown');

    // Update badge
    badge.className = `phishbuster-status-badge ${statusInfo.class}`;
    badge.textContent = statusInfo.text;

    // Store analysis data
    panel.setAttribute('data-analysis', JSON.stringify({
      prediction,
      analysisData,
      statusText: statusInfo.text,
      statusClass: statusInfo.class
    }));

    // Update dropdown if it's open
    if (dropdown.classList.contains('show')) {
      dropdown.innerHTML = UIBuilder.buildAnalysisHTML(
        analysisData,
        statusInfo.text,
        prediction
      );
    }

    // Show/hide alert
    if (statusInfo.alert) {
      this.showHighRiskAlert();
    } else {
      this.removeAlert();
    }
  },

  /**
   * Show high-risk alert
   */
  showHighRiskAlert() {
    if (DOMUtils.getElementById('phishbuster-alert')) return;

    const alert = DOMUtils.createElement('div', {
      id: 'phishbuster-alert',
      className: 'phishbuster-alert show',
      innerHTML: `
        <span class="phishbuster-alert-icon">⚠️</span>
        <div style="display: inline-block;">
          <div class="phishbuster-alert-title">Warning: Potential Phishing Email Detected</div>
          <div class="phishbuster-alert-message">
            This email contains suspicious patterns. Do not click links or provide personal information.
          </div>
        </div>
      `
    });

    document.body.appendChild(alert);

    // Auto-hide after configured duration
    setTimeout(() => {
      alert.classList.remove('show');
      setTimeout(() => DOMUtils.removeElement(alert), Config.ALERT_FADE_DURATION);
    }, Config.ALERT_DISPLAY_DURATION);
  },

  /**
   * Remove alert
   */
  removeAlert() {
    const alert = DOMUtils.getElementById('phishbuster-alert');
    if (alert) DOMUtils.removeElement(alert);
  },

  /**
   * Remove status panel
   */
  removePanel() {
    const panel = DOMUtils.getElementById('phishbuster-inline-panel');
    if (panel) DOMUtils.removeElement(panel);
    this.removeAlert();
  }
};

// ═════════════════════════════════════════════════════════════════════════════
// API COMMUNICATION
// ═════════════════════════════════════════════════════════════════════════════

const APIService = {
  /**
   * Send email text to background script for analysis
   */
  analyzeEmail(text, callback) {
    chrome.runtime.sendMessage(
      { type: 'CHECK_TEXT', text },
      (response) => {
        if (!response || !response.ok) {
          callback({ error: true, data: null });
          return;
        }
        callback({ error: false, data: response.data });
      }
    );
  }
};

// ═════════════════════════════════════════════════════════════════════════════
// ANALYSIS CONTROLLER
// ═════════════════════════════════════════════════════════════════════════════

const AnalysisController = {
  /**
   * Check if email is already cached
   */
  getCachedAnalysis(emailId) {
    return AppState.analysisCache.get(emailId);
  },

  /**
   * Cache analysis result
   */
  cacheAnalysis(emailId, prediction, analysisData) {
    AppState.analysisCache.set(emailId, { prediction, analysisData });
  },

  /**
   * Perform phishing analysis on email
   */
  analyzeEmail(text, emailId) {
    if (!text || text.length < 10) return;

    // Check cache first
    const cached = this.getCachedAnalysis(emailId);
    if (cached) {
      UIManager.updateStatusBadge(cached.prediction, cached.analysisData);
      return;
    }

    // Show analyzing state
    UIManager.updateStatusBadge(null, null);

    // Call API
    APIService.analyzeEmail(text, (result) => {
      if (result.error) {
        const features = FeatureAnalyzer.analyze(text);
        const analysisData = { features, prediction_prob: 0.05 };
        UIManager.updateStatusBadge('unknown', analysisData);
        return;
      }

      const data = result.data || {};
      const probability = parseFloat(data.prediction_prob || data.phishing_probability || 0);
      const prediction = RiskAssessor.assessRiskLevel(probability);
      const features = FeatureAnalyzer.analyze(text);

      const analysisData = {
        features,
        prediction_prob: probability,
        raw_data: data
      };

      this.cacheAnalysis(emailId, prediction, analysisData);
      UIManager.updateStatusBadge(prediction, analysisData);
    });
  },

  /**
   * Schedule email check with debouncing
   */
  scheduleCheck() {
    if (AppState.debounceTimer) {
      clearTimeout(AppState.debounceTimer);
    }

    AppState.debounceTimer = setTimeout(() => {
      AppState.debounceTimer = null;

      const emailId = EmailExtractor.extractEmailId();

      // Same email - show cached result
      if (emailId && emailId === AppState.currentEmailId) {
        const cached = this.getCachedAnalysis(emailId);
        if (cached) {
          UIManager.updateStatusBadge(cached.prediction, cached.analysisData);
        }
        return;
      }

      // New email
      AppState.currentEmailId = emailId;

      const { subject, body } = EmailExtractor.extractEmail();
      const combined = (subject + '\n\n' + body).trim();

      if (!combined || combined.length < 10) {
        UIManager.removePanel();
        return;
      }

      this.analyzeEmail(combined, emailId);
    }, Config.DEBOUNCE_DELAY);
  }
};

// ═════════════════════════════════════════════════════════════════════════════
// OBSERVER MANAGER
// ═════════════════════════════════════════════════════════════════════════════

const ObserverManager = {
  /**
   * Start DOM mutation observer
   */
  startDOMObserver() {
    if (AppState.observerStarted) return;
    AppState.observerStarted = true;

    const findAndObserve = () => {
      const targetNode = DOMUtils.querySelector('div[role="main"]') || document.body;
      
      if (!targetNode) {
        setTimeout(findAndObserve, Config.OBSERVER_RETRY_DELAY);
        return;
      }

      const observer = new MutationObserver((mutations) => {
        const hasChanges = mutations.some(
          m => m.addedNodes.length > 0 || m.removedNodes.length > 0
        );
        
        if (hasChanges) {
          AnalysisController.scheduleCheck();
        }
      });

      observer.observe(targetNode, {
        childList: true,
        subtree: true
      });

      // Initial check
      AnalysisController.scheduleCheck();
    };

    findAndObserve();
  },

  /**
   * Start URL change observer
   */
  startURLObserver() {
    new MutationObserver(() => {
      const currentUrl = location.href;
      if (currentUrl !== AppState.lastUrl) {
        AppState.lastUrl = currentUrl;
        AppState.currentEmailId = null;
        AnalysisController.scheduleCheck();
      }
    }).observe(document, {
      subtree: true,
      childList: true
    });
  },

  /**
   * Start click event listener
   */
  startClickListener() {
    document.addEventListener('click', (evt) => {
      const row = evt.target.closest('.zA, [role="link"], .ae4');
      if (row) {
        setTimeout(() => {
          AnalysisController.scheduleCheck();
        }, Config.EMAIL_CLICK_DELAY);
      }
    });
  },

  /**
   * Initialize all observers
   */
  initialize() {
    this.startDOMObserver();
    this.startURLObserver();
    this.startClickListener();
  }
};

// ═════════════════════════════════════════════════════════════════════════════
// APPLICATION INITIALIZATION
// ═════════════════════════════════════════════════════════════════════════════

// Start the application
ObserverManager.initialize();

console.log('🛡️ PhishBuster initialized successfully');
