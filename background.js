// background.js (service worker)
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'CHECK_TEXT') {
    const payload = { text: message.text };
    // call backend predict endpoint
    fetch('http://127.0.0.1:5000/api/predict', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    })
    .then(resp => resp.json())
    .then(data => {
      sendResponse({ ok: true, data });
    })
    .catch(err => {
      console.error('Background fetch error:', err);
      sendResponse({ ok: false, error: err.toString() });
    });
    // keep the message channel open for async response
    return true;
  }
});
