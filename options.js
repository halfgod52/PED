function showStatus() {
  const status = document.getElementById('status');
  status.classList.add('show');
  setTimeout(() => status.classList.remove('show'), 2000);
}

function renderList(ulId, items, storageKey) {
  const ul = document.getElementById(ulId);
  ul.innerHTML = '';
  items.forEach((item, index) => {
    const li = document.createElement('li');
    li.textContent = item;
    const btn = document.createElement('button');
    btn.textContent = '✕';
    btn.className = 'delete-btn';
    btn.onclick = () => {
      items.splice(index, 1);
      chrome.storage.sync.set({ [storageKey]: items }, () => {
        renderList(ulId, items, storageKey);
        showStatus();
      });
    };
    li.appendChild(btn);
    ul.appendChild(li);
  });
}

function addItem(inputId, storageKey, items, ulId) {
  const input = document.getElementById(inputId);
  const val = input.value.trim().toLowerCase();
  if (val && !items.includes(val)) {
    items.push(val);
    chrome.storage.sync.set({ [storageKey]: items }, () => {
      input.value = '';
      renderList(ulId, items, storageKey);
      showStatus();
    });
  }
}

document.addEventListener('DOMContentLoaded', () => {
  chrome.storage.sync.get({ customBrands: [], trustedSenders: [] }, (data) => {
    let customBrands = data.customBrands;
    let trustedSenders = data.trustedSenders;

    renderList('brandList', customBrands, 'customBrands');
    renderList('trustedList', trustedSenders, 'trustedSenders');

    document.getElementById('addBrandBtn').onclick = () => addItem('brandInput', 'customBrands', customBrands, 'brandList');
    document.getElementById('addTrustedBtn').onclick = () => addItem('trustedInput', 'trustedSenders', trustedSenders, 'trustedList');
  });
});
