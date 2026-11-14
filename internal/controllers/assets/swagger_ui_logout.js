;(function () {
  var buttonId = 'swagger-ui-logout-button';
  var base = 'oklch(64.5% 0.246 16.439)';
  var hover = 'oklch(71.2% 0.194 13.428)';

  function post(path) {
    return fetch(path, { method: 'POST', credentials: 'same-origin' });
  }

  function logout() {
    return post('/auth/logout')
      .then(function (res) {
        if (res.status !== 401) {
          return res;
        }
        return post('/auth/refresh').then(function () {
          return post('/auth/logout');
        });
      })
      .catch(function () {});
  }

  function createButton() {
    var button = document.createElement('button');
    button.id = buttonId;
    button.type = 'button';
    button.textContent = 'Logout';
    var style = button.style;
    style.background = base;
    style.color = '#fff';
    style.padding = '8px 16px';
    style.borderRadius = '4px';
    style.border = 'none';
    style.font = '500 14px/20px ui-sans-serif, system-ui, sans-serif';
    style.cursor = 'pointer';
    style.marginLeft = '12px';
    style.transition = 'background-color 200ms';
    button.addEventListener('mouseenter', function () { style.background = hover; });
    button.addEventListener('mouseleave', function () { style.background = base; });
    button.addEventListener('focus', function () { style.outline = '2px solid ' + hover; style.outlineOffset = '2px'; });
    button.addEventListener('blur', function () { style.outline = 'none'; });
    button.addEventListener('click', function () {
      logout().then(function () { location.replace('/swagger/'); });
    });
    return button;
  }

  function insert() {
    if (document.getElementById(buttonId)) {
      return true;
    }
    var wrapper = document.querySelector('.topbar .topbar-wrapper');
    if (!wrapper) {
      return false;
    }
    wrapper.appendChild(createButton());
    return true;
  }

  if (insert()) {
    return;
  }
  var observer = new MutationObserver(function () {
    if (insert()) {
      observer.disconnect();
    }
  });
  observer.observe(document.body, { childList: true, subtree: true });
  setTimeout(function () { observer.disconnect(); }, 10000);
})();
