const state = {
  token: localStorage.getItem('agentzt.session') || '',
  policy: null,
};

const statusEl = document.querySelector('#status');
const loginPanel = document.querySelector('#login-panel');
const consolePanel = document.querySelector('#console-panel');
const logout = document.querySelector('#logout');

function setStatus(message, ok = true) {
  statusEl.textContent = message;
  statusEl.style.color = ok ? '#bbf7d0' : '#fecaca';
}

function authHeaders() {
  return state.token ? { authorization: 'Bearer ' + state.token } : {};
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      ...(options.body ? { 'content-type': 'application/json' } : {}),
      ...authHeaders(),
      ...(options.headers || {}),
    },
  });
  const text = await response.text();
  const data = text ? JSON.parse(text) : {};
  if (!response.ok) {
    throw new Error(data.error?.message || data.message || `${response.status} ${response.statusText}`);
  }
  return data;
}

function json(value) {
  return JSON.stringify(value ?? {}, null, 2);
}

function csv(value) {
  return String(value || '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
}

function parseJsonField(value, fallback) {
  const trimmed = String(value || '').trim();
  return trimmed ? JSON.parse(trimmed) : fallback;
}

function showConsole(show) {
  loginPanel.classList.toggle('hidden', show);
  consolePanel.classList.toggle('hidden', !show);
  logout.classList.toggle('hidden', !show);
}

function renderTable(table, rows, columns, actions) {
  table.innerHTML = '';
  const thead = table.createTHead();
  const head = thead.insertRow();
  for (const column of columns) head.insertCell().outerHTML = `<th>${column.label}</th>`;
  if (actions) head.insertCell().outerHTML = '<th>Actions</th>';
  const tbody = table.createTBody();
  for (const row of rows) {
    const tr = tbody.insertRow();
    for (const column of columns) tr.insertCell().textContent = column.value(row);
    if (actions) actions(tr.insertCell(), row);
  }
}

async function loadAgents() {
  const data = await api('/api/v1/agents');
  const agents = data.agents || [];
  document.querySelector('#agent-count').textContent = String(data.total ?? agents.length);
  renderTable(document.querySelector('#agents-table'), agents, [
    { label: 'Agent', value: (row) => row.agentId },
    { label: 'Role', value: (row) => row.role },
    { label: 'Status', value: (row) => row.status || 'active' },
    { label: 'Project', value: (row) => row.governance?.projectId || '' },
    { label: 'Description', value: (row) => row.description || '' },
  ], (cell, row) => {
    const disable = document.createElement('button');
    disable.type = 'button';
    disable.textContent = row.status === 'disabled' ? 'Enable' : 'Disable';
    disable.onclick = async () => {
      await api(`/api/v1/agents/${encodeURIComponent(row.agentId)}`, {
        method: 'PATCH',
        body: JSON.stringify({ status: row.status === 'disabled' ? 'active' : 'disabled' }),
      });
      await loadAgents();
    };
    const remove = document.createElement('button');
    remove.type = 'button';
    remove.className = 'secondary';
    remove.textContent = 'Delete';
    remove.onclick = async () => {
      await api(`/api/v1/agents/${encodeURIComponent(row.agentId)}`, { method: 'DELETE' });
      await loadAgents();
    };
    cell.append(disable, ' ', remove);
  });
}

async function loadProjects() {
  const data = await api('/api/v1/projects');
  const projects = data.projects || [];
  document.querySelector('#project-count').textContent = String(projects.length);
  const list = document.querySelector('#project-list');
  list.innerHTML = '';
  for (const projectId of projects) {
    const item = document.createElement('li');
    item.textContent = projectId;
    const remove = document.createElement('button');
    remove.type = 'button';
    remove.className = 'secondary';
    remove.textContent = 'Delete';
    remove.onclick = async () => {
      await api(`/api/v1/projects/${encodeURIComponent(projectId)}`, { method: 'DELETE' });
      await loadProjects();
    };
    item.append(remove);
    list.append(item);
  }
}

async function loadPolicy() {
  const policy = await api('/api/v1/policy');
  state.policy = policy;
  document.querySelector('#policy-json').value = json(policy);
  const roles = Object.entries(policy.roles || {}).map(([name, role]) => ({ name, role }));
  document.querySelector('#role-count').textContent = String(roles.length);
  renderTable(document.querySelector('#roles-table'), roles, [
    { label: 'Role', value: (row) => row.name },
    { label: 'Models', value: (row) => (row.role.models || []).join(', ') },
    { label: 'Tools', value: (row) => (row.role.tools || []).join(', ') },
    { label: 'Governance', value: (row) => json(row.role.governance) },
  ], (cell, row) => {
    const remove = document.createElement('button');
    remove.type = 'button';
    remove.className = 'secondary';
    remove.textContent = 'Delete';
    remove.onclick = async () => {
      await api(`/api/v1/roles/${encodeURIComponent(row.name)}`, { method: 'DELETE' });
      await loadPolicy();
    };
    cell.append(remove);
  });
}

async function loadAudit(form = new FormData(document.querySelector('#audit-filter'))) {
  const params = new URLSearchParams({ limit: '100', verify: '1' });
  for (const [key, value] of form.entries()) {
    if (String(value).trim()) params.set(key, String(value).trim());
  }
  const data = await api(`/api/v1/audit?${params}`);
  document.querySelector('#audit-count').textContent = String((data.events || []).length);
  document.querySelector('#audit-output').textContent = json(data);
}

async function refreshAll() {
  await Promise.all([loadAgents(), loadProjects(), loadPolicy(), loadAudit()]);
  setStatus('Console data loaded');
}

document.querySelector('#login-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  try {
    const data = await api('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({
        email: form.get('email'),
        password: form.get('password'),
      }),
    });
    state.token = data.session.token;
    localStorage.setItem('agentzt.session', state.token);
    showConsole(true);
    await refreshAll();
  } catch (err) {
    setStatus(err.message, false);
  }
});

logout.addEventListener('click', async () => {
  try {
    await api('/api/auth/logout', { method: 'POST' });
  } catch {
    // Local logout still clears the browser session.
  }
  state.token = '';
  localStorage.removeItem('agentzt.session');
  showConsole(false);
  setStatus('Logged out');
});

for (const tab of document.querySelectorAll('.tab')) {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach((item) => item.classList.toggle('active', item === tab));
    document.querySelectorAll('.view').forEach((view) => view.classList.toggle('active', view.id === tab.dataset.tab));
  });
}

document.querySelectorAll('[data-refresh]').forEach((button) => {
  button.addEventListener('click', async () => {
    try {
      const section = button.dataset.refresh;
      if (section === 'agents') await loadAgents();
      if (section === 'projects') await loadProjects();
      if (section === 'policy') await loadPolicy();
      if (section === 'audit') await loadAudit();
      setStatus(`${section} refreshed`);
    } catch (err) {
      setStatus(err.message, false);
    }
  });
});

document.querySelector('#agent-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  try {
    await api('/api/v1/agents', {
      method: 'POST',
      body: JSON.stringify({
        agentId: form.get('agentId'),
        role: form.get('role'),
        status: form.get('status'),
        description: form.get('description') || undefined,
        publicKeyJwk: parseJsonField(form.get('publicKeyJwk'), {}),
        governance: parseJsonField(form.get('governance'), undefined),
      }),
    });
    event.currentTarget.reset();
    await loadAgents();
    setStatus('Agent created');
  } catch (err) {
    setStatus(err.message, false);
  }
});

document.querySelector('#project-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  try {
    await api('/api/v1/projects', {
      method: 'POST',
      body: JSON.stringify({ projectId: form.get('projectId') }),
    });
    event.currentTarget.reset();
    await loadProjects();
    setStatus('Project added');
  } catch (err) {
    setStatus(err.message, false);
  }
});

document.querySelector('#role-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const roleName = String(form.get('roleName') || '').trim();
  try {
    await api(`/api/v1/roles/${encodeURIComponent(roleName)}`, {
      method: 'PUT',
      body: JSON.stringify({
        models: csv(form.get('models')),
        tools: csv(form.get('tools')),
        governance: parseJsonField(form.get('governance'), undefined),
      }),
    });
    event.currentTarget.reset();
    await loadPolicy();
    setStatus('Role saved');
  } catch (err) {
    setStatus(err.message, false);
  }
});

document.querySelector('#save-policy').addEventListener('click', async () => {
  try {
    const policy = JSON.parse(document.querySelector('#policy-json').value);
    await api('/api/v1/policy', { method: 'PUT', body: JSON.stringify(policy) });
    await loadPolicy();
    setStatus('Policy saved');
  } catch (err) {
    setStatus(err.message, false);
  }
});

document.querySelector('#audit-filter').addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    await loadAudit(new FormData(event.currentTarget));
    setStatus('Audit filtered');
  } catch (err) {
    setStatus(err.message, false);
  }
});

if (state.token) {
  showConsole(true);
  refreshAll().catch((err) => {
    setStatus(err.message, false);
    showConsole(false);
  });
} else {
  showConsole(false);
}
