// app.js — Phase 2 (secured)
let currentUser = null;

async function init() {
  const res = await fetch('/api/me', { credentials: 'include' });
  if (!res.ok) {
    window.location = '/login.html';
    return;
  }
  currentUser = await res.json();
  document.getElementById('whoami').textContent = currentUser.username;
  document.getElementById('role').textContent = currentUser.role;

  // This is still just a UI convenience - the real enforcement is
  // server-side (requireRole() in server.js). Hiding a button here changes
  // nothing security-relevant; it's just a better user experience.
  if (currentUser.role === 'admin') {
    document.getElementById('usersBtn').style.display = 'inline-block';
  }
  if (currentUser.role === 'manager' || currentUser.role === 'admin') {
    document.getElementById('showFormBtn').style.display = 'inline-block';
  }

  loadTasks();
}

function toggleForm() {
  const form = document.getElementById('newTaskForm');
  form.style.display = form.style.display === 'none' ? 'block' : 'none';
}

function el(tag, props = {}, children = []) {
  const node = document.createElement(tag);
  Object.entries(props).forEach(([k, v]) => {
    if (k === 'class') node.className = v;
    else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  });
  children.forEach((c) => node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c));
  return node;
}

async function loadTasks() {
  const search = document.getElementById('search').value;
  const res = await fetch('/api/tasks?search=' + encodeURIComponent(search), { credentials: 'include' });
  const tasks = await res.json();
  const list = document.getElementById('taskList');
  list.innerHTML = '';

  if (!Array.isArray(tasks)) {
    list.textContent = 'Error loading tasks';
    return;
  }

  tasks.forEach((t) => {
    // FIX (#7 Stored XSS): every piece of task/comment text is inserted via
    // textContent / DOM nodes, never innerHTML - so a title, description,
    // or comment containing "<script>" is rendered as inert text, not code.
    const card = el('div', { class: 'task-card' });

    const title = el('h3', {}, [t.title + ' ']);
    const badge = el('span', { class: `badge ${t.priority}` }, [t.priority]);
    title.appendChild(badge);
    card.appendChild(title);

    card.appendChild(el('p', {}, [t.description || '']));

    const statusRow = el('p', { style: 'font-size:12px;color:#5e6c84' });
    const select = el('select', {
      onchange: (e) => updateStatus(t.id, e.target.value),
    });
    ['todo', 'in_progress', 'done'].forEach((s) => {
      const opt = el('option', { value: s }, [s.replace('_', ' ')]);
      if (t.status === s) opt.setAttribute('selected', 'selected');
      select.appendChild(opt);
    });
    statusRow.appendChild(document.createTextNode('Status: '));
    statusRow.appendChild(select);
    statusRow.appendChild(document.createTextNode(` · assigned to user #${t.assignee_id ?? '-'} `));
    if (currentUser.role === 'admin') {
      statusRow.appendChild(el('button', { onclick: () => deleteTask(t.id) }, ['Delete']));
    }
    card.appendChild(statusRow);

    const commentsDiv = el('div', { id: `comments-${t.id}` });
    card.appendChild(commentsDiv);

    const commentInput = el('input', { placeholder: 'Add a comment...' });
    commentInput.addEventListener('keyup', (e) => {
      if (e.key === 'Enter') {
        addComment(t.id, commentInput.value);
        commentInput.value = '';
      }
    });
    card.appendChild(commentInput);

    list.appendChild(card);
    loadComments(t.id);
  });
}

async function loadComments(taskId) {
  const res = await fetch(`/api/tasks/${taskId}/comments`, { credentials: 'include' });
  const comments = await res.json();
  const container = document.getElementById(`comments-${taskId}`);
  if (!container || !Array.isArray(comments)) return;

  container.innerHTML = '';
  comments.forEach((c) => {
    // Server already HTML-escapes on the way out (defense in depth), and we
    // additionally use textContent here so nothing is ever interpreted as
    // markup client-side either.
    const div = el('div', { class: 'comment' });
    const b = el('b', {}, [c.username + ': ']);
    div.appendChild(b);
    div.appendChild(document.createTextNode(c.body));
    container.appendChild(div);
  });
}

async function addComment(taskId, body) {
  if (!body) return;
  const res = await fetch(`/api/tasks/${taskId}/comments`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ body }),
    credentials: 'include'
  });
  if (!res.ok) {
    const data = await res.json();
    alert(data.error || 'Could not add comment');
  }
  loadComments(taskId);
}

async function updateStatus(taskId, status) {
  const res = await fetch(`/api/tasks/${taskId}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status }),
    credentials: 'include'
  });
  if (!res.ok) {
    const data = await res.json();
    alert(data.error || 'Could not update task');
    loadTasks();
  }
}

async function deleteTask(taskId) {
  const res = await fetch(`/api/tasks/${taskId}`, { method: 'DELETE', credentials: 'include' });
  if (!res.ok) {
    const data = await res.json();
    alert(data.error || 'Could not delete task');
  }
  loadTasks();
}

async function createTask() {
  const title = document.getElementById('newTitle').value;
  const description = document.getElementById('newDesc').value;
  const priority = document.getElementById('newPriority').value;
  const assignee_id = document.getElementById('newAssignee').value || null;

  const res = await fetch('/api/tasks', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ title, description, priority, assignee_id }),
    credentials: 'include'
  });
  if (!res.ok) {
    const data = await res.json();
    alert(data.error || 'Could not create task');
    return;
  }
  document.getElementById('newTitle').value = '';
  document.getElementById('newDesc').value = '';
  toggleForm();
  loadTasks();
}

async function logout() {
  await fetch('/api/logout', { method: 'POST', credentials: 'include' });
  window.location = '/login.html';
}

init();
