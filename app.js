// app.js — dashboard behaviour
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

  // NOTE: this is a UI-only convenience, not a real access control boundary.
  // The corresponding server endpoints do not re-check the role, which is
  // exactly the Phase 1 vulnerability documented in server.js.
  if (currentUser.role === 'admin') {
    document.getElementById('usersBtn').style.display = 'inline-block';
  }
  if (currentUser.role === 'employee') {
    document.getElementById('showFormBtn').style.display = 'none';
  }

  loadTasks();
}

function toggleForm() {
  const form = document.getElementById('newTaskForm');
  form.style.display = form.style.display === 'none' ? 'block' : 'none';
}

async function loadTasks() {
  const search = document.getElementById('search').value;
  const res = await fetch('/api/tasks?search=' + encodeURIComponent(search), { credentials: 'include' });
  const tasks = await res.json();
  const list = document.getElementById('taskList');

  if (!Array.isArray(tasks)) {
    list.textContent = 'Error loading tasks';
    return;
  }

  list.innerHTML = tasks.map(t => `
    <div class="task-card">
      <h3>${t.title} <span class="badge ${t.priority}">${t.priority}</span></h3>
      <p>${t.description || ''}</p>
      <p style="font-size:12px;color:#5e6c84">Status:
        <select onchange="updateStatus(${t.id}, this.value)">
          <option value="todo" ${t.status === 'todo' ? 'selected' : ''}>To do</option>
          <option value="in_progress" ${t.status === 'in_progress' ? 'selected' : ''}>In progress</option>
          <option value="done" ${t.status === 'done' ? 'selected' : ''}>Done</option>
        </select>
        · assigned to user #${t.assignee_id ?? '-'}
        ${currentUser.role === 'admin' ? `<button onclick="deleteTask(${t.id})">Delete</button>` : ''}
      </p>
      <div id="comments-${t.id}"></div>
      <input placeholder="Add a comment..." onkeyup="if(event.key==='Enter'){ addComment(${t.id}, this.value); this.value=''; }" />
    </div>
  `).join('');

  tasks.forEach(t => loadComments(t.id));
}

async function loadComments(taskId) {
  const res = await fetch(`/api/tasks/${taskId}/comments`, { credentials: 'include' });
  const comments = await res.json();
  const el = document.getElementById(`comments-${taskId}`);
  if (!el || !Array.isArray(comments)) return;

  // VULNERABLE (Phase 1): comment body is inserted via innerHTML without
  // any escaping - this is what makes the server-side stored XSS
  // vulnerability (see server.js handleGetComments) actually execute in
  // the browser. Fixed in Phase 2 by escaping/using textContent, or a
  // templating layer that auto-escapes.
  el.innerHTML = comments.map(c => `<div class="comment"><b>${c.username}:</b> ${c.body}</div>`).join('');
}

async function addComment(taskId, body) {
  if (!body) return;
  await fetch(`/api/tasks/${taskId}/comments`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ body }),
    credentials: 'include'
  });
  loadComments(taskId);
}

async function updateStatus(taskId, status) {
  await fetch(`/api/tasks/${taskId}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status }),
    credentials: 'include'
  });
}

async function deleteTask(taskId) {
  await fetch(`/api/tasks/${taskId}`, { method: 'DELETE', credentials: 'include' });
  loadTasks();
}

async function createTask() {
  const title = document.getElementById('newTitle').value;
  const description = document.getElementById('newDesc').value;
  const priority = document.getElementById('newPriority').value;
  const assignee_id = document.getElementById('newAssignee').value || null;

  await fetch('/api/tasks', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ title, description, priority, assignee_id }),
    credentials: 'include'
  });
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