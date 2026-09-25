// app.js — Phase 2 (secured), dashboard page only.
// Shared helpers (el, apiFetch, showToast, initTopbar) live in common.js.
let currentUser = null;

async function init() {
  currentUser = await initTopbar();
  if (!currentUser) return; // initTopbar already redirected to login

  // This is still just a UI convenience - the real enforcement is
  // server-side (requireRole() in server.js). Hiding a button here changes
  // nothing security-relevant; it's just a better user experience.
  if (currentUser.role === 'manager' || currentUser.role === 'admin') {
    document.getElementById('showFormBtn').style.display = 'inline-block';
  }

  loadTasks();
}

function toggleForm() {
  const form = document.getElementById('newTaskForm');
  const showing = form.style.display === 'block';
  form.style.display = showing ? 'none' : 'block';
  document.getElementById('formErr').textContent = '';
  if (!showing) document.getElementById('newTitle').focus();
}

async function loadTasks() {
  const loading = document.getElementById('loading');
  const list = document.getElementById('taskList');
  loading.style.display = 'block';
  list.innerHTML = '';

  const search = document.getElementById('search').value;
  let tasks;
  try {
    tasks = await apiFetch('/api/tasks?search=' + encodeURIComponent(search));
  } catch (e) {
    loading.style.display = 'none';
    list.appendChild(el('div', { class: 'empty-state' }, [
      el('div', { class: 'icon' }, ['⚠️']),
      el('p', {}, ['Could not reach the server.']),
    ]));
    return;
  }
  loading.style.display = 'none';

  if (!Array.isArray(tasks)) {
    list.appendChild(el('div', { class: 'empty-state' }, [
      el('div', { class: 'icon' }, ['⚠️']),
      el('p', {}, ['Error loading tasks.']),
    ]));
    return;
  }

  if (tasks.length === 0) {
    list.appendChild(el('div', { class: 'empty-state' }, [
      el('div', { class: 'icon' }, ['📋']),
      el('p', {}, [search ? `No tasks match "${search}".` : 'No tasks yet.']),
    ]));
    return;
  }

  tasks.forEach((t) => {
    // FIX (#7 Stored XSS): every piece of task/comment text is inserted via
    // textContent / DOM nodes, never innerHTML - so a title, description,
    // or comment containing "<script>" is rendered as inert text, not code.
    const card = el('div', { class: `task-card priority-${t.priority}` });

    const title = el('h3', {}, [t.title + ' ']);
    const badge = el('span', { class: `badge ${t.priority}` }, [t.priority]);
    title.appendChild(badge);
    card.appendChild(title);

    if (t.description) {
      card.appendChild(el('p', { class: 'task-desc' }, [t.description]));
    }

    const statusRow = el('div', { class: 'status-row' });
    const select = el('select', {
      onchange: (e) => updateStatus(t.id, e.target.value),
    });
    ['todo', 'in_progress', 'done'].forEach((s) => {
      const opt = el('option', { value: s }, [s.replace('_', ' ')]);
      if (t.status === s) opt.setAttribute('selected', 'selected');
      select.appendChild(opt);
    });
    statusRow.appendChild(document.createTextNode('Status:'));
    statusRow.appendChild(select);
    statusRow.appendChild(document.createTextNode(`assigned to #${t.assignee_id ?? '—'}`));
    statusRow.appendChild(el('span', { class: 'spacer' }));
    if (currentUser.role === 'admin') {
      statusRow.appendChild(el('button', { class: 'danger', onclick: () => deleteTask(t.id) }, ['Delete']));
    }
    card.appendChild(statusRow);

    const commentsDiv = el('div', { class: 'comments', id: `comments-${t.id}` }, [
      el('div', { class: 'comment-empty' }, ['Loading comments…']),
    ]);
    card.appendChild(commentsDiv);

    const commentRow = el('div', { class: 'comment-input-row' });
    const commentInput = el('input', { placeholder: 'Add a comment and press Enter…' });
    commentInput.addEventListener('keyup', (e) => {
      if (e.key === 'Enter' && commentInput.value.trim()) {
        addComment(t.id, commentInput.value);
        commentInput.value = '';
      }
    });
    commentRow.appendChild(commentInput);
    card.appendChild(commentRow);

    list.appendChild(card);
    loadComments(t.id);
  });
}

async function loadComments(taskId) {
  const container = document.getElementById(`comments-${taskId}`);
  let comments;
  try {
    comments = await apiFetch(`/api/tasks/${taskId}/comments`);
  } catch (e) {
    return;
  }
  if (!container || !Array.isArray(comments)) return;

  container.innerHTML = '';

  if (comments.length === 0) {
    container.appendChild(el('div', { class: 'comment-empty' }, ['No comments yet.']));
    return;
  }

  comments.forEach((c) => {
    // Server already HTML-escapes on the way out (defense in depth), and we
    // additionally use textContent here so nothing is ever interpreted as
    // markup client-side either.
    const div = el('div', { class: 'comment' });
    div.appendChild(el('b', { class: 'who' }, [c.username + ': ']));
    div.appendChild(document.createTextNode(c.body));
    container.appendChild(div);
  });
}

async function addComment(taskId, body) {
  if (!body) return;
  try {
    await apiFetch(`/api/tasks/${taskId}/comments`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ body }),
    });
  } catch (e) {
    showToast(e.message || 'Could not add comment');
  }
  loadComments(taskId);
}

async function updateStatus(taskId, status) {
  try {
    await apiFetch(`/api/tasks/${taskId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status }),
    });
    showToast('Task updated', false);
  } catch (e) {
    showToast(e.message || 'Could not update task');
    loadTasks();
  }
}

async function deleteTask(taskId) {
  if (!confirm('Delete this task? This cannot be undone.')) return;
  try {
    await apiFetch(`/api/tasks/${taskId}`, { method: 'DELETE' });
    showToast('Task deleted', false);
  } catch (e) {
    showToast(e.message || 'Could not delete task');
  }
  loadTasks();
}

async function createTask() {
  const title = document.getElementById('newTitle').value;
  const description = document.getElementById('newDesc').value;
  const priority = document.getElementById('newPriority').value;
  const assignee_id = document.getElementById('newAssignee').value || null;
  const formErr = document.getElementById('formErr');
  formErr.textContent = '';

  if (!title.trim()) {
    formErr.textContent = 'Title is required.';
    return;
  }

  try {
    await apiFetch('/api/tasks', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title, description, priority, assignee_id }),
    });
  } catch (e) {
    formErr.textContent = e.message || 'Could not create task';
    return;
  }
  document.getElementById('newTitle').value = '';
  document.getElementById('newDesc').value = '';
  document.getElementById('newAssignee').value = '';
  toggleForm();
  showToast('Task created', false);
  loadTasks();
}

init();
