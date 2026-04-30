import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  AlertTriangle,
  CheckCircle2,
  ClipboardList,
  FolderKanban,
  LogOut,
  Plus,
  Shield,
  Trash2,
  UserPlus,
  Users,
} from "lucide-react";
import "./styles.css";

const API = "/api";
const statuses = ["To Do", "In Progress", "Done"];
const priorities = ["Low", "Medium", "High"];

function useApi() {
  const [token, setToken] = useState(localStorage.getItem("ttm_token") || "");

  function saveToken(next) {
    if (next) localStorage.setItem("ttm_token", next);
    else localStorage.removeItem("ttm_token");
    setToken(next);
  }

  async function request(path, options = {}) {
    const response = await fetch(`${API}${path}`, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...options.headers,
      },
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || "Request failed");
    return data;
  }

  return { token, saveToken, request };
}

function AuthScreen({ api, onAuthed }) {
  const [mode, setMode] = useState("login");
  const [form, setForm] = useState({ name: "", email: "", password: "" });
  const [error, setError] = useState("");

  async function submit(event) {
    event.preventDefault();
    setError("");
    try {
      const payload = mode === "signup" ? form : { email: form.email, password: form.password };
      const data = await api.request(`/auth/${mode}`, { method: "POST", body: JSON.stringify(payload) });
      api.saveToken(data.token);
      onAuthed(data.user);
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <main className="auth-shell">
      <section className="auth-panel">
        <div className="brand-mark"><FolderKanban size={28} /> Team Task Manager</div>
        <h1>Operational command center for project teams.</h1>
        <p>Authenticate, create a project, invite members by email, assign work, and track delivery from one dashboard.</p>
        <div className="auth-stats">
          <span>JWT sessions</span>
          <span>Postgres relationships</span>
          <span>Admin/Member access</span>
        </div>
      </section>
      <form className="auth-card" onSubmit={submit}>
        <div className="segmented">
          <button type="button" className={mode === "login" ? "active" : ""} onClick={() => setMode("login")}>Login</button>
          <button type="button" className={mode === "signup" ? "active" : ""} onClick={() => setMode("signup")}>Signup</button>
        </div>
        {mode === "signup" && (
          <label>Name<input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required /></label>
        )}
        <label>Email<input type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} required /></label>
        <label>Password<input type="password" minLength={8} value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} required /></label>
        {error && <p className="error">{error}</p>}
        <button className="primary" type="submit">{mode === "signup" ? "Create account" : "Enter workspace"}</button>
      </form>
    </main>
  );
}

function App() {
  const api = useApi();
  const [user, setUser] = useState(null);
  const [projects, setProjects] = useState([]);
  const [activeId, setActiveId] = useState(null);
  const [projectDetail, setProjectDetail] = useState(null);
  const [tasks, setTasks] = useState([]);
  const [dashboard, setDashboard] = useState(null);
  const [toast, setToast] = useState("");

  async function loadAll(nextActive = activeId) {
    const [projectData, dashData] = await Promise.all([api.request("/projects"), api.request("/dashboard")]);
    setProjects(projectData.projects);
    setDashboard(dashData);
    const targetId = nextActive || projectData.projects[0]?.id || null;
    setActiveId(targetId);
    if (targetId) await loadProject(targetId);
    else {
      setProjectDetail(null);
      setTasks([]);
    }
  }

  async function loadProject(projectId) {
    const [detail, taskData] = await Promise.all([
      api.request(`/projects/${projectId}`),
      api.request(`/projects/${projectId}/tasks`),
    ]);
    setProjectDetail(detail);
    setTasks(taskData.tasks);
  }

  useEffect(() => {
    if (!api.token) return;
    api.request("/me")
      .then((data) => {
        setUser(data.user);
        return loadAll();
      })
      .catch(() => api.saveToken(""));
  }, [api.token]);

  if (!api.token || !user) return <AuthScreen api={api} onAuthed={setUser} />;

  const role = projectDetail?.project?.role;
  const isAdmin = role === "Admin";

  async function createProject(event) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const data = await api.request("/projects", {
      method: "POST",
      body: JSON.stringify({ name: form.get("name"), description: form.get("description") }),
    });
    event.currentTarget.reset();
    await loadAll(data.project.id);
  }

  async function addMember(event) {
    event.preventDefault();
    const email = new FormData(event.currentTarget).get("email");
    await api.request(`/projects/${activeId}/members`, { method: "POST", body: JSON.stringify({ email }) });
    event.currentTarget.reset();
    await loadProject(activeId);
    setToast("Member added");
  }

  async function createTask(event) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const assignedTo = Number(form.get("assignedTo"));
    await api.request(`/projects/${activeId}/tasks`, {
      method: "POST",
      body: JSON.stringify({
        title: form.get("title"),
        description: form.get("description"),
        dueDate: form.get("dueDate") || null,
        priority: form.get("priority"),
        assignedTo: assignedTo || null,
      }),
    });
    event.currentTarget.reset();
    await Promise.all([loadProject(activeId), loadAll(activeId)]);
  }

  async function updateStatus(task, status) {
    await api.request(`/projects/${activeId}/tasks/${task.id}`, {
      method: "PATCH",
      body: JSON.stringify({ status }),
    });
    await Promise.all([loadProject(activeId), loadAll(activeId)]);
  }

  async function removeMember(id) {
    await api.request(`/projects/${activeId}/members/${id}`, { method: "DELETE" });
    await loadProject(activeId);
  }

  async function removeTask(id) {
    await api.request(`/projects/${activeId}/tasks/${id}`, { method: "DELETE" });
    await Promise.all([loadProject(activeId), loadAll(activeId)]);
  }

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand-mark"><FolderKanban size={22} /> TTM</div>
        <div className="user-box">
          <strong>{user.name}</strong>
          <span>{user.email}</span>
        </div>
        <form className="mini-form" onSubmit={createProject}>
          <input name="name" placeholder="New project name" required />
          <textarea name="description" placeholder="Project brief" rows="3" />
          <button className="primary" type="submit"><Plus size={16} /> Create project</button>
        </form>
        <nav className="project-list">
          {projects.map((project) => (
            <button key={project.id} className={project.id === activeId ? "active" : ""} onClick={() => { setActiveId(project.id); loadProject(project.id); }}>
              <span>{project.name}</span>
              <small>{project.role} · {project.done_count}/{project.task_count} done</small>
            </button>
          ))}
        </nav>
        <button className="ghost logout" onClick={() => { api.saveToken(""); setUser(null); }}><LogOut size={16} /> Logout</button>
      </aside>

      <section className="workspace">
        <Dashboard dashboard={dashboard} />

        {!projectDetail ? (
          <section className="empty-state">
            <ClipboardList size={42} />
            <h2>Create a project to start assigning work.</h2>
          </section>
        ) : (
          <>
            <header className="project-header">
              <div>
                <span className="eyebrow">{role} workspace</span>
                <h1>{projectDetail.project.name}</h1>
                <p>{projectDetail.project.description || "No project description yet."}</p>
              </div>
              <span className={`role-chip ${isAdmin ? "admin" : ""}`}><Shield size={15} /> {role}</span>
            </header>

            <section className="split-layout">
              <div className="task-board">
                {statuses.map((status) => (
                  <TaskColumn
                    key={status}
                    status={status}
                    tasks={tasks.filter((task) => task.status === status)}
                    onStatus={updateStatus}
                    onDelete={isAdmin ? removeTask : null}
                  />
                ))}
              </div>

              <aside className="control-rail">
                {isAdmin && (
                  <>
                    <Panel title="Create Task" icon={<Plus size={18} />}>
                      <form className="stack-form" onSubmit={createTask}>
                        <input name="title" placeholder="Task title" required />
                        <textarea name="description" placeholder="Description" rows="3" />
                        <input name="dueDate" type="date" />
                        <select name="priority" defaultValue="Medium">{priorities.map((item) => <option key={item}>{item}</option>)}</select>
                        <select name="assignedTo" defaultValue="">
                          <option value="">Unassigned</option>
                          {projectDetail.members.map((member) => <option value={member.id} key={member.id}>{member.name}</option>)}
                        </select>
                        <button className="primary" type="submit">Add task</button>
                      </form>
                    </Panel>
                    <Panel title="Add Member" icon={<UserPlus size={18} />}>
                      <form className="inline-form" onSubmit={addMember}>
                        <input name="email" type="email" placeholder="member@email.com" required />
                        <button className="icon-button" type="submit" aria-label="Add member"><Plus size={18} /></button>
                      </form>
                    </Panel>
                  </>
                )}
                <Panel title="Team" icon={<Users size={18} />}>
                  <div className="member-list">
                    {projectDetail.members.map((member) => (
                      <div className="member" key={member.id}>
                        <span>{member.name}<small>{member.email}</small></span>
                        <strong>{member.role}</strong>
                        {isAdmin && member.id !== user.id && (
                          <button className="icon-button danger" onClick={() => removeMember(member.id)} aria-label="Remove member"><Trash2 size={15} /></button>
                        )}
                      </div>
                    ))}
                  </div>
                </Panel>
              </aside>
            </section>
          </>
        )}
        {toast && <button className="toast" onAnimationEnd={() => setToast("")}>{toast}</button>}
      </section>
    </main>
  );
}

function Dashboard({ dashboard }) {
  const summary = dashboard?.summary || {};
  const cards = [
    ["Total tasks", summary.total_tasks || 0, <ClipboardList size={18} />],
    ["In progress", summary.in_progress || 0, <FolderKanban size={18} />],
    ["Done", summary.done || 0, <CheckCircle2 size={18} />],
    ["Overdue", summary.overdue || 0, <AlertTriangle size={18} />],
  ];
  return (
    <section className="dashboard-strip">
      {cards.map(([label, value, icon]) => (
        <article className="metric" key={label}>
          {icon}<span>{label}</span><strong>{value}</strong>
        </article>
      ))}
      <article className="metric wide">
        <Users size={18} /><span>Tasks per user</span>
        <div className="user-bars">
          {(dashboard?.perUser || []).map((item) => <i key={item.name} style={{ "--w": `${Math.max(8, item.count * 16)}px` }}>{item.name}: {item.count}</i>)}
        </div>
      </article>
    </section>
  );
}

function TaskColumn({ status, tasks, onStatus, onDelete }) {
  return (
    <section className="column">
      <header><h2>{status}</h2><span>{tasks.length}</span></header>
      <div className="task-stack">
        {tasks.map((task) => <TaskCard key={task.id} task={task} onStatus={onStatus} onDelete={onDelete} />)}
      </div>
    </section>
  );
}

function TaskCard({ task, onStatus, onDelete }) {
  const overdue = task.due_date && new Date(task.due_date) < new Date() && task.status !== "Done";
  const formattedDate = useMemo(() => (task.due_date ? new Date(task.due_date).toLocaleDateString() : "No due date"), [task.due_date]);
  return (
    <article className={`task-card priority-${task.priority.toLowerCase()} ${overdue ? "overdue" : ""}`}>
      <div className="task-top">
        <strong>{task.title}</strong>
        {onDelete && <button className="icon-button danger" onClick={() => onDelete(task.id)} aria-label="Delete task"><Trash2 size={15} /></button>}
      </div>
      <p>{task.description || "No description"}</p>
      <div className="task-meta">
        <span>{task.priority}</span>
        <span>{formattedDate}</span>
        <span>{task.assignee_name || "Unassigned"}</span>
      </div>
      <select value={task.status} onChange={(event) => onStatus(task, event.target.value)}>
        {statuses.map((status) => <option key={status}>{status}</option>)}
      </select>
    </article>
  );
}

function Panel({ title, icon, children }) {
  return (
    <section className="panel">
      <h2>{icon}{title}</h2>
      {children}
    </section>
  );
}

createRoot(document.getElementById("root")).render(<App />);
