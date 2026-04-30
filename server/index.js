import "dotenv/config";
import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { initDb, query } from "./db.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const port = process.env.PORT || 8080;
const jwtSecret = process.env.JWT_SECRET || "development-secret-change-me";

app.use(cors());
app.use(express.json());

const signupSchema = z.object({
  name: z.string().trim().min(2).max(80),
  email: z.string().trim().email().max(160).transform((value) => value.toLowerCase()),
  password: z.string().min(8).max(100),
});

const loginSchema = z.object({
  email: z.string().trim().email().transform((value) => value.toLowerCase()),
  password: z.string().min(1),
});

const projectSchema = z.object({
  name: z.string().trim().min(2).max(100),
  description: z.string().trim().max(600).optional().default(""),
});

const taskSchema = z.object({
  title: z.string().trim().min(2).max(140),
  description: z.string().trim().max(1000).optional().default(""),
  dueDate: z.string().regex(/^\d{4}-\d{2}-\d{2}$/).optional().nullable(),
  priority: z.enum(["Low", "Medium", "High"]),
  status: z.enum(["To Do", "In Progress", "Done"]).optional().default("To Do"),
  assignedTo: z.number().int().positive().optional().nullable(),
});

function tokenFor(user) {
  return jwt.sign({ id: user.id, email: user.email }, jwtSecret, { expiresIn: "7d" });
}

function sendAuth(res, user) {
  res.json({
    token: tokenFor(user),
    user: { id: user.id, name: user.name, email: user.email },
  });
}

function validate(schema) {
  return (req, res, next) => {
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: parsed.error.issues[0]?.message || "Invalid request" });
    }
    req.body = parsed.data;
    next();
  };
}

async function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: "Authentication required" });
    const payload = jwt.verify(token, jwtSecret);
    const { rows } = await query("SELECT id, name, email FROM users WHERE id = $1", [payload.id]);
    if (!rows[0]) return res.status(401).json({ error: "Invalid session" });
    req.user = rows[0];
    next();
  } catch {
    res.status(401).json({ error: "Invalid session" });
  }
}

async function membership(projectId, userId) {
  const { rows } = await query(
    "SELECT role FROM project_members WHERE project_id = $1 AND user_id = $2",
    [projectId, userId],
  );
  return rows[0] || null;
}

async function requireMember(req, res, next) {
  const projectId = Number(req.params.projectId || req.params.id);
  if (!Number.isInteger(projectId)) return res.status(400).json({ error: "Invalid project id" });
  const member = await membership(projectId, req.user.id);
  if (!member) return res.status(403).json({ error: "Project access denied" });
  req.projectId = projectId;
  req.memberRole = member.role;
  next();
}

async function requireAdmin(req, res, next) {
  if (req.memberRole !== "Admin") return res.status(403).json({ error: "Admin access required" });
  next();
}

app.get("/api/health", (_req, res) => res.json({ ok: true }));

app.post("/api/auth/signup", validate(signupSchema), async (req, res) => {
  try {
    const hash = await bcrypt.hash(req.body.password, 12);
    const { rows } = await query(
      "INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id, name, email",
      [req.body.name, req.body.email, hash],
    );
    sendAuth(res.status(201), rows[0]);
  } catch (error) {
    if (error.code === "23505") return res.status(409).json({ error: "Email is already registered" });
    res.status(500).json({ error: "Could not create account" });
  }
});

app.post("/api/auth/login", validate(loginSchema), async (req, res) => {
  const { rows } = await query("SELECT * FROM users WHERE email = $1", [req.body.email]);
  const user = rows[0];
  if (!user || !(await bcrypt.compare(req.body.password, user.password_hash))) {
    return res.status(401).json({ error: "Invalid email or password" });
  }
  sendAuth(res, user);
});

app.get("/api/me", requireAuth, (req, res) => res.json({ user: req.user }));

app.get("/api/projects", requireAuth, async (req, res) => {
  const { rows } = await query(
    `SELECT p.*, pm.role,
      COUNT(DISTINCT t.id)::INT AS task_count,
      COUNT(DISTINCT CASE WHEN t.status = 'Done' THEN t.id END)::INT AS done_count
     FROM projects p
     JOIN project_members pm ON pm.project_id = p.id
     LEFT JOIN tasks t ON t.project_id = p.id
     WHERE pm.user_id = $1
     GROUP BY p.id, pm.role
     ORDER BY p.created_at DESC`,
    [req.user.id],
  );
  res.json({ projects: rows });
});

app.post("/api/projects", requireAuth, validate(projectSchema), async (req, res) => {
  const client = await query("INSERT INTO projects (name, description, created_by) VALUES ($1, $2, $3) RETURNING *", [
    req.body.name,
    req.body.description,
    req.user.id,
  ]);
  const project = client.rows[0];
  await query("INSERT INTO project_members (project_id, user_id, role) VALUES ($1, $2, 'Admin')", [project.id, req.user.id]);
  res.status(201).json({ project: { ...project, role: "Admin" } });
});

app.get("/api/projects/:id", requireAuth, requireMember, async (req, res) => {
  const projectRows = await query("SELECT * FROM projects WHERE id = $1", [req.projectId]);
  const members = await query(
    `SELECT u.id, u.name, u.email, pm.role
     FROM project_members pm JOIN users u ON u.id = pm.user_id
     WHERE pm.project_id = $1 ORDER BY pm.role, u.name`,
    [req.projectId],
  );
  res.json({ project: { ...projectRows.rows[0], role: req.memberRole }, members: members.rows });
});

app.post("/api/projects/:id/members", requireAuth, requireMember, requireAdmin, async (req, res) => {
  const parsed = z.object({ email: z.string().email().transform((value) => value.toLowerCase()) }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Valid email is required" });
  const user = await query("SELECT id FROM users WHERE email = $1", [parsed.data.email]);
  if (!user.rows[0]) return res.status(404).json({ error: "No user found with that email" });
  await query(
    `INSERT INTO project_members (project_id, user_id, role)
     VALUES ($1, $2, 'Member')
     ON CONFLICT (project_id, user_id) DO NOTHING`,
    [req.projectId, user.rows[0].id],
  );
  res.status(201).json({ ok: true });
});

app.delete("/api/projects/:id/members/:userId", requireAuth, requireMember, requireAdmin, async (req, res) => {
  const userId = Number(req.params.userId);
  if (userId === req.user.id) return res.status(400).json({ error: "Admins cannot remove themselves" });
  await query("DELETE FROM project_members WHERE project_id = $1 AND user_id = $2", [req.projectId, userId]);
  res.json({ ok: true });
});

app.get("/api/projects/:id/tasks", requireAuth, requireMember, async (req, res) => {
  const memberFilter = req.memberRole === "Admin" ? "" : "AND (t.assigned_to = $2 OR t.created_by = $2)";
  const params = req.memberRole === "Admin" ? [req.projectId] : [req.projectId, req.user.id];
  const { rows } = await query(
    `SELECT t.*, u.name AS assignee_name, c.name AS creator_name
     FROM tasks t
     LEFT JOIN users u ON u.id = t.assigned_to
     JOIN users c ON c.id = t.created_by
     WHERE t.project_id = $1 ${memberFilter}
     ORDER BY
      CASE t.status WHEN 'To Do' THEN 1 WHEN 'In Progress' THEN 2 ELSE 3 END,
      t.due_date NULLS LAST,
      t.created_at DESC`,
    params,
  );
  res.json({ tasks: rows });
});

app.post("/api/projects/:id/tasks", requireAuth, requireMember, requireAdmin, validate(taskSchema), async (req, res) => {
  if (req.body.assignedTo) {
    const assignee = await membership(req.projectId, req.body.assignedTo);
    if (!assignee) return res.status(400).json({ error: "Assignee must be a project member" });
  }
  const { rows } = await query(
    `INSERT INTO tasks (project_id, title, description, due_date, priority, status, assigned_to, created_by)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
    [
      req.projectId,
      req.body.title,
      req.body.description,
      req.body.dueDate || null,
      req.body.priority,
      req.body.status,
      req.body.assignedTo || null,
      req.user.id,
    ],
  );
  res.status(201).json({ task: rows[0] });
});

app.patch("/api/projects/:id/tasks/:taskId", requireAuth, requireMember, async (req, res) => {
  const taskId = Number(req.params.taskId);
  const current = await query("SELECT * FROM tasks WHERE id = $1 AND project_id = $2", [taskId, req.projectId]);
  const task = current.rows[0];
  if (!task) return res.status(404).json({ error: "Task not found" });
  const isAssignedMember = task.assigned_to === req.user.id && req.memberRole === "Member";
  if (req.memberRole !== "Admin" && !isAssignedMember) return res.status(403).json({ error: "Task access denied" });

  const patchSchema = req.memberRole === "Admin" ? taskSchema.partial() : z.object({ status: z.enum(["To Do", "In Progress", "Done"]) });
  const parsed = patchSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0]?.message || "Invalid task update" });

  const next = { ...task, ...parsed.data };
  if (parsed.data.assignedTo !== undefined) {
    next.assigned_to = parsed.data.assignedTo;
  }
  if (next.assigned_to) {
    const assignee = await membership(req.projectId, Number(next.assigned_to));
    if (!assignee) return res.status(400).json({ error: "Assignee must be a project member" });
  }
  const { rows } = await query(
    `UPDATE tasks SET title = $1, description = $2, due_date = $3, priority = $4, status = $5,
      assigned_to = $6, updated_at = NOW()
     WHERE id = $7 AND project_id = $8 RETURNING *`,
    [
      next.title,
      next.description,
      parsed.data.dueDate !== undefined ? parsed.data.dueDate : next.due_date,
      next.priority,
      next.status,
      next.assigned_to || null,
      taskId,
      req.projectId,
    ],
  );
  res.json({ task: rows[0] });
});

app.delete("/api/projects/:id/tasks/:taskId", requireAuth, requireMember, requireAdmin, async (req, res) => {
  await query("DELETE FROM tasks WHERE id = $1 AND project_id = $2", [Number(req.params.taskId), req.projectId]);
  res.json({ ok: true });
});

app.get("/api/dashboard", requireAuth, async (req, res) => {
  const { rows } = await query(
    `SELECT
      COUNT(t.id)::INT AS total_tasks,
      COUNT(CASE WHEN t.status = 'To Do' THEN 1 END)::INT AS todo,
      COUNT(CASE WHEN t.status = 'In Progress' THEN 1 END)::INT AS in_progress,
      COUNT(CASE WHEN t.status = 'Done' THEN 1 END)::INT AS done,
      COUNT(CASE WHEN t.due_date < CURRENT_DATE AND t.status <> 'Done' THEN 1 END)::INT AS overdue
     FROM tasks t
     JOIN project_members pm ON pm.project_id = t.project_id
     WHERE pm.user_id = $1 AND (pm.role = 'Admin' OR t.assigned_to = $1 OR t.created_by = $1)`,
    [req.user.id],
  );
  const perUser = await query(
    `SELECT COALESCE(u.name, 'Unassigned') AS name, COUNT(t.id)::INT AS count
     FROM tasks t
     JOIN project_members pm ON pm.project_id = t.project_id
     LEFT JOIN users u ON u.id = t.assigned_to
     WHERE pm.user_id = $1 AND (pm.role = 'Admin' OR t.assigned_to = $1 OR t.created_by = $1)
     GROUP BY u.name ORDER BY count DESC, name LIMIT 8`,
    [req.user.id],
  );
  res.json({ summary: rows[0], perUser: perUser.rows });
});

const distPath = path.resolve(__dirname, "../dist");
app.use(express.static(distPath));
app.get("/{*splat}", (_req, res) => res.sendFile(path.join(distPath, "index.html")));

initDb()
  .then(() => {
    app.listen(port, () => console.log(`Team Task Manager listening on ${port}`));
  })
  .catch((error) => {
    console.error("Failed to initialize database", error);
    process.exit(1);
  });
