# Team Task Manager

A full-stack collaborative task manager with authentication, project teams, role-based access, task assignment, status tracking, and dashboard metrics.

## Features

- Signup and login with JWT authentication
- Project creation with the creator assigned as `Admin`
- Admin member management by email
- Admin task creation, assignment, deletion, and updates
- Member access limited to assigned tasks, with status updates
- Dashboard for total tasks, status counts, overdue work, and tasks per user
- PostgreSQL schema with proper relationships between users, projects, members, and tasks

## Tech Stack

- Frontend: React, Vite, CSS
- Backend: Node.js, Express
- Database: PostgreSQL
- Auth: JWT, bcrypt password hashing
- Validation: Zod

## Local Setup

1. Install dependencies:

   ```bash
   npm install
   ```

2. Create `.env`:

   ```bash
   cp .env.example .env
   ```

3. Set `DATABASE_URL` and `JWT_SECRET` in `.env`.

4. Start the app in development:

   ```bash
   npm run dev
   ```

   Vite runs the frontend and the API runs on `PORT` from `.env`.

## Production

Build and start the single deployable service:

```bash
npm run build
npm start
```

The Express server serves the compiled frontend from `dist/` and exposes REST APIs under `/api`.

## Railway Deployment

1. Push this repository to GitHub.
2. Create a new Railway project from the GitHub repo.
3. Add a Railway PostgreSQL database.
4. Set environment variables on the app service:

   ```bash
   DATABASE_URL=${{Postgres.DATABASE_URL}}
   JWT_SECRET=<long-random-secret>
   NODE_ENV=production
   ```

5. Railway uses `railway.json` to run:

   ```bash
   npm install && npm run build
   npm start
   ```

6. Open the generated Railway domain and create the first account.

## API Overview

- `POST /api/auth/signup`
- `POST /api/auth/login`
- `GET /api/me`
- `GET /api/projects`
- `POST /api/projects`
- `GET /api/projects/:id`
- `POST /api/projects/:id/members`
- `DELETE /api/projects/:id/members/:userId`
- `GET /api/projects/:id/tasks`
- `POST /api/projects/:id/tasks`
- `PATCH /api/projects/:id/tasks/:taskId`
- `DELETE /api/projects/:id/tasks/:taskId`
- `GET /api/dashboard`
