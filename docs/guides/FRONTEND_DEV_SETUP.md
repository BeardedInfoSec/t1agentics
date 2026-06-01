# Frontend Development Setup

Switch from Docker frontend to npm development server for live reloading.

---

## Quick Setup

```bash
# 1. Stop Docker frontend
docker-compose stop frontend

# 2. Start npm dev server
cd frontend
npm install # First time only
npm start

# Opens http://localhost:3000 with live reload
# Backend still runs in Docker at http://localhost:8000
```

---

## Detailed Steps

### 1. Stop Docker Frontend Container

```bash
# Stop only frontend (keep backend, database running)
docker-compose stop frontend

# Verify it's stopped
docker-compose ps | grep frontend
# Should show "Exit" status
```

### 2. Install Frontend Dependencies

```bash
cd frontend

# Install (if not already done)
npm install

# Should complete without errors
```

### 3. Configure API URL

Frontend needs to know where backend is:

**Option A: Environment Variable**
```bash
# Set backend URL
export REACT_APP_API_URL=http://localhost:8000

# Start dev server
npm start
```

**Option B: .env File** (Recommended)
```bash
# Create .env file in frontend/
cat > .env << EOF
REACT_APP_API_URL=http://localhost:8000
PORT=3000
EOF

# Start dev server
npm start
```

### 4. Start Development Server

```bash
npm start

# Should output:
# Compiled successfully!
#
# You can now view t1agentics in the browser.
#
# Local: http://localhost:3000
# On Your Network: http://192.168.x.x:3000
```

---

## Backend Configuration

Backend needs to allow CORS from npm dev server:

### Check docker-compose.yml

```yaml
backend:
 environment:
 # Should include localhost:3000
- ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8000
```

### If CORS errors occur:

```bash
# Edit docker-compose.yml
nano docker-compose.yml

# Add to backend environment:
- ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8000

# Restart backend
docker-compose restart backend
```

---

## Verify Setup

### 1. Check Backend is Running

```bash
curl http://localhost:8000/api/v1/health
# Should return: {"status":"ok"}
```

### 2. Check Frontend Dev Server

```bash
curl http://localhost:3000
# Should return HTML
```

### 3. Open Browser

```bash
# Open http://localhost:3000
# Login: admin/admin123
```

### 4. Check Browser Console

Press F12 → Console tab
- Should see no CORS errors
- Should see successful API calls

---

## Development Workflow

### Making Changes

```bash
# 1. Edit frontend files
nano frontend/src/components/Dashboard.js

# 2. Save - auto-reloads in browser
# 3. Check browser for changes
```

### Backend Changes

```bash
# Backend still runs in Docker
# Need to restart to see changes

docker-compose restart backend
```

### Full Restart

```bash
# Stop everything
docker-compose down

# Start backend only
docker-compose up -d postgres opensearch backend

# Start frontend npm
cd frontend && npm start
```

---

## Troubleshooting

### CORS Error

**Symptom:**
```
Access to fetch at 'http://localhost:8000/api/v1/...'
has been blocked by CORS policy
```

**Fix:**
```bash
# Add localhost:3000 to ALLOWED_ORIGINS in docker-compose.yml
docker-compose restart backend
```

### Port 3000 Already in Use

**Symptom:**
```
Something is already running on port 3000
```

**Fix:**
```bash
# Kill existing process
lsof -ti:3000 | xargs kill -9

# Or use different port
PORT=3001 npm start
```

### Backend Not Responding

**Symptom:**
```
Failed to fetch
Network request failed
```

**Fix:**
```bash
# Check backend is running
docker-compose ps backend

# Check backend health
curl http://localhost:8000/api/v1/health

# Check backend logs
docker-compose logs backend --tail 50
```

### npm install Fails

**Symptom:**
```
npm ERR! code ERESOLVE
```

**Fix:**
```bash
# Clear cache
npm cache clean --force

# Install with legacy peer deps
npm install --legacy-peer-deps

# Or force
npm install --force
```

---

## Production Build (Testing)

To test production build locally:

```bash
cd frontend

# Build
npm run build

# Serve with simple server
npx serve -s build -l 3000

# Open http://localhost:3000
```

---

## Switch Back to Docker

When done developing:

```bash
# Stop npm dev server
# Press Ctrl+C in terminal

# Start Docker frontend
docker-compose up -d frontend

# Verify
docker-compose ps | grep frontend
# Should show "Up" status
```

---

## Environment Variables

Frontend can use these variables:

```bash
# .env file in frontend/
REACT_APP_API_URL=http://localhost:8000
PORT=3000
BROWSER=none # Don't auto-open browser
FAST_REFRESH=true # Enable fast refresh
```

---

## Hot Reload Not Working?

```bash
# Check watchman (Mac/Linux)
brew install watchman # Mac
sudo apt install watchman # Ubuntu

# Or disable fast refresh
echo "FAST_REFRESH=false" >> .env
npm start
```

---

## Summary

**Development Mode:**
- Frontend: `npm start` (port 3000, live reload)
- Backend: Docker (port 8000)
- Database: Docker (port 5432)

**Benefits:**
- Instant live reload
- Better error messages
- Source maps for debugging
- React DevTools work

**Trade-offs:**
- Need to keep terminal open
- CORS configuration needed
- Separate process to manage
