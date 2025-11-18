const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const { z } = require('zod');
const pino = require('pino');
const pinoHttp = require('pino-http');

const app = express();
const PORT = process.env.PORT || 8000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';

// Logger
const logger = pino({
    level: process.env.LOG_LEVEL || 'info',
});

// Middleware
app.use(helmet());
app.use(cors({
    origin: CORS_ORIGIN === '*' ? true : CORS_ORIGIN.split(','),
    credentials: true
}));
app.use(express.json());
app.use((req, res, next) => {
    const id = req.header('X-Request-ID') || uuidv4();
    req.requestId = id;
    res.setHeader('X-Request-ID', id);
    next();
});
app.use(pinoHttp({
    logger,
    customProps: (req) => ({ requestId: req.requestId, service: 'service_users' })
}));

// In-memory storage
const usersById = new Map();
const usersByEmail = new Map();

// Helpers: response format
function ok(res, data) { return res.json({ success: true, data }); }
function created(res, data) { return res.status(201).json({ success: true, data }); }
function fail(res, code, message, http = 400) { return res.status(http).json({ success: false, error: { code, message } }); }

// Auth helpers
function signToken(user) {
    const payload = { sub: user.id, email: user.email, roles: user.roles || [] };
    return jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });
}
function authGuard(req, res, next) {
    const open = [
        '/v1/users/register',
        '/v1/users/login',
        '/health',
        '/status'
    ];
    if (open.includes(req.path)) return next();
    const authHeader = req.header('Authorization') || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
    if (!token) return fail(res, 'UNAUTHORIZED', 'Missing token', 401);
    try {
        const payload = jwt.verify(token, JWT_SECRET);
        req.user = payload;
        next();
    } catch (e) {
        return fail(res, 'UNAUTHORIZED', 'Invalid token', 401);
    }
}
function requireRole(role) {
    return (req, res, next) => {
        const roles = (req.user && req.user.roles) || [];
        if (!roles.includes(role)) return fail(res, 'FORBIDDEN', 'Insufficient permissions', 403);
        next();
    };
}

app.use('/v1', authGuard);

// Validation schemas
const registerSchema = z.object({
    email: z.string().email(),
    password: z.string().min(6),
    name: z.string().min(1),
});
const loginSchema = z.object({
    email: z.string().email(),
    password: z.string().min(6),
});
const profileUpdateSchema = z.object({
    name: z.string().min(1).optional(),
    roles: z.array(z.string()).optional()
});

// Routes
app.post('/v1/users/register', async (req, res) => {
    const parse = registerSchema.safeParse(req.body);
    if (!parse.success) return fail(res, 'VALIDATION_ERROR', parse.error.errors.map(e => e.message).join('; '), 400);
    const { email, password, name } = parse.data;
    if (usersByEmail.has(email)) return fail(res, 'USER_EXISTS', 'Email already registered', 409);

    const id = uuidv4();
    const now = new Date().toISOString();
    const passwordHash = await bcrypt.hash(password, 10);
    const user = {
        id,
        email,
        passwordHash,
        name,
        roles: ['user'],
        createdAt: now,
        updatedAt: now
    };
    usersById.set(id, user);
    usersByEmail.set(email, user);
    return created(res, { id });
});

app.post('/v1/users/login', async (req, res) => {
    const parse = loginSchema.safeParse(req.body);
    if (!parse.success) return fail(res, 'VALIDATION_ERROR', parse.error.errors.map(e => e.message).join('; '), 400);
    const { email, password } = parse.data;
    const user = usersByEmail.get(email);
    if (!user) return fail(res, 'INVALID_CREDENTIALS', 'Invalid email or password', 401);
    const okPwd = await bcrypt.compare(password, user.passwordHash);
    if (!okPwd) return fail(res, 'INVALID_CREDENTIALS', 'Invalid email or password', 401);
    const token = signToken(user);
    return ok(res, { token });
});

app.get('/v1/users/me', (req, res) => {
    const me = usersById.get(req.user.sub);
    if (!me) return fail(res, 'NOT_FOUND', 'User not found', 404);
    const { passwordHash, ...publicUser } = me;
    return ok(res, publicUser);
});

app.put('/v1/users/me', (req, res) => {
    const me = usersById.get(req.user.sub);
    if (!me) return fail(res, 'NOT_FOUND', 'User not found', 404);
    const parse = profileUpdateSchema.safeParse(req.body);
    if (!parse.success) return fail(res, 'VALIDATION_ERROR', parse.error.errors.map(e => e.message).join('; '), 400);
    const updates = parse.data;
    // Only admins can change roles
    if (updates.roles && !(req.user.roles || []).includes('admin')) {
        return fail(res, 'FORBIDDEN', 'Only admin can update roles', 403);
    }
    const updated = {
        ...me,
        ...('name' in updates ? { name: updates.name } : {}),
        ...('roles' in updates ? { roles: updates.roles } : {}),
        updatedAt: new Date().toISOString()
    };
    usersById.set(me.id, updated);
    usersByEmail.set(updated.email, updated);
    const { passwordHash, ...publicUser } = updated;
    return ok(res, publicUser);
});

// Admin list with pagination and filters
app.get('/v1/users', requireRole('admin'), (req, res) => {
    const page = parseInt(req.query.page || '1', 10);
    const pageSize = parseInt(req.query.pageSize || '10', 10);
    const role = req.query.role;
    const name = req.query.name;
    let list = Array.from(usersById.values());
    if (role) list = list.filter(u => (u.roles || []).includes(role));
    if (name) list = list.filter(u => u.name && u.name.toLowerCase().includes(String(name).toLowerCase()));
    const total = list.length;
    const pages = Math.ceil(total / pageSize) || 1;
    const start = (page - 1) * pageSize;
    const data = list.slice(start, start + pageSize).map(u => {
        const { passwordHash, ...pu } = u;
        return pu;
    });
    return ok(res, { items: data, page, pageSize, total, pages });
});

// Health and status
app.get('/health', (req, res) => ok(res, { status: 'OK', service: 'Users Service', env: NODE_ENV }));
app.get('/status', (req, res) => ok(res, { status: 'ok' }));

// Start server
app.listen(PORT, '0.0.0.0', () => {
    logger.info({ port: PORT }, 'Users service running');
});