const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
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
    customProps: (req) => ({ requestId: req.requestId, service: 'service_orders' })
}));

// Helpers: response format
function ok(res, data) { return res.json({ success: true, data }); }
function created(res, data) { return res.status(201).json({ success: true, data }); }
function fail(res, code, message, http = 400) { return res.status(http).json({ success: false, error: { code, message } }); }

// Auth guard
function authGuard(req, res, next) {
    const open = [
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
app.use('/v1', authGuard);

// In-memory orders
const ordersById = new Map();

// Domain events (placeholder for broker)
function publishEvent(eventType, payload) {
    logger.info({ eventType, payload, requestId: payload.requestId }, 'Domain event');
}

// Validation
const orderItemSchema = z.object({
    sku: z.string().min(1),
    name: z.string().min(1),
    quantity: z.number().int().positive(),
    price: z.number().nonnegative()
});
const createOrderSchema = z.object({
    items: z.array(orderItemSchema).nonempty(),
    totalAmount: z.number().nonnegative()
});
const updateStatusSchema = z.object({
    status: z.enum(['created', 'in_progress', 'completed', 'cancelled'])
});

// Permissions
function isAdminOrManager(user) {
    const roles = user.roles || [];
    return roles.includes('admin') || roles.includes('manager');
}

// Routes
app.post('/v1/orders', (req, res) => {
    const parse = createOrderSchema.safeParse(req.body);
    if (!parse.success) return fail(res, 'VALIDATION_ERROR', parse.error.errors.map(e => e.message).join('; '), 400);

    const now = new Date().toISOString();
    const id = uuidv4();
    const order = {
        id,
        userId: req.user.sub,
        items: parse.data.items,
        status: 'created',
        totalAmount: parse.data.totalAmount,
        createdAt: now,
        updatedAt: now
    };
    ordersById.set(id, order);
    publishEvent('order.created', { orderId: id, userId: req.user.sub, requestId: req.requestId });
    return created(res, order);
});

app.get('/v1/orders/:orderId', (req, res) => {
    const order = ordersById.get(req.params.orderId);
    if (!order) return fail(res, 'NOT_FOUND', 'Order not found', 404);
    if (order.userId !== req.user.sub && !isAdminOrManager(req.user)) {
        return fail(res, 'FORBIDDEN', 'Access denied', 403);
    }
    return ok(res, order);
});

app.get('/v1/orders', (req, res) => {
    // Only own orders unless admin/manager; support pagination and sort
    const page = parseInt(req.query.page || '1', 10);
    const pageSize = parseInt(req.query.pageSize || '10', 10);
    const sort = String(req.query.sort || 'createdAt:desc');
    let list = Array.from(ordersById.values());
    if (!isAdminOrManager(req.user)) {
        list = list.filter(o => o.userId === req.user.sub);
    }
    const [field, direction] = sort.split(':');
    list.sort((a, b) => {
        const av = a[field]; const bv = b[field];
        if (av === bv) return 0;
        return (av > bv ? 1 : -1) * (direction === 'desc' ? -1 : 1);
    });
    const total = list.length;
    const pages = Math.ceil(total / pageSize) || 1;
    const start = (page - 1) * pageSize;
    const items = list.slice(start, start + pageSize);
    return ok(res, { items, page, pageSize, total, pages });
});

app.put('/v1/orders/:orderId', (req, res) => {
    const order = ordersById.get(req.params.orderId);
    if (!order) return fail(res, 'NOT_FOUND', 'Order not found', 404);
    if (!isAdminOrManager(req.user)) {
        return fail(res, 'FORBIDDEN', 'Only manager/admin can update status', 403);
    }
    const parse = updateStatusSchema.safeParse(req.body);
    if (!parse.success) return fail(res, 'VALIDATION_ERROR', parse.error.errors.map(e => e.message).join('; '), 400);
    const nextStatus = parse.data.status;
    const allowedTransitions = {
        created: ['in_progress', 'cancelled'],
        in_progress: ['completed', 'cancelled'],
        completed: [],
        cancelled: []
    };
    if (!allowedTransitions[order.status].includes(nextStatus)) {
        return fail(res, 'INVALID_STATUS', `Cannot change status from ${order.status} to ${nextStatus}`, 400);
    }
    order.status = nextStatus;
    order.updatedAt = new Date().toISOString();
    ordersById.set(order.id, order);
    publishEvent('order.status_updated', { orderId: order.id, status: nextStatus, requestId: req.requestId });
    return ok(res, order);
});

app.post('/v1/orders/:orderId/cancel', (req, res) => {
    const order = ordersById.get(req.params.orderId);
    if (!order) return fail(res, 'NOT_FOUND', 'Order not found', 404);
    // Owner can cancel if not completed/cancelled; managers/admin too
    if (order.userId !== req.user.sub && !isAdminOrManager(req.user)) {
        return fail(res, 'FORBIDDEN', 'Access denied', 403);
    }
    if (['completed', 'cancelled'].includes(order.status)) {
        return fail(res, 'INVALID_STATUS', 'Order already finalized', 400);
    }
    order.status = 'cancelled';
    order.updatedAt = new Date().toISOString();
    ordersById.set(order.id, order);
    publishEvent('order.cancelled', { orderId: order.id, requestId: req.requestId });
    return ok(res, order);
});

// Health and status
app.get('/health', (req, res) => ok(res, { status: 'OK', service: 'Orders Service', env: NODE_ENV }));
app.get('/status', (req, res) => ok(res, { status: 'ok' }));

// Start server
app.listen(PORT, () => {
    logger.info({ port: PORT }, 'Orders service running');
});