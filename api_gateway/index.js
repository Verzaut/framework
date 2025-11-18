const express = require('express');
const cors = require('cors');
const axios = require('axios');
const CircuitBreaker = require('opossum');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const pino = require('pino');
const pinoHttp = require('pino-http');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 8000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';
const RATE_LIMIT_WINDOW_MS = parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000', 10);
const RATE_LIMIT_MAX = parseInt(process.env.RATE_LIMIT_MAX || '100', 10);

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

// Request ID + logging
app.use((req, res, next) => {
    const incomingId = req.header('X-Request-ID');
    req.requestId = incomingId || uuidv4();
    res.setHeader('X-Request-ID', req.requestId);
    next();
});
app.use(pinoHttp({
    logger,
    customProps: (req) => ({ requestId: req.requestId, service: 'api_gateway' })
}));

// Rate limit
app.use(rateLimit({
    windowMs: RATE_LIMIT_WINDOW_MS,
    max: RATE_LIMIT_MAX,
    standardHeaders: true,
    legacyHeaders: false
}));

// Service URLs
const USERS_SERVICE_URL = process.env.USERS_SERVICE_URL || 'http://service_users:8000';
const ORDERS_SERVICE_URL = process.env.ORDERS_SERVICE_URL || 'http://service_orders:8000';

// Helper: standardized responses
function ok(res, data) {
    return res.json({ success: true, data });
}
function created(res, data) {
    return res.status(201).json({ success: true, data });
}
function fail(res, code, message, httpStatus = 400) {
    return res.status(httpStatus).json({ success: false, error: { code, message } });
}

// JWT guard
function authGuard(req, res, next) {
    const openPaths = [
        '/v1/users/register',
        '/v1/users/login',
        '/health',
        '/status'
    ];
    if (openPaths.includes(req.path)) return next();
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

// Attach auth guard for protected routes
app.use('/v1', authGuard);

// Axios helper to propagate headers
function forwardHeaders(req) {
    const headers = {
        'X-Request-ID': req.requestId,
    };
    if (req.header('Authorization')) headers['Authorization'] = req.header('Authorization');
    if (req.header('traceparent')) headers['traceparent'] = req.header('traceparent');
    if (req.header('tracestate')) headers['tracestate'] = req.header('tracestate');
    return headers;
}

// Circuit Breaker configuration
const circuitOptions = {
    timeout: 3000,
    errorThresholdPercentage: 50,
    resetTimeout: 30000,
};

// Create circuit breakers for each service
const usersCircuit = new CircuitBreaker(async (options) => {
    const response = await axios({ validateStatus: () => true, ...options });
    return response;
}, circuitOptions);
const ordersCircuit = new CircuitBreaker(async (options) => {
    const response = await axios({ validateStatus: () => true, ...options });
    return response;
}, circuitOptions);

usersCircuit.fallback(() => ({ status: 503, data: { success: false, error: { code: 'USERS_UNAVAILABLE', message: 'Users service temporarily unavailable' } } }));
ordersCircuit.fallback(() => ({ status: 503, data: { success: false, error: { code: 'ORDERS_UNAVAILABLE', message: 'Orders service temporarily unavailable' } } }));

// Users routes
app.post('/v1/users/register', async (req, res) => {
    const response = await usersCircuit.fire({
        url: `${USERS_SERVICE_URL}/v1/users/register`,
        method: 'POST',
        headers: forwardHeaders(req),
        data: req.body
    });
    return res.status(response.status).json(response.data);
});
app.post('/v1/users/login', async (req, res) => {
    const response = await usersCircuit.fire({
        url: `${USERS_SERVICE_URL}/v1/users/login`,
        method: 'POST',
        headers: forwardHeaders(req),
        data: req.body
    });
    return res.status(response.status).json(response.data);
});
app.get('/v1/users/me', async (req, res) => {
    const response = await usersCircuit.fire({
        url: `${USERS_SERVICE_URL}/v1/users/me`,
        method: 'GET',
        headers: forwardHeaders(req)
    });
    return res.status(response.status).json(response.data);
});
app.put('/v1/users/me', async (req, res) => {
    const response = await usersCircuit.fire({
        url: `${USERS_SERVICE_URL}/v1/users/me`,
        method: 'PUT',
        headers: forwardHeaders(req),
        data: req.body
    });
    return res.status(response.status).json(response.data);
});
app.get('/v1/users', async (req, res) => {
    const response = await usersCircuit.fire({
        url: `${USERS_SERVICE_URL}/v1/users`,
        method: 'GET',
        headers: forwardHeaders(req),
        params: req.query
    });
    return res.status(response.status).json(response.data);
});

// Orders routes
app.post('/v1/orders', async (req, res) => {
    const response = await ordersCircuit.fire({
        url: `${ORDERS_SERVICE_URL}/v1/orders`,
        method: 'POST',
        headers: forwardHeaders(req),
        data: req.body
    });
    return res.status(response.status).json(response.data);
});
app.get('/v1/orders', async (req, res) => {
    const response = await ordersCircuit.fire({
        url: `${ORDERS_SERVICE_URL}/v1/orders`,
        method: 'GET',
        headers: forwardHeaders(req),
        params: req.query
    });
    return res.status(response.status).json(response.data);
});
app.get('/v1/orders/:orderId', async (req, res) => {
    const response = await ordersCircuit.fire({
        url: `${ORDERS_SERVICE_URL}/v1/orders/${req.params.orderId}`,
        method: 'GET',
        headers: forwardHeaders(req)
    });
    return res.status(response.status).json(response.data);
});
app.put('/v1/orders/:orderId', async (req, res) => {
    const response = await ordersCircuit.fire({
        url: `${ORDERS_SERVICE_URL}/v1/orders/${req.params.orderId}`,
        method: 'PUT',
        headers: forwardHeaders(req),
        data: req.body
    });
    return res.status(response.status).json(response.data);
});
app.post('/v1/orders/:orderId/cancel', async (req, res) => {
    const response = await ordersCircuit.fire({
        url: `${ORDERS_SERVICE_URL}/v1/orders/${req.params.orderId}/cancel`,
        method: 'POST',
        headers: forwardHeaders(req)
    });
    return res.status(response.status).json(response.data);
});

// Health/status
app.get('/health', (req, res) => ok(res, {
    status: 'API Gateway is running',
    env: NODE_ENV
}));
app.get('/status', (req, res) => ok(res, { status: 'ok' }));

// Start server
app.listen(PORT, () => {
    logger.info({ port: PORT }, 'API Gateway running');
    usersCircuit.on('open', () => logger.warn('Users circuit breaker opened'));
    usersCircuit.on('close', () => logger.info('Users circuit breaker closed'));
    usersCircuit.on('halfOpen', () => logger.info('Users circuit breaker half-open'));
    ordersCircuit.on('open', () => logger.warn('Orders circuit breaker opened'));
    ordersCircuit.on('close', () => logger.info('Orders circuit breaker closed'));
    ordersCircuit.on('halfOpen', () => logger.info('Orders circuit breaker half-open'));
});