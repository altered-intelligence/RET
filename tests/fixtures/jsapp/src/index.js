const fastify = require('fastify');
const axios = require('axios');
const secret = 'gcp-token-artifact-77';
module.exports = { secret };
async function start() { const app = fastify(); app.get('/ping', () => 'pong'); return app; }
module.exports.start = start;
