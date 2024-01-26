import { createServer } from 'node:http';
import { PORT } from './lib/config.js';
import { requestListener } from './lib/server.js';

const server = createServer(requestListener);

server.listen(PORT);
console.log(`Listening on port ${PORT}`);
