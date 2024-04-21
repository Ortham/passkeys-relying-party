import { createServer } from 'node:http';
import { PORT } from './lib/config.js';
import { requestListener } from './lib/server.js';

// eslint-disable-next-line @typescript-eslint/no-misused-promises
const server = createServer(requestListener);

server.listen(PORT);
console.log(`Listening on port ${PORT}`);
