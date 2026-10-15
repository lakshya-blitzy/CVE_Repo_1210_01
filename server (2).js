const _ = require('lodash');

/** HTTP request listener that responds to every request with the plain-text body "Hello, World!". */
require('http').createServer((req, res) => {
  res.end('Hello, World!\n');
}).listen(3000, () => console.log('Server running at http://127.0.0.1:3000/'));
