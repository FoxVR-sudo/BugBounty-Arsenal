const handler = require('serve-handler');
const http = require('http');

const port = process.env.PORT || 3000;

const server = http.createServer((request, response) => {
  return handler(request, response, {
    public: 'build'
  });
});

server.listen(port, () => {
  console.log(`Frontend running on port ${port}`);
});
