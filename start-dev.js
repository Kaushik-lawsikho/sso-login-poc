const { spawn } = require('child_process');
const path = require('path');

console.log('🚀 Starting SSO Development Environment...\n');

// Start backend
console.log('📡 Starting Backend Server...');
const backend = spawn('npm', ['run', 'dev'], {
  cwd: __dirname,
  stdio: 'inherit',
  shell: true
});

// Wait a bit for backend to start
setTimeout(() => {
  console.log('⚛️  Starting React Frontend...');
  const frontend = spawn('npm', ['start'], {
    cwd: path.join(__dirname, 'frontend'),
    stdio: 'inherit',
    shell: true
  });

  // Handle process termination
  process.on('SIGINT', () => {
    console.log('\n🛑 Shutting down servers...');
    backend.kill();
    frontend.kill();
    process.exit(0);
  });
}, 3000);

backend.on('error', (err) => {
  console.error('Backend error:', err);
});

backend.on('close', (code) => {
  console.log(`Backend process exited with code ${code}`);
});
