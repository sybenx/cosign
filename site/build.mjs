import { build } from 'esbuild';
await build({ entryPoints: ['src/demo.ts'], outfile: 'public/app.js', bundle: true, format: 'esm', target: 'es2022', minify: true, sourcemap: true, logLevel: 'warning' });
console.log('built public/app.js');
