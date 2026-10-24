// Every request goes to the one Durable Object that is this server: WebSockets (it's the
// relay devices reach it on), its page, its NIP-11 document.
import './wasm.ts';
export { CosignHost } from './host.ts';

export default {
  async fetch(req: Request, env: any): Promise<Response> {
    return env.HOST.get(env.HOST.idFromName('host')).fetch(req);
  },
};
