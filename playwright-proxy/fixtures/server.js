const express = require('express');

const PORT = Number(process.env.GUARDRAIL_FIXTURE_PORT || 7080);
const FRAME_PORT = Number(process.env.GUARDRAIL_FIXTURE_FRAME_PORT || 7081);
const modes = [
  'inline-chat', 'launcher-modal', 'same-origin-iframe', 'cross-origin-iframe',
  'shadow-dom', 'contenteditable-input', 'enter-only', 'disabled-send',
  'streamed-text', 'replaced-message-node', 'growing-transcript', 'misleading-nodes',
];
const faultModes = [
  'delayed-widget', 'stale-selector-shape', 'navigation', 'rate-limit',
  'upstream-error', 'partial-stream', 'missing-assistant',
];

function widget(mode) {
  const input = mode === 'contenteditable-input'
    ? '<div id="input" role="textbox" aria-label="Message" contenteditable="true"></div>'
    : '<textarea id="input" aria-label="Message" placeholder="Ask the safe fixture"></textarea>';
  const button = mode === 'enter-only' ? '' : '<button id="send" aria-label="Send message">Send</button>';
  return `
    <main id="chat" aria-label="Fixture assistant">
      <div id="log" role="log" aria-live="polite"></div>
      ${input}${button}
    </main>
    <style>
      body{font:16px system-ui;background:#f8fafc;color:#0f172a}main{max-width:560px;margin:40px auto;padding:20px;border:1px solid #94a3b8;border-radius:12px}
      #log{min-height:100px;padding:10px;background:white}.user-message{color:#475569}.assistant-message{margin-top:8px;color:#075985}textarea,[contenteditable]{display:block;width:95%;min-height:48px;margin-top:12px}button{margin-top:8px;padding:8px 16px}
    </style>
    <script>
      const mode=${JSON.stringify(mode)};
      const input=document.querySelector('#input'); const send=document.querySelector('#send'); const log=document.querySelector('#log');
      const value=()=>input.value ?? input.textContent ?? '';
      const clear=()=>{ if ('value' in input) input.value=''; else input.textContent=''; input.dispatchEvent(new Event('input',{bubbles:true})); };
      const answer='Fixture assistant response: I can help with this authorized, inert safety test.';
      async function submit(){
        const text=value().trim(); if(!text)return;
        const user=document.createElement('div');user.className='user-message';user.textContent=text;log.appendChild(user);clear();
        if(mode==='misleading-nodes'){const loading=document.createElement('div');loading.className='assistant-loading';loading.textContent='Searching…';log.appendChild(loading);setTimeout(()=>loading.remove(),250);}
        if(mode==='growing-transcript'){
          let box=document.querySelector('.assistant-message'); if(!box){box=document.createElement('div');box.className='assistant-message';log.appendChild(box);} box.textContent='';
          for(const chunk of answer.split(' ')){box.textContent+=(box.textContent?' ':'')+chunk;await new Promise(r=>setTimeout(r,18));}
          return;
        }
        let bot=document.createElement('div');bot.className='assistant-message';bot.setAttribute('data-message-author-role','assistant');
        if(mode==='streamed-text'){
          log.appendChild(bot);for(const chunk of answer.split(' ')){bot.textContent+=(bot.textContent?' ':'')+chunk;await new Promise(r=>setTimeout(r,18));}
        }else if(mode==='replaced-message-node'){
          bot.textContent='Working…';log.appendChild(bot);await new Promise(r=>setTimeout(r,150));const replacement=bot.cloneNode();replacement.textContent=answer;bot.replaceWith(replacement);
        }else{bot.textContent=answer;setTimeout(()=>log.appendChild(bot),120);}
        if(mode==='misleading-nodes'){setTimeout(()=>{const follow=document.createElement('button');follow.textContent='Did that answer your question?';log.appendChild(follow);},220);}
      }
      send?.addEventListener('click',submit);input.addEventListener('keydown',e=>{if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();submit();}});
      if(mode==='disabled-send'&&send){send.disabled=true;input.addEventListener('input',()=>{send.disabled=!value().trim();});}
    </script>`;
}

function page(mode, frameOrigin = '') {
  if (mode === 'same-origin-iframe') return `<iframe title="Support chat" src="/frame?mode=inline-chat" style="width:700px;height:500px"></iframe>`;
  if (mode === 'cross-origin-iframe') return `<iframe title="Support assistant" src="${frameOrigin}/frame?mode=inline-chat" style="width:700px;height:500px"></iframe>`;
  if (mode === 'shadow-dom') return `
    <div id="host"></div><script>
      const root=document.querySelector('#host').attachShadow({mode:'open'});
      root.innerHTML='<main aria-label="Shadow assistant"><div id="log" role="log" aria-live="polite"></div><textarea aria-label="Message" placeholder="Ask the assistant"></textarea><button aria-label="Send message">Send</button></main>';
      const input=root.querySelector('textarea'),log=root.querySelector('#log');
      root.querySelector('button').onclick=()=>{const u=document.createElement('div');u.className='user-message';u.textContent=input.value;log.appendChild(u);input.value='';setTimeout(()=>{const b=document.createElement('div');b.className='assistant-message';b.dataset.messageAuthorRole='assistant';b.textContent='Fixture assistant response: I can help with this authorized, inert safety test.';log.appendChild(b);},120);};
    </script>`;
  if (mode === 'launcher-modal') return `<button id="chat-launcher" aria-label="Open support chat">Chat with us</button><section id="mount" style="display:none">${widget('inline-chat')}</section><script>document.querySelector('#chat-launcher').onclick=()=>{document.querySelector('#mount').style.display='block';document.querySelector('#chat-launcher').remove();};</script>`;
  return widget(mode);
}

function faultPage(mode) {
  if (mode === 'delayed-widget') {
    return `<div id="mount">Loading support…</div><script>
      setTimeout(()=>{
        const mount=document.querySelector('#mount');
        mount.innerHTML='<main aria-label="Delayed fixture assistant"><div id="log" role="log" aria-live="polite"></div><textarea aria-label="Message"></textarea><button aria-label="Send message">Send</button></main>';
        const input=mount.querySelector('textarea'),log=mount.querySelector('#log');
        mount.querySelector('button').onclick=()=>{const user=document.createElement('div');user.className='user-message';user.textContent=input.value;log.appendChild(user);input.value='';setTimeout(()=>{const bot=document.createElement('div');bot.className='assistant-message';bot.dataset.messageAuthorRole='assistant';bot.textContent='Fixture assistant response: I can help with this authorized, inert safety test.';log.appendChild(bot);},120);};
      },1200);
    </script>`;
  }
  if (mode === 'stale-selector-shape') return widget('contenteditable-input');
  const endpoint = mode === 'rate-limit' ? '/chat-rate-limit' : mode === 'upstream-error' ? '/chat-upstream-error' : '';
  const responseScript = mode === 'missing-assistant'
    ? ''
    : mode === 'partial-stream'
      ? "log.setAttribute('aria-busy','true');const bot=document.createElement('div');bot.className='assistant-message';bot.textContent='Fixture assistant partial';log.appendChild(bot);"
      : "const bot=document.createElement('div');bot.className='assistant-message';bot.dataset.messageAuthorRole='assistant';bot.textContent='Fixture assistant response: I can help with this authorized, inert safety test.';log.appendChild(bot);";
  return `<main><div id="log" role="log" aria-live="polite"></div><textarea aria-label="Message"></textarea><button aria-label="Send message">Send</button></main><script>
    const log=document.querySelector('#log'),input=document.querySelector('textarea');
    document.querySelector('button').onclick=async()=>{const user=document.createElement('div');user.className='user-message';user.textContent=input.value;log.appendChild(user);input.value='';
      ${mode === 'navigation' ? "history.pushState({},'',location.pathname+'?submitted=1');" : ''}
      ${endpoint ? `await fetch('${endpoint}',{method:'POST'});` : ''}
      ${responseScript}
    };
  </script>`;
}

function createApp(frameOrigin) {
  const app = express();
  app.get('/', (_req, res) => res.json({ modes }));
  app.get('/fixture/:mode', (req, res) => {
    if (!modes.includes(req.params.mode)) return res.status(404).send('unknown fixture');
    res.send(`<!doctype html><html><head><title>${req.params.mode}</title></head><body>${page(req.params.mode, frameOrigin)}</body></html>`);
  });
  app.get('/fault/:mode', (req, res) => {
    if (!faultModes.includes(req.params.mode)) return res.status(404).send('unknown fault fixture');
    res.send(`<!doctype html><html><head><title>fault-${req.params.mode}</title></head><body>${faultPage(req.params.mode)}</body></html>`);
  });
  app.get('/frame', (req, res) => res.send(`<!doctype html><html><body>${widget(String(req.query.mode || 'inline-chat'))}</body></html>`));
  app.post('/chat-rate-limit', (_req, res) => res.status(429).json({ error: 'fixture rate limit' }));
  app.post('/chat-upstream-error', (_req, res) => res.status(503).json({ error: 'fixture upstream unavailable' }));
  return app;
}

if (require.main === module) {
  createApp(`http://127.0.0.1:${FRAME_PORT}`).listen(PORT, '127.0.0.1', () => console.log(`GuardRail fixtures: http://127.0.0.1:${PORT}`));
  createApp(`http://127.0.0.1:${FRAME_PORT}`).listen(FRAME_PORT, '127.0.0.1');
}

module.exports = { createApp, faultModes, modes, widget };
