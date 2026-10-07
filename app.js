/* Sorpresa de cumpleaños · lógica de la página.
   Todo lo personal (nombres, carta, fotos) llega cifrado y solo se abre con la palabra clave. */
(() => {
  'use strict';

  const CFG = Object.assign({ supabaseUrl: '', supabaseKey: '' }, window.RN_CONFIG || {});
  const PREVIA = window.RN_PREVIA || null;           // versión de vista previa: contenido ya incluido
  const NUBE = !!(CFG.supabaseUrl && CFG.supabaseKey) && !PREVIA;
  const SIN_MARCOS = !!PREVIA;                        // la vista previa no puede incrustar otros sitios
  const MAX_VIDEO = 50 * 1024 * 1024;
  const MAX_FOTOS = 6;
  const ESPACIO_TOTAL = 1024 * 1024 * 1024;

  // ---------- utilidades ----------
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const ico = n => `<svg class="ico" viewBox="0 0 24 24" aria-hidden="true"><use href="#i-${n}"/></svg>`;
  const pieza = c => `<span class="pieza" aria-hidden="true">${c}︎</span>`;
  const norm = s => String(s || '').normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase().replace(/[^a-z0-9]/g, '');
  const azar = (n = 16) => [...crypto.getRandomValues(new Uint8Array(n))].map(b => b.toString(16).padStart(2, '0')).join('');
  const uuid = () => (crypto.randomUUID ? crypto.randomUUID() : azar(16).replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, '$1-$2-$3-$4-$5'));
  const plural = (n, uno, varios) => `${n} ${n === 1 ? uno : varios}`;
  const dos = n => String(n).padStart(2, '0');

  const memoria = {};
  const guarda = {
    get(k) { try { const v = localStorage.getItem('rn_' + k); return v ?? memoria[k] ?? null; } catch { return memoria[k] ?? null; } },
    set(k, v) { memoria[k] = v; try { localStorage.setItem('rn_' + k, v); } catch { /* sin almacenamiento */ } },
    del(k) { delete memoria[k]; try { localStorage.removeItem('rn_' + k); } catch { /* nada */ } },
    json(k, def) { try { return JSON.parse(this.get(k)) ?? def; } catch { return def; } }
  };

  function fecha(iso, conHora = false) {
    const d = new Date(iso);
    if (isNaN(d)) return '';
    const f = `${dos(d.getDate())}/${dos(d.getMonth() + 1)}/${d.getFullYear()}`;
    return conHora ? `${f} · ${dos(d.getHours())}:${dos(d.getMinutes())}` : f;
  }
  function fechaDia(aaaammdd) { const [a, m, d] = aaaammdd.split('-'); return `${d}/${m}/${a}`; }
  function diasPara(aaaammdd) {
    const [a, m, d] = aaaammdd.split('-').map(Number);
    const hoy = new Date(); hoy.setHours(0, 0, 0, 0);
    return Math.round((new Date(a, m - 1, d) - hoy) / 86400000);
  }
  function peso(b) { return b > 1048576 ? `${(b / 1048576).toFixed(1)} MB` : `${Math.max(1, Math.round(b / 1024))} KB`; }

  let tostadaT;
  function tostada(msg, ms = 3200) {
    const t = $('#tostada'); t.textContent = msg; t.hidden = false;
    clearTimeout(tostadaT); tostadaT = setTimeout(() => { t.hidden = true; }, ms);
  }

  // ---------- estado ----------
  let C = null;                 // contenido personal descifrado
  let llave = null;             // llave de contenido
  let clave = '';               // palabra clave normalizada
  let claveAdmin = guarda.get('admin') || '';
  let esAdmin = false;
  let rol = guarda.get('rol') || 'familia';   // 'familia' | 'homenajeado'
  let vistaPreviaEl = false;                  // la dueña mirando "como él"
  let posts = [];
  let huella = '';
  let vista = 'inicio';
  let filtro = 'todos';
  let temaAbierto = null;
  let pendientes = false;
  const borradores = {};        // textos a medio escribir
  const abiertos = new Set();   // tarjetas con la caja de respuesta abierta
  const dispositivo = guarda.get('disp') || (() => { const d = azar(12); guarda.set('disp', d); return d; })();
  const yo = { nombre: guarda.get('nombre') || '', relacion: guarda.get('relacion') || '' };
  const esEl = () => rol === 'homenajeado' || vistaPreviaEl;

  // ---------- cifrado del contenido ----------
  const b64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const aB64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));

  async function abrirLlave(texto) {
    const rL = await fetch('llave.json', { cache: 'no-cache' });
    if (!rL.ok) throw new Error('no_encontrado');
    const L = await rL.json();
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(norm(texto)), 'PBKDF2', false, ['deriveKey']);
    const envoltura = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt: b64(L.sal), iterations: L.iter, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    const cruda = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64(L.iv) }, envoltura, b64(L.ct));
    guarda.set('llave', aB64(cruda));
    return crypto.subtle.importKey('raw', cruda, 'AES-GCM', false, ['decrypt']);
  }
  async function descifrar(url, fresco) {
    const r = await fetch(url, fresco ? { cache: 'no-cache' } : undefined);
    if (!r.ok) throw new Error('no_encontrado');
    const buf = new Uint8Array(await r.arrayBuffer());
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv: buf.slice(0, 12) }, llave, buf.slice(12));
  }
  const cacheMedios = {};
  function medio(nombre) {
    if (PREVIA) return Promise.resolve(PREVIA.medios[nombre] || '');
    if (!cacheMedios[nombre]) {
      const m = C.medios[nombre];
      cacheMedios[nombre] = !m ? Promise.resolve('') : descifrar(m.archivo).then(b => URL.createObjectURL(new Blob([b], { type: m.tipo })));
    }
    return cacheMedios[nombre];
  }
  function hidratar(raiz) {
    $$('[data-medio]', raiz).forEach(el => {
      const n = el.dataset.medio; el.removeAttribute('data-medio');
      medio(n).then(u => { if (u) el.src = u; }).catch(() => { });
    });
    $$('[data-cartel]', raiz).forEach(el => {
      const n = el.dataset.cartel; el.removeAttribute('data-cartel');
      medio(n).then(u => { if (u) el.poster = u; }).catch(() => { });
    });
  }

  // ---------- datos: nube (Supabase) o modo de prueba ----------
  async function rpc(fn, args) {
    const r = await fetch(`${CFG.supabaseUrl}/rest/v1/rpc/${fn}`, {
      method: 'POST',
      headers: { apikey: CFG.supabaseKey, Authorization: `Bearer ${CFG.supabaseKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(args)
    });
    const j = await r.json().catch(() => null);
    if (!r.ok) throw Object.assign(new Error((j && j.message) || 'error_de_red'), { estado: r.status });
    return j;
  }
  const tokens = () => guarda.json('tokens', {});

  const nube = {
    async listar() {
      const r = await rpc('rn_listar', { p_clave: clave, p_dispositivo: dispositivo, p_admin: claveAdmin || null });
      esAdmin = !!r.admin;
      return r.posts;
    },
    async publicar(p) {
      const token = azar(16);
      const fila = await rpc('rn_publicar', {
        p_clave: clave, p_dispositivo: dispositivo, p_token: token, p_seccion: p.seccion, p_autor: p.autor,
        p_relacion: p.relacion || null, p_tipo: p.tipo || 'texto', p_mensaje: p.mensaje || null, p_enlace: p.enlace || null,
        p_adjuntos: p.adjuntos || [], p_parent: p.parent || null, p_tema: p.tema || null, p_homenajeado: !!p.homenajeado
      });
      const t = tokens(); t[fila.id] = token; guarda.set('tokens', JSON.stringify(t));
      return fila;
    },
    megusta: id => rpc('rn_megusta', { p_clave: clave, p_dispositivo: dispositivo, p_post: id }),
    borrar: id => rpc('rn_borrar', { p_clave: clave, p_post: id, p_token: tokens()[id] || '' }),
    moderar: (id, accion) => rpc('rn_moderar', { p_admin: claveAdmin, p_post: id, p_accion: accion }),
    subir(archivo, alAvanzar) {
      return new Promise((ok, mal) => {
        const ext = (archivo.name && archivo.name.includes('.') ? archivo.name.split('.').pop() : (archivo.type.split('/')[1] || 'bin')).toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 5) || 'bin';
        const ruta = `${new Date().getFullYear()}/${uuid()}.${ext}`;
        const x = new XMLHttpRequest();
        x.open('POST', `${CFG.supabaseUrl}/storage/v1/object/saludos/${ruta}`);
        x.setRequestHeader('apikey', CFG.supabaseKey);
        x.setRequestHeader('Authorization', `Bearer ${CFG.supabaseKey}`);
        x.setRequestHeader('Content-Type', archivo.type || 'application/octet-stream');
        x.setRequestHeader('cache-control', 'max-age=31536000');
        x.upload.onprogress = e => { if (e.lengthComputable && alAvanzar) alAvanzar(e.loaded / e.total); };
        x.onload = () => (x.status >= 200 && x.status < 300)
          ? ok({ url: `${CFG.supabaseUrl}/storage/v1/object/public/saludos/${ruta}`, tipo: archivo.type, nombre: archivo.name || '', peso: archivo.size })
          : mal(new Error(x.status === 413 ? 'archivo_muy_grande' : 'no_se_pudo_subir'));
        x.onerror = () => mal(new Error('sin_conexion'));
        x.send(archivo);
      });
    }
  };

  // Modo de prueba: todo queda en este dispositivo.
  const prueba = {
    _leer: () => guarda.json('demo', []),
    _guardar(l) { guarda.set('demo', JSON.stringify(l)); },
    async listar() {
      esAdmin = !!claveAdmin;
      const gustos = guarda.json('demo_gustos', {});
      return this._leer().map(p => ({ ...p, mio: true, megusta: !!gustos[p.id], likes: gustos[p.id] ? 1 : 0 }));
    },
    async publicar(p) {
      const fila = { id: uuid(), creado: new Date().toISOString(), oculto: false, adjuntos: [], ...p };
      const l = this._leer(); l.push(fila); this._guardar(l);
      return { ...fila, mio: true, likes: 0, megusta: false };
    },
    async megusta(id) { const g = guarda.json('demo_gustos', {}); g[id] = !g[id]; guarda.set('demo_gustos', JSON.stringify(g)); return { megusta: g[id], likes: g[id] ? 1 : 0 }; },
    async borrar(id) { this._guardar(this._leer().filter(p => p.id !== id && p.parent !== id)); return true; },
    async moderar(id, accion) {
      if (accion === 'borrar') return this.borrar(id);
      this._guardar(this._leer().map(p => p.id === id ? { ...p, oculto: accion === 'ocultar' } : p)); return true;
    },
    subir(archivo, alAvanzar) {
      return new Promise(ok => {
        const fin = url => { if (alAvanzar) alAvanzar(1); ok({ url, tipo: archivo.type, nombre: archivo.name || '', peso: archivo.size }); };
        if (archivo.size < 600 * 1024) { const fr = new FileReader(); fr.onload = () => fin(fr.result); fr.readAsDataURL(archivo); }
        else fin(URL.createObjectURL(archivo));
      });
    }
  };
  const api = NUBE ? nube : prueba;

  const ERRORES = {
    clave_incorrecta: 'La palabra clave ya no es válida. Pídele el enlace nuevo a quien te invitó.',
    saludo_vacio: 'Tu saludo está vacío. Escribe algo o agrega un archivo.',
    demasiado_rapido: 'Vas muy rápido. Espera un par de minutos y vuelve a intentar.',
    archivo_muy_grande: 'Ese archivo pesa más de 50 MB. Prueba con uno más corto.',
    no_se_pudo_subir: 'No se pudo subir el archivo. Revisa tu conexión y vuelve a intentar.',
    sin_conexion: 'Parece que no hay internet. Revisa tu conexión y vuelve a intentar.'
  };
  const decirError = e => ERRORES[e && e.message] || (e && /fetch|network|red/i.test(e.message || '') ? ERRORES.sin_conexion : 'Algo falló. Vuelve a intentar en un momento.');

  // ---------- incrustar música ----------
  function arreglarEnlace(t) {
    let s = String(t || '').trim();
    if (!s) return '';
    if (!/^https?:\/\//i.test(s)) s = 'https://' + s;
    try { const u = new URL(s); return /^https?:$/.test(u.protocol) && u.hostname.includes('.') ? u.href : ''; } catch { return ''; }
  }
  function incrustar(enlace) {
    let u; try { u = new URL(enlace); } catch { return null; }
    const h = u.hostname.replace(/^(www|m|music)\./, '');
    const id = /^[\w-]{6,64}$/;
    if (h === 'youtu.be' || h === 'youtube.com' || h === 'youtube-nocookie.com') {
      const lista = u.searchParams.get('list');
      let v = h === 'youtu.be' ? u.pathname.slice(1) : u.searchParams.get('v');
      const m = u.pathname.match(/^\/(shorts|embed|live)\/([\w-]+)/); if (m) v = m[2];
      if (v && id.test(v)) return { clase: 'yt', src: `https://www.youtube-nocookie.com/embed/${v}${lista && id.test(lista) ? `?list=${lista}` : ''}`, sitio: 'YouTube' };
      if (lista && id.test(lista)) return { clase: 'yt', src: `https://www.youtube-nocookie.com/embed/videoseries?list=${lista}`, sitio: 'YouTube' };
    }
    if (h === 'open.spotify.com') {
      const m = u.pathname.match(/\/(track|album|playlist|episode|show|artist)\/([A-Za-z0-9]{10,40})/);
      if (m) return { clase: 'sp', src: `https://open.spotify.com/embed/${m[1]}/${m[2]}`, alto: m[1] === 'track' || m[1] === 'episode' ? 152 : 352, sitio: 'Spotify' };
    }
    if (u.hostname === 'music.apple.com') return { clase: 'am', src: `https://embed.music.apple.com${u.pathname}${u.search}`, alto: u.searchParams.get('i') || /\/song\//.test(u.pathname) ? 175 : 450, sitio: 'Apple Music' };
    return null;
  }
  function htmlEnlace(enlace) {
    if (!enlace) return '';
    const e = incrustar(enlace);
    if (e && !SIN_MARCOS) {
      return `<div class="incrustado ${e.clase}${e.clase === 'yt' ? ' enmarcado' : ''}"><iframe src="${esc(e.src)}" ${e.alto ? `height="${e.alto}"` : ''} loading="lazy" title="Música en ${e.sitio}" allow="autoplay; clipboard-write; encrypted-media; fullscreen; picture-in-picture" allowfullscreen referrerpolicy="strict-origin-when-cross-origin"></iframe></div>`;
    }
    let sitio = e ? e.sitio : ''; try { sitio = sitio || new URL(enlace).hostname.replace(/^www\./, ''); } catch { /* */ }
    return `<a class="tarjeta-enlace" href="${esc(enlace)}" target="_blank" rel="noopener">${ico(e ? 'musica' : 'enlace')}<span><b>Abrir en ${esc(sitio)}</b></span></a>`;
  }

  // ---------- piezas de interfaz ----------
  const esFoto = a => (a.tipo || '').startsWith('image/');
  const esVideo = a => (a.tipo || '').startsWith('video/');
  const esAudio = a => (a.tipo || '').startsWith('audio/');
  const esCancion = a => a.tipo === 'cancion';
  // Un saludo puede traer varias cosas a la vez
  function contiene(p) { const a = p.adjuntos || []; return { texto: !!p.mensaje, foto: a.some(esFoto), video: a.some(esVideo), audio: a.some(esAudio), musica: !!p.enlace || a.some(esCancion) }; }
  // Canción elegida por nombre: portada, adelanto de 30 segundos y accesos para oírla completa.
  const urlDe = (u, dominios) => { try { const x = new URL(u); return x.protocol === 'https:' && dominios.some(d => x.hostname === d || x.hostname.endsWith('.' + d)) ? x.href : ''; } catch { return ''; } };
  const portadaDe = c => SIN_MARCOS ? '' : urlDe(c.portada, ['mzstatic.com']);
  function htmlCancion(c) {
    const portada = portadaDe(c), previa = SIN_MARCOS ? '' : urlDe(c.previa, ['itunes.apple.com']);
    const q = encodeURIComponent(`${c.titulo || ''} ${c.artista || ''}`.trim());
    return `<div class="cancion">${portada ? `<img src="${esc(portada)}" alt="" loading="lazy" width="96" height="96">` : `<span class="cancion-disco">${ico('musica')}</span>`}
      <div class="cancion-datos"><b>${esc(c.titulo)}</b><span>${esc(c.artista)}</span>
        ${previa ? `<audio controls preload="none" src="${esc(previa)}"></audio>` : ''}
        <div class="cancion-enlaces"><span>Completa en</span><a href="https://www.youtube.com/results?search_query=${q}" target="_blank" rel="noopener">YouTube</a><a href="https://open.spotify.com/search/${q}" target="_blank" rel="noopener">Spotify</a></div>
      </div></div>`;
  }
  function htmlAdjuntos(p) {
    const a = p.adjuntos || [];
    const fotos = a.filter(esFoto);
    let h = '';
    if (fotos.length) h += `<div class="fotos ${fotos.length === 1 ? 'una' : ''}">${fotos.map(f => `<button type="button" class="enmarcado" data-accion="ver-foto" data-url="${esc(f.url)}" aria-label="Ver foto en grande"><img src="${esc(f.url)}" alt="Foto de ${esc(p.autor)}" loading="lazy"></button>`).join('')}</div>`;
    a.filter(esVideo).forEach(v => { h += `<div class="enmarcado"><video src="${esc(v.url)}" controls playsinline preload="metadata"></video></div>`; });
    a.filter(esAudio).forEach(v => { h += `<audio src="${esc(v.url)}" controls preload="metadata"></audio>`; });
    a.filter(esCancion).forEach(c => { h += htmlCancion(c); });
    return h;
  }
  const etiquetaEl = () => `${pieza('♚')} ${esc(C.homenajeado.nombre)}`;

  function htmlTarjeta(p, n) {
    const resp = posts.filter(r => r.parent === p.id && r.seccion === 'respuesta' && (esAdmin || !r.oculto));
    const abierto = abiertos.has(p.id);
    return `<article class="jugada ${p.oculto ? 'oculta' : ''} ${p.homenajeado ? 'del-homenajeado' : ''}" id="p-${p.id}">
      <div class="quien">
        <span class="inicial" aria-hidden="true">${esc((p.autor || '?').trim().charAt(0).toUpperCase())}</span>
        <div><b>${p.homenajeado ? etiquetaEl() : esc(p.autor)}</b>
          <small>${p.relacion ? esc(p.relacion) + ' · ' : ''}${fecha(p.creado)}${p.oculto ? ' · OCULTO' : ''}</small></div>
      </div>
      ${p.mensaje ? `<p class="texto-saludo">${esc(p.mensaje)}</p>` : ''}
      ${htmlAdjuntos(p)}${htmlEnlace(p.enlace)}
      <div class="pie-jugada">
        <button type="button" class="btn-texto ${p.megusta ? 'activo' : ''}" data-accion="megusta" data-id="${p.id}" aria-pressed="${!!p.megusta}">${ico('corazon')}<span>${p.likes ? p.likes : 'Me encanta'}</span></button>
        <button type="button" class="btn-texto" data-accion="abrir-respuesta" data-id="${p.id}">${ico('responder')}<span>${resp.length ? plural(resp.length, 'respuesta', 'respuestas') : 'Responder'}</span></button>
        <span class="empuja"></span>
        ${p.mio && !esAdmin ? `<button type="button" class="btn-texto peligro" data-accion="borrar" data-id="${p.id}" title="Borrar mi saludo">${ico('basura')}<span class="solo-lector">Borrar</span></button>` : ''}
        ${esAdmin ? `<button type="button" class="btn-texto" data-accion="moderar" data-id="${p.id}" data-que="${p.oculto ? 'mostrar' : 'ocultar'}">${ico('ojo')}<span>${p.oculto ? 'Mostrar' : 'Ocultar'}</span></button>
          <button type="button" class="btn-texto peligro" data-accion="moderar" data-id="${p.id}" data-que="borrar" title="Borrar">${ico('basura')}<span class="solo-lector">Borrar</span></button>` : ''}
      </div>
      ${resp.length || abierto ? `<div class="respuestas">
        ${resp.map(r => `<div class="respuesta"><b>${r.homenajeado ? etiquetaEl() : esc(r.autor)}<small>${fecha(r.creado)}</small></b><p>${esc(r.mensaje)}</p>
          ${(r.mio || esAdmin) ? `<button type="button" class="btn-texto peligro" data-accion="${esAdmin ? 'moderar' : 'borrar'}" data-que="borrar" data-id="${r.id}">Borrar</button>` : ''}</div>`).join('')}
        ${abierto ? `<form class="redactar" data-form="respuesta" novalidate data-id="${p.id}">
          <textarea id="r-${p.id}" data-borrador="r-${p.id}" placeholder="Escribe tu respuesta" aria-label="Tu respuesta" rows="1">${esc(borradores['r-' + p.id] || '')}</textarea>
          <button class="btn btn-haz" type="submit" aria-label="Enviar respuesta">${ico('enviar')}</button></form>` : ''}
      </div>` : ''}
    </article>`;
  }

  function htmlMarcador(saludos) {
    const c = t => saludos.filter(p => contiene(p)[t]).length;
    return `<div class="marcador">
      <div class="recursos" role="list" aria-label="Lo que ha dejado la gente">
        <div role="listitem">${ico('pluma')}<b>${c('texto')}</b><span>Mensajes</span></div>
        <div role="listitem">${ico('foto')}<b>${c('foto')}</b><span>Fotos</span></div>
        <div role="listitem">${ico('video')}<b>${c('video')}</b><span>Videos</span></div>
        <div role="listitem">${ico('audio')}<b>${c('audio')}</b><span>Audios</span></div>
        <div role="listitem">${ico('musica')}<b>${c('musica')}</b><span>Música</span></div>
      </div>
    </div>`;
  }

  // ---------- vistas ----------
  function htmlBloqueCarta(b) {
    if (b.t === 'saludo') return `<p class="saludo-carta">${esc(b.texto)}</p>`;
    if (b.t === 'p') return `<p>${esc(b.texto)}</p>`;
    if (b.t === 'firma') return `<p class="firma">${esc(b.texto)}</p>`;
    if (b.t === 'foto') return `<figure><div class="marco enmarcado ${b.alto ? 'alto' : ''}"><img data-medio="${esc(b.medio)}" alt="${esc(b.alt || '')}" width="${b.ancho || 800}" height="${b.altoPx || 1000}"></div><figcaption>${esc(b.pie || '')}</figcaption></figure>`;
    if (b.t === 'par') return `<div class="par">${b.fotos.map(f => htmlBloqueCarta({ t: 'foto', ...f })).join('')}</div>`;
    if (b.t === 'video') return `<figure><div class="video-vertical enmarcado"><video data-medio="${esc(b.medio)}" data-cartel="${esc(b.cartel || '')}" controls playsinline preload="none"></video></div><figcaption>${esc(b.pie || '')}</figcaption></figure>`;
    if (b.t === 'cancion') {
      const url = `https://www.youtube.com/watch?v=${encodeURIComponent(b.youtube)}`;
      return `<div class="luna">
        <p class="artista">${esc(b.artista)}</p>
        <h3>${esc(b.titulo)}</h3>
        <p>${esc(b.texto)}</p>
        <div id="cancion-caja">${SIN_MARCOS
          ? `<a class="btn btn-haz" href="${url}" target="_blank" rel="noopener">${ico('play')}Escuchar en YouTube</a>`
          : `<button type="button" class="btn btn-haz" data-accion="tocar-cancion" data-yt="${esc(b.youtube)}">${ico('play')}Escuchar la canción</button>`}</div>
      </div>`;
    }
    return '';
  }

  function vistaInicio() {
    const h = C.homenajeado, T = C.textos, nombre = esc(h.nombre);
    const saludos = posts.filter(p => p.seccion === 'saludo' && !p.oculto);
    const gente = new Set(saludos.map(p => norm(p.autor))).size;
    const d = diasPara(h.fecha), f = fechaDia(h.fecha);
    const cuenta = d > 0 ? `<b>T−${d}</b>${d === 1 ? 'día' : 'días'} para el ${f}` : d === 0 ? `<b>T−0</b>Hoy es el día` : `<b>T+${-d}</b>Fue el ${f}. Aún puedes sumar tu saludo`;
    const portada = esEl()
      ? `<p class="rotulo">${f} · ${esc(T.elRotulo)}</p>
         <h1 class="palabra"><span>Feliz</span><span class="lado">${esc(T.elLado)}</span><span class="l2">cumple,</span><span class="l2">${nombre}</span></h1>
         <p class="bajada">${esc(saludos.length ? T.elBajada.replace('{personas}', plural(gente, 'persona', 'personas')).replace('{saludos}', plural(saludos.length, 'saludo', 'saludos')) : T.elBajadaVacia)}</p>
         <div class="portada-pie">
           <div><button type="button" class="enlace-flecha" data-accion="saludar">${esc(T.elEscribir)}<i>→</i></button></div>
           <a class="cta-circulo" href="#mosaico" data-ir="mosaico">${esc(T.elVer)}</a>
         </div>`
      : `<p class="rotulo">Sorpresa de cumpleaños · ${f}</p>
         <h1 class="palabra"><span>Misión</span><span class="lado">Cumple lejos. Llevémosle la casa.</span><span class="l2">${nombre}</span></h1>
         <ul class="vinetas"><li>Mensajes</li><li>Videos</li><li>Fotos</li><li>Audios</li><li>Canciones</li></ul>
         <p class="bajada">Déjale una cosa o varias. Toma dos minutos y no necesitas crear ninguna cuenta.</p>
         <div class="portada-pie">
           <div><p class="cuenta">${cuenta}</p><a class="enlace-flecha" href="#mosaico" data-ir="mosaico">Ver el mosaico<i>→</i></a></div>
           <button type="button" class="cta-circulo" data-accion="saludar">Dejar mi saludo</button>
         </div>`;

    return `<div class="portada espacio"><div class="columna portada-texto">${portada}</div></div>
      <div class="columna">
        ${esEl() ? '' : `
        <div class="secreto">${pieza('♞')}<p><b>Es sorpresa.</b> No le reenvíes este enlace a ${nombre}: él recibirá el suyo el ${f}.</p></div>
        <section class="seccion">
          <h2>Cómo sumarte</h2>
          <ol class="como">
            <li><div><b>Dinos quién eres</b><span>Solo tu nombre, para que ${nombre} sepa de quién viene.</span></div></li>
            <li><div><b>Elige qué dejarle</b><span>Unas palabras, fotos, un video, un audio, una canción. Una cosa o varias.</span></div></li>
            <li><div><b>Envía</b><span>Tu saludo se suma al mosaico al instante.</span></div></li>
          </ol>
        </section>`}
        <section class="seccion">
          <p class="rotulo">${esc(C.ficha.rotulo)}</p>
          <h2>${esc(C.ficha.titulo)}</h2>
          <div class="ficha-rejilla">
            <figure class="ficha-foto"><div class="enmarcado"><img data-medio="${esc(C.portada.medio)}" alt="${esc(C.portada.alt)}" width="1080" height="1080"></div><figcaption>${esc(C.portada.pie)}</figcaption></figure>
            <div class="ficha">${C.ficha.lineas.map(l => `<div>${pieza(l.pieza)}<p><b>${esc(l.titulo)}</b><span>${esc(l.texto)}</span></p></div>`).join('')}</div>
          </div>
        </section>
        <section class="carta">
          <p class="rotulo">${esc(C.carta.rotulo)}</p>
          <h2>${esc(C.carta.titulo)}</h2>
          ${C.carta.bloques.map(htmlBloqueCarta).join('')}
        </section>
      </div>
      <footer class="pie-nave espacio"><div class="columna">
        <div class="pie-marca"><span class="logo grande" aria-hidden="true">${esc(h.nombre.charAt(0))}</span><b>${esc(C.marca)}</b><p>Sorpresa de cumpleaños · ${f}</p></div>
        <nav class="pie-col" aria-label="Secciones"><h4>Navegación</h4><a href="#mosaico" data-ir="mosaico">Mosaico</a><a href="#saludos" data-ir="saludos">Saludos</a><a href="#foro" data-ir="foro">Foro</a></nav>
        <div class="pie-col"><h4>${esc(C.despedida.titulo)}</h4>${C.despedida.lineas.map(l => `<span>${esc(l)}</span>`).join('')}</div>
        <div class="pie-fin"><span>${esc(C.pie)}</span><span>${esc(C.despedida.fecha)}</span></div>
      </div></footer>`;
  }

  // ---------- mosaico: cada cosa que alguien deja es una pieza ----------
  const piezasVistas = new Set();
  const colorDe = nombre => 'c' + ([...norm(nombre)].reduce((s, ch) => (s * 31 + ch.charCodeAt(0)) % 997, 7) % 6);
  function piezasMosaico() {
    const P = [], org = C.organiza;
    const pon = o => P.push(o);
    // Los recuerdos de la carta abren el mosaico
    C.carta.bloques.forEach(b => {
      (b.t === 'par' ? b.fotos : b.t === 'foto' ? [b] : []).forEach(f => pon({ k: 'm-' + f.medio, t: 'foto', medio: f.medio, autor: org, w: 2, h: 2, destino: 'carta' }));
      if (b.t === 'video') pon({ k: 'm-video', t: 'video', medio: b.cartel, autor: org, w: 2, h: 3, destino: 'carta' });
      if (b.t === 'cancion') pon({ k: 'm-cancion', t: 'musica', texto: b.titulo, autor: org, w: 2, h: 1, destino: 'carta' });
    });
    const privados = new Set(C.foro.temas.filter(t => t.soloFamilia).map(t => t.id));
    const temaDe = id => (C.foro.temas.find(t => t.id === id) || {}).titulo || 'Foro';
    posts.filter(p => !p.oculto).forEach(p => {
      const a = p.adjuntos || [], autor = p.homenajeado ? C.homenajeado.nombre : p.autor;
      if (p.seccion === 'saludo') {
        const d = { destino: 'saludo', id: p.id, autor };
        a.filter(esFoto).forEach((f, i) => pon({ ...d, k: `${p.id}-f${i}`, t: 'foto', url: f.url, w: i ? 1 : 2, h: i ? 1 : 2 }));
        a.filter(esVideo).forEach((f, i) => pon({ ...d, k: `${p.id}-v${i}`, t: 'video', url: f.url, w: 2, h: 3 }));
        if (p.mensaje) pon({ ...d, k: p.id + '-t', t: 'texto', texto: p.mensaje, w: p.mensaje.length > 110 ? 4 : 2, h: 2 });
        if (a.some(esAudio)) pon({ ...d, k: p.id + '-a', t: 'audio', w: 2, h: 1 });
        if (p.enlace) pon({ ...d, k: p.id + '-m', t: 'musica', texto: (incrustar(p.enlace) || {}).sitio || 'Canción', w: 2, h: 1 });
        a.filter(esCancion).forEach((c, i) => pon(portadaDe(c) ? { ...d, k: `${p.id}-c${i}`, t: 'cancion', cancion: c, w: 2, h: 2 } : { ...d, k: `${p.id}-c${i}`, t: 'musica', texto: c.titulo || 'Canción', w: 2, h: 1 }));
      } else if (p.seccion === 'foro' && !privados.has(p.tema)) {
        const d = { destino: 'foro', tema: p.tema, autor };
        a.filter(esFoto).forEach((f, i) => pon({ ...d, k: `${p.id}-f${i}`, t: 'foto', url: f.url, w: 2, h: 2 }));
        if (p.mensaje) pon({ ...d, k: p.id + '-t', t: 'texto', texto: p.mensaje, pie: temaDe(p.tema), w: 2, h: p.mensaje.length > 60 ? 2 : 1 });
      } else if (p.seccion === 'respuesta') {
        const padre = posts.find(x => x.id === p.parent);
        if (padre && !padre.oculto) pon({ k: p.id + '-r', t: 'respuesta', autor, a: padre.homenajeado ? C.homenajeado.nombre : padre.autor, destino: 'saludo', id: padre.id, w: 2, h: 1 });
      }
    });
    const gustos = posts.reduce((s, p) => s + (p.oculto ? 0 : (p.likes || 0)), 0);
    if (gustos) pon({ k: 'gustos', t: 'gustos', n: gustos, w: 1, h: 1, destino: 'saludos' });
    return P;
  }
  function htmlTesela(p, i) {
    const nueva = !piezasVistas.has(p.k); piezasVistas.add(p.k);
    const base = `class="tesela ${['foto', 'video', 'cancion'].includes(p.t) ? 'con-foto' : colorDe(p.autor || 'x')} w${p.w} h${p.h} ${nueva ? 'nueva' : ''} ${{ texto: 'con-texto', musica: 'con-texto', audio: 'con-texto', respuesta: 'con-texto', gustos: 'chica' }[p.t] || ''}" style="--w:${p.w};--h:${p.h};--i:${Math.min(i, 28)}" data-accion="ir-pieza" data-destino="${p.destino}" ${p.id ? `data-id="${p.id}"` : ''} ${p.tema ? `data-tema="${esc(p.tema)}"` : ''}`;
    const quien = esc(p.autor || '');
    if (p.t === 'foto') return `<button type="button" ${base} aria-label="Foto de ${quien}"><img ${p.medio ? `data-medio="${esc(p.medio)}"` : `src="${esc(p.url)}" loading="lazy"`} alt=""><span class="sello">${quien}</span></button>`;
    if (p.t === 'video') return `<button type="button" ${base} aria-label="Video de ${quien}">${p.medio ? `<img data-medio="${esc(p.medio)}" alt="">` : `<video src="${esc(p.url)}#t=0.4" muted playsinline preload="metadata" tabindex="-1"></video>`}<span class="play">${ico('play')}</span><span class="sello">${quien}</span></button>`;
    if (p.t === 'texto') return `<button type="button" ${base}><span class="cita ${p.texto.length < 48 ? 'corta' : ''}">${esc(p.texto.slice(0, 220))}</span><span class="autor">${quien}${p.pie ? ' · ' + esc(p.pie) : ''}</span></button>`;
    if (p.t === 'cancion') return `<button type="button" ${base} aria-label="Canción de ${quien}"><img src="${esc(portadaDe(p.cancion))}" alt="" loading="lazy"><span class="play">${ico('musica')}</span><span class="sello">${esc(p.cancion.titulo)} · ${quien}</span></button>`;
    if (p.t === 'audio') return `<button type="button" ${base}>${ico('audio')}<span class="autor">Audio de ${quien}</span></button>`;
    if (p.t === 'musica') return `<button type="button" ${base}>${ico('musica')}<span class="autor">${esc(p.texto)} · ${quien}</span></button>`;
    if (p.t === 'respuesta') return `<button type="button" ${base}>${ico('responder')}<span class="autor">${quien} le respondió a ${esc(p.a)}</span></button>`;
    if (p.t === 'gustos') return `<button type="button" ${base} aria-label="${p.n} me encanta">${ico('corazon')}<span class="autor">${p.n}</span></button>`;
    return '';
  }
  function vistaMosaico() {
    const P = piezasMosaico(), h = C.homenajeado;
    const huecos = esEl() ? '' : `
      <button type="button" class="tesela hueco w2 h1" style="--w:2;--h:1" data-accion="ir-pieza" data-destino="saludar">${ico('mas')}${esc(C.textos.hueco)}</button>
      <button type="button" class="tesela hueco w1 h1" style="--w:1;--h:1" data-accion="ir-pieza" data-destino="saludar" aria-label="Agregar una pieza">${ico('mas')}</button>
      <button type="button" class="tesela hueco w1 h1" style="--w:1;--h:1" data-accion="ir-pieza" data-destino="saludar" aria-label="Agregar una pieza">${ico('mas')}</button>`;
    return `<div class="columna ancha">
      <header class="cab-vista">
        <p class="rotulo">Mosaico · ${plural(P.length, 'pieza', 'piezas')}</p>
        <h2>${esEl() ? esc(C.textos.elMosaico) : `El mosaico de ${esc(h.nombre)}`}</h2>
        <p>${esEl() ? esc(C.textos.elMosaicoBajada) : 'Cada foto, mensaje, audio, video o canción que alguien deja se vuelve una pieza. Toca cualquiera para verla completa.'}</p>
      </header>
      <div class="mosaico-caja"><div class="mosaico">${P.map(htmlTesela).join('')}${huecos}</div></div>
    </div>`;
  }

  const FILTROS = [['todos', 'Todos'], ['texto', 'Mensajes'], ['foto', 'Fotos'], ['video', 'Videos'], ['audio', 'Audios'], ['musica', 'Música']];
  function vistaSaludos() {
    const todos = posts.filter(p => p.seccion === 'saludo' && (esAdmin || !p.oculto));
    const numero = new Map(todos.map((p, i) => [p.id, i + 1]));
    const visibles = todos.filter(p => filtro === 'todos' || contiene(p)[filtro]).slice().reverse();
    const h = C.homenajeado;
    return `<div class="columna">
      <header class="cab-vista">
        <p class="rotulo">El tablero</p>
        <h2>${esEl() ? esc(C.textos.elTablero) : `Saludos para ${esc(h.nombre)}`}</h2>
        <p>${esEl() ? esc(C.textos.elTableroBajada) : 'Todo lo que le han dejado, del más reciente al primero.'}</p>
      </header>
      ${htmlMarcador(todos.filter(p => !p.oculto))}
      <div class="filtros" role="group" aria-label="Filtrar saludos">${FILTROS.map(([k, t]) => `<button type="button" class="chip" data-accion="filtrar" data-filtro="${k}" aria-pressed="${filtro === k}">${t}</button>`).join('')}</div>
      <div class="muro">
        ${visibles.length ? visibles.map(p => htmlTarjeta(p, numero.get(p.id))).join('') : `<div class="vacio">${pieza('♙')}
          <h3>${todos.length ? 'Nada de este tipo todavía' : 'El tablero está listo'}</h3>
          <p>${todos.length ? 'Prueba con otro filtro o sé quien lo estrene.' : esEl() ? esc(C.textos.elVacio) : 'Aún no hay saludos. El primero puede ser el tuyo.'}</p>
          ${esEl() ? '' : `<button type="button" class="btn btn-haz" data-accion="saludar">${ico('mas')}Dejar mi saludo</button>`}</div>`}
      </div>
    </div>`;
  }

  function temasVisibles() { return C.foro.temas.filter(t => !(t.soloFamilia && esEl())); }
  function vistaForo() {
    const temas = temasVisibles();
    if (temaAbierto && !temas.some(t => t.id === temaAbierto)) temaAbierto = null;
    const msjs = id => posts.filter(p => p.seccion === 'foro' && p.tema === id && (esAdmin || !p.oculto));
    if (!temaAbierto) {
      return `<div class="columna">
        <header class="cab-vista"><p class="rotulo">Puente de mando</p><h2>${esc(C.foro.titulo)}</h2><p>${esc(C.foro.texto)}</p></header>
        <div class="temas">${temas.map(t => {
          const m = msjs(t.id), ult = m[m.length - 1];
          return `<button type="button" class="tema ${t.soloFamilia ? 'privado' : ''}" data-accion="abrir-tema" data-tema="${t.id}">
            ${pieza(t.pieza)}<span><b>${esc(t.titulo)}</b><span>${ult ? `${esc(ult.autor)}: ${esc((ult.mensaje || 'envió una foto').slice(0, 60))}` : esc(t.texto)}</span></span>
            <span class="cuantos" aria-label="${plural(m.length, 'mensaje', 'mensajes')}">${m.length}</span></button>`;
        }).join('')}</div>
      </div>`;
    }
    const t = temas.find(x => x.id === temaAbierto), m = msjs(t.id);
    const adj = adjuntoForo[t.id];
    return `<div class="columna">
      <header class="cab-vista">
        <button type="button" class="btn-texto volver" data-accion="cerrar-tema">${ico('atras')}Todos los temas</button>
        <h2>${esc(t.titulo)}</h2><p>${esc(t.texto)}</p>
      </header>
      <div class="hilo">${m.length ? m.map(p => `<div class="globo ${p.mio ? 'mio' : ''} ${p.homenajeado ? 'del-homenajeado' : ''} ${p.oculto ? 'oculta' : ''}">
          <b>${p.homenajeado ? etiquetaEl() : esc(p.autor)}<small>${fecha(p.creado, true)}</small></b>
          ${p.mensaje ? `<p>${esc(p.mensaje)}</p>` : ''}
          ${(p.adjuntos || []).filter(esFoto).map(a => `<div class="enmarcado"><img src="${esc(a.url)}" alt="Foto de ${esc(p.autor)}" loading="lazy" data-accion="ver-foto" data-url="${esc(a.url)}"></div>`).join('')}
          ${(p.mio || esAdmin) ? `<button type="button" class="btn-texto peligro" data-accion="${esAdmin ? 'moderar' : 'borrar'}" data-que="borrar" data-id="${p.id}">Borrar</button>` : ''}
        </div>`).join('') : `<div class="vacio">${pieza(t.pieza)}<h3>Nadie ha escrito aquí todavía</h3><p>Rompe el hielo: cuenta algo.</p></div>`}</div>
      <form class="redactar-foro" data-form="foro" novalidate data-tema="${t.id}">
        ${adj ? `<div class="adjunto-listo">${ico('foto')}<span>Foto lista: ${esc(adj.name)}</span><button type="button" class="btn-texto" data-accion="quitar-adjunto-foro">Quitar</button></div>` : ''}
        <div class="fila">
          <label class="btn-icono con-borde" style="cursor:pointer" title="Agregar una foto">${ico('clip')}<input type="file" id="foro-foto" accept="image/*" hidden><span class="solo-lector">Agregar una foto</span></label>
          <textarea id="f-${t.id}" data-borrador="f-${t.id}" placeholder="Escribe aquí" aria-label="Tu mensaje" rows="1">${esc(borradores['f-' + t.id] || '')}</textarea>
          <button class="btn btn-haz" type="submit" aria-label="Enviar mensaje">${ico('enviar')}</button>
        </div>
      </form>
    </div>`;
  }
  const adjuntoForo = {};

  function enlaces() {
    const base = location.origin + location.pathname;
    return { familia: `${base}#clave=${C.claveVisible}`, el: `${base}#clave=${C.claveVisible}&para=${norm(C.homenajeado.nombre)}` };
  }
  function vistaPanel() {
    if (!esAdmin) return `<div class="columna"><div class="vacio" style="margin-top:2rem"><h3>Este panel es solo para la organizadora</h3><p>Ábrelo desde tu enlace personal.</p></div></div>`;
    const h = C.homenajeado, L = enlaces();
    const sal = posts.filter(p => p.seccion === 'saludo');
    const foro = posts.filter(p => p.seccion !== 'saludo');
    const likes = posts.reduce((s, p) => s + (p.likes || 0), 0);
    const gente = new Map();
    posts.forEach(p => { const k = norm(p.autor); const g = gente.get(k) || { nombre: p.autor, saludos: 0, otros: 0, ult: p.creado }; p.seccion === 'saludo' ? g.saludos++ : g.otros++; g.ult = p.creado; gente.set(k, g); });
    const usado = posts.reduce((s, p) => s + (p.adjuntos || []).reduce((a, x) => a + (x.peso || 0), 0), 0);
    const invitacion = C.textos.invitacion.replace('{enlace}', L.familia).replace('{fecha}', fechaDia(h.fecha));
    const paraEl = C.textos.mensajeParaEl.replace('{enlace}', L.el);
    return `<div class="columna">
      <header class="cab-vista"><p class="rotulo">Solo tú ves esto</p><h2>Panel de la organizadora</h2>
        <p>${diasPara(h.fecha) >= 0 ? `Faltan ${plural(diasPara(h.fecha), 'día', 'días')} para el ${fechaDia(h.fecha)}.` : `El cumpleaños fue el ${fechaDia(h.fecha)}.`} ${NUBE ? '' : 'Estás en modo de prueba: falta conectar la base de datos.'}</p></header>
      <div class="cifras">
        <div class="cifra"><b>${sal.length}</b><span>Saludos</span></div>
        <div class="cifra"><b>${gente.size}</b><span>Personas</span></div>
        <div class="cifra"><b>${foro.length}</b><span>Mensajes y respuestas</span></div>
        <div class="cifra"><b>${likes}</b><span>Me encanta</span></div>
      </div>

      <section class="bloque"><h3>1. Invita a la familia y amigos</h3>
        <p>Este enlace ya lleva la palabra clave. Quien lo abra entra directo.</p>
        <div class="enlace-caja"><code id="enlace-familia">${esc(L.familia)}</code>
          <div class="fila">
            <button type="button" class="btn btn-haz btn-chico" data-accion="copiar" data-texto="${esc(invitacion)}">${ico('copiar')}Copiar invitación</button>
            <a class="btn btn-chico" href="https://wa.me/?text=${encodeURIComponent(invitacion)}" target="_blank" rel="noopener">Enviar por WhatsApp</a>
            <button type="button" class="btn btn-chico" data-accion="copiar" data-texto="${esc(L.familia)}">Copiar solo el enlace</button>
          </div></div>
      </section>

      <section class="bloque"><h3>2. El ${fechaDia(h.fecha)}, mándale esto a ${esc(h.nombre)}</h3>
        <p>Su enlace abre con una bienvenida especial y esconde el tema donde coordinan la sorpresa.</p>
        <div class="enlace-caja"><code>${esc(L.el)}</code>
          <div class="fila">
            <button type="button" class="btn btn-sodio btn-chico" data-accion="copiar" data-texto="${esc(paraEl)}">${ico('copiar')}Copiar mensaje para él</button>
            <button type="button" class="btn btn-chico" data-accion="ver-como-el">${ico('ojo')}Ver la página como él</button>
          </div></div>
      </section>

      <section class="bloque"><h3>Quiénes ya participaron</h3>
        ${gente.size ? `<ul class="lista-gente">${[...gente.values()].sort((a, b) => b.ult.localeCompare(a.ult)).map(g => `<li><b>${esc(g.nombre)}</b><small>${plural(g.saludos, 'saludo', 'saludos')}${g.otros ? ` · ${plural(g.otros, 'mensaje', 'mensajes')}` : ''}<br>último: ${fecha(g.ult, true)}</small></li>`).join('')}</ul>` : `<p>Todavía nadie. Comparte la invitación de arriba.</p>`}
      </section>

      <section class="bloque"><h3>Espacio para archivos</h3>
        <div class="medidor" role="img" aria-label="Espacio usado"><u style="width:${Math.min(100, (usado / ESPACIO_TOTAL) * 100).toFixed(1)}%"></u></div>
        <p>${peso(usado)} usados de 1 GB gratuito. Un video de un minuto suele pesar entre 10 y 40 MB.</p>
      </section>

      <section class="bloque"><h3>Moderación y respaldo</h3>
        <p>Desde las pestañas Saludos y Foro puedes ocultar o borrar cualquier publicación. Lo oculto solo lo ves tú.</p>
        <div class="fila">
          <button type="button" class="btn btn-chico" data-accion="respaldo">Descargar respaldo</button>
          <button type="button" class="btn btn-chico" data-accion="salir-admin">Salir del modo organizadora</button>
        </div>
      </section>
    </div>`;
  }

  // ---------- pintar ----------
  function pintar() {
    $$('[data-solo-admin]').forEach(e => { e.hidden = !esAdmin; });
    $$('[data-ir]').forEach(a => a.classList.toggle('activo', a.dataset.ir === vista));
    $$('.vista').forEach(v => { v.hidden = v.id !== 'v-' + vista; });
    const cont = $('#v-' + vista);
    const foco = document.activeElement && document.activeElement.id;
    cont.innerHTML = vista === 'inicio' ? vistaInicio() : vista === 'mosaico' ? vistaMosaico() : vista === 'saludos' ? vistaSaludos() : vista === 'foro' ? vistaForo() : vistaPanel();
    hidratar(cont);
    if (foco && document.getElementById(foco)) { const el = document.getElementById(foco); el.focus(); if (el.setSelectionRange) el.setSelectionRange(el.value.length, el.value.length); }
    $$('[data-txt="cta-corto"]').forEach(e => { e.textContent = esEl() ? C.textos.elEscribir : 'Dejar mi saludo'; });
    $$('[data-txt="cta-tab"]').forEach(e => { e.textContent = esEl() ? 'Escribir' : 'Saludar'; });
    pendientes = false; pintarNovedades();
  }
  function pintarNovedades() {
    let b = $('#novedades');
    if (!pendientes) { if (b) b.remove(); return; }
    if (!b) { b = document.createElement('button'); b.id = 'novedades'; b.type = 'button'; b.className = 'btn btn-haz btn-chico novedades'; b.dataset.accion = 'refrescar'; b.textContent = 'Hay novedades · Ver'; document.body.appendChild(b); }
  }
  function ir(v, alTope = true) {
    if (!['inicio', 'mosaico', 'saludos', 'foro', 'panel'].includes(v)) v = 'inicio';
    if (v === 'panel' && !esAdmin) v = 'inicio';
    vista = v;
    try { history.replaceState(null, '', '#' + v); } catch { /* */ }
    pintar();
    if (alTope) window.scrollTo(0, 0);
  }
  const ocupado = () => {
    const a = document.activeElement;
    if (a && /TEXTAREA|INPUT/.test(a.tagName) && a.closest('main')) return true;
    return $$('main video, main audio').some(m => !m.paused && !m.ended) || !!$('#cancion-caja iframe');
  };
  async function cargar(forzar = false) {
    let lista;
    try { lista = await api.listar(); } catch (e) { if (e.message === 'clave_incorrecta') tostada(ERRORES.clave_incorrecta, 6000); return; }
    const h = JSON.stringify(lista);
    if (h === huella && !forzar) return;
    huella = h; posts = lista;
    if (!forzar && (ocupado() || !$('#asistente').hidden)) { pendientes = true; pintarNovedades(); return; }
    pintar();
  }

  // ---------- asistente ----------
  const TIPOS = [
    { id: 'texto', ico: 'pluma', titulo: 'Un mensaje', texto: 'Unas líneas, una anécdota, un deseo.', falta: 'el mensaje', solo: 'Escribe tu mensaje antes de enviar.' },
    { id: 'foto', ico: 'foto', titulo: 'Fotos', texto: 'Recuerdos juntos. Hasta 6 fotos.', falta: 'las fotos', solo: 'Elige al menos una foto.' },
    { id: 'video', ico: 'video', titulo: 'Un video', texto: 'Grabado ahora o elegido de tu galería.', falta: 'el video', solo: 'Elige o graba un video.' },
    { id: 'audio', ico: 'audio', titulo: 'Un audio', texto: 'Tu voz, grabada aquí mismo.', falta: 'el audio', solo: 'Graba o sube un audio.' },
    { id: 'musica', ico: 'musica', titulo: 'Una canción', texto: 'Un enlace de YouTube o Spotify. También sirve una playlist.', falta: 'la canción', solo: 'Elige una canción de la lista o pega un enlace.' }
  ];
  const RELACIONES = ['Familia', 'Amistad', 'Colega', 'Estudiante', 'Otro'];
  let A = null;   // estado del asistente
  let grab = null; // grabadora

  const saludoVacio = () => ({ tipos: new Set(), texto: '', fotos: [], video: null, audio: null, enlace: '', cancion: null, busca: '', resultados: null, buscando: false, verEnlace: false });
  const elegidos = () => TIPOS.filter(t => A.tipos.has(t.id));
  const enLista = l => l.length < 2 ? l.join('') : `${l.slice(0, -1).join(', ')} y ${l[l.length - 1]}`;
  function sincronizar() {
    if (!A) return;
    const t = $('#as-texto'); if (t) A.texto = t.value;
    const e = $('#as-enlace'); if (e) A.enlace = e.value;
    const b = $('#as-busca'); if (b) A.busca = b.value;
  }

  // Sugerencias de canciones a partir del nombre (catálogo público de iTunes)
  let buscaT = null, buscaN = 0;
  function htmlResultados() {
    if (A.buscando) return `<p class="tenue">Buscando…</p>`;
    if (A.resultados === null) return '';
    if (A.resultados === 'error') return `<p class="tenue">La búsqueda no está disponible ahora. Puedes pegar un enlace.</p>`;
    if (!A.resultados.length) return `<p class="tenue">No encontramos esa canción. Prueba con otras palabras o pega un enlace.</p>`;
    return A.resultados.map((c, i) => `<button type="button" class="resultado" data-accion="elegir-cancion" data-i="${i}">
      ${portadaDe(c) ? `<img src="${esc(portadaDe(c))}" alt="" width="48" height="48" loading="lazy">` : `<span class="cancion-disco">${ico('musica')}</span>`}
      <span><b>${esc(c.titulo)}</b><span>${esc(c.artista)}</span></span></button>`).join('');
  }
  function pintarResultados() { const c = $('#as-resultados'); if (c) c.innerHTML = htmlResultados(); }
  function buscarCancion(q) {
    clearTimeout(buscaT); const n = ++buscaN; q = q.trim();
    if (q.length < 3) { A.resultados = null; A.buscando = false; return pintarResultados(); }
    if (PREVIA) {   // la vista previa no puede salir a internet: muestra una lista de ejemplo
      const n2 = norm(q), ej = [['Fly Me to the Moon', 'Angelina Jordan'], ['What a Wonderful World', 'Louis Armstrong'], ['Viva la Vida', 'Coldplay'], ['Las Mañanitas', 'Tradicional']];
      const hay = ej.filter(([t, a2]) => norm(t + a2).includes(n2));
      A.buscando = false; A.resultados = (hay.length ? hay : ej).map(([titulo, artista]) => ({ titulo, artista, portada: '', previa: '', url: '' }));
      return pintarResultados();
    }
    A.buscando = true; pintarResultados();
    buscaT = setTimeout(async () => {
      const pedir = async pais => { const r = await fetch(`https://itunes.apple.com/search?term=${encodeURIComponent(q)}&entity=song&media=music&limit=6${pais}`); if (!r.ok) throw new Error('busqueda'); return (await r.json()).results || []; };
      let lista;
      try { lista = await pedir('&country=bo'); if (!lista.length) lista = await pedir(''); } catch { lista = null; }
      if (n !== buscaN || !A) return;
      A.buscando = false;
      A.resultados = !lista ? 'error' : lista.filter(x => x.trackName && x.artistName).map(x => ({ titulo: String(x.trackName).slice(0, 160), artista: String(x.artistName).slice(0, 160), portada: String(x.artworkUrl100 || '').replace('100x100', '300x300'), previa: x.previewUrl || '', url: x.trackViewUrl || '' }));
      pintarResultados();
    }, 450);
  }

  function abrirAsistente() {
    if (vistaPreviaEl) { tostada('Estás viendo la página como él. Sal de esa vista para publicar.'); return; }
    const soyEl = rol === 'homenajeado';
    A = { paso: (yo.nombre || soyEl) ? 2 : 1, subiendo: false, prog: 0, error: '', ...saludoVacio() };
    $('#asistente').hidden = false; document.body.style.overflow = 'hidden';
    pintarAsistente();
  }
  function cerrarAsistente() {
    detenerGrabacion(true);
    $('#asistente').hidden = true; document.body.style.overflow = '';
    A = null;
    if (pendientes) pintar();
  }
  function urlTemp(f) { if (!f._u) f._u = URL.createObjectURL(f); return f._u; }

  function htmlParte(t, varias) {
    let cuerpo = '';
    if (t.id === 'texto') {
      cuerpo = `<label class="campo"><span>${varias ? 'Lo que quieres decirle' : 'Tu mensaje'}</span><textarea id="as-texto" maxlength="6000" placeholder="Con calma. Puede ser corto.">${esc(A.texto)}</textarea></label>`;
    } else if (t.id === 'foto') {
      cuerpo = `<label class="soltar" ${A.fotos.length >= MAX_FOTOS ? 'hidden' : ''}>${ico('foto')}<b>${A.fotos.length ? 'Agregar más fotos' : 'Elegir fotos'}</b><small>De tu galería o tomadas ahora</small><input type="file" id="as-fotos" accept="image/*" multiple></label>
        ${A.fotos.length ? `<div class="miniaturas">${A.fotos.map((f, i) => `<div><img src="${urlTemp(f)}" alt="Foto ${i + 1}"><button type="button" data-accion="quitar-foto" data-i="${i}" aria-label="Quitar foto ${i + 1}">${ico('cerrar')}</button></div>`).join('')}</div>` : ''}`;
    } else if (t.id === 'video') {
      cuerpo = A.video
        ? `<div class="asistente-prev"><video src="${urlTemp(A.video)}" controls playsinline></video></div><button type="button" class="btn-texto" data-accion="quitar-video">Elegir otro video (${peso(A.video.size)})</button>`
        : `<label class="soltar">${ico('video')}<b>Elegir o grabar un video</b><small>Hasta 50 MB (más o menos un minuto)</small><input type="file" id="as-video" accept="video/*"></label>`;
    } else if (t.id === 'audio') {
      cuerpo = A.audio
        ? `<div class="asistente-prev"><audio src="${urlTemp(A.audio)}" controls></audio></div><button type="button" class="btn-texto" data-accion="quitar-audio">Grabar de nuevo</button>`
        : `<div class="grabadora"><button type="button" class="grabar ${grab ? 'grabando' : ''}" data-accion="grabar" aria-label="${grab ? 'Detener grabación' : 'Empezar a grabar'}">${ico('audio')}</button>
            <span class="reloj" id="as-reloj">${grab ? '00:00' : 'Toca para grabar'}</span>
            <small class="tenue">${grab ? 'Grabando… toca el cuadrado para terminar' : 'Máximo 5 minutos'}</small></div>
           <label class="btn-texto subir-alterno">O sube un audio que ya tengas<input type="file" id="as-audio" accept="audio/*" hidden></label>`;
    } else if (t.id === 'musica') {
      const enl = arreglarEnlace(A.enlace);
      const porEnlace = `<label class="campo"><span>Enlace de la canción o playlist</span><input type="text" id="as-enlace" inputmode="url" autocapitalize="none" autocorrect="off" spellcheck="false" placeholder="https://" value="${esc(A.enlace)}"><small>En YouTube o Spotify: Compartir → Copiar enlace. Luego pégalo aquí.</small></label>
        <div id="as-vista-enlace">${enl ? htmlEnlace(enl) : ''}</div>`;
      cuerpo = (A.cancion
        ? `${htmlCancion(A.cancion)}<button type="button" class="btn-texto" data-accion="quitar-cancion">Elegir otra canción</button>`
        : `<label class="campo"><span>Nombre de la canción o del artista</span><input type="text" id="as-busca" autocomplete="off" autocorrect="off" spellcheck="false" enterkeyhint="search" placeholder="Ej.: Fly me to the moon" value="${esc(A.busca)}"><small>Escribe y elige de la lista. No hace falta buscar ningún enlace.</small></label>
           <div id="as-resultados" class="resultados" aria-live="polite">${htmlResultados()}</div>`)
        + (A.verEnlace || A.enlace ? porEnlace : (A.cancion ? '' : `<button type="button" class="btn-texto subir-alterno" data-accion="ver-enlace">O pegar un enlace de YouTube o Spotify</button>`));
    }
    if (!varias) return cuerpo;
    return `<section class="parte"><div class="parte-cab"><b>${ico(t.ico)}${t.titulo}</b><button type="button" class="btn-texto" data-accion="quitar-tipo" data-tipo="${t.id}">Quitar</button></div>${cuerpo}</section>`;
  }

  function pintarAsistente() {
    const c = $('#as-cuerpo'), h = C.homenajeado, soyEl = rol === 'homenajeado';
    $$('#as-pasos li').forEach((li, i) => li.classList.toggle('hecho', i < Math.min(A.paso, 3)));
    $('#as-atras').style.visibility = (A.paso === 1 || A.paso === 4 || A.subiendo || (A.paso === 2 && soyEl)) ? 'hidden' : 'visible';
    let html = '';
    if (A.paso === 1) {
      html = `<form class="paso" data-form="quien" novalidate>
        <p class="rotulo">Paso 1 de 3</p><h2 id="as-titulo">¿Quién eres?</h2>
        <label class="campo"><span>Tu nombre</span><input type="text" id="as-nombre" maxlength="60" autocomplete="name" placeholder="Ej.: Tía Carmen" value="${esc(yo.nombre)}"><small>Así aparecerá junto a tu saludo.</small></label>
        <div class="campo"><span>¿Qué eres de ${esc(h.nombre)}? <small>(opcional)</small></span>
          <div class="chips">${RELACIONES.map(r => `<button type="button" class="chip" data-accion="relacion" data-rel="${r}" aria-pressed="${yo.relacion === r}">${r}</button>`).join('')}</div></div>
        <p class="error" id="as-error" role="alert" ${A.error ? '' : 'hidden'}>${esc(A.error)}</p>
        <button class="btn btn-haz btn-grande" type="submit">Continuar</button>
      </form>`;
    } else if (A.paso === 2) {
      const n = A.tipos.size;
      html = `<div class="paso">
        ${soyEl ? '' : `<div class="hola"><span>Hola, <b>${esc(yo.nombre)}</b></span><button type="button" class="btn-texto" data-accion="cambiar-nombre">Cambiar nombre</button></div>`}
        <p class="rotulo">${soyEl ? esc(C.textos.elAsistenteRotulo) : 'Paso 2 de 3'}</p><h2 id="as-titulo">${soyEl ? esc(C.textos.elAsistenteTitulo) : `¿Qué le quieres dejar a ${esc(h.nombre)}?`}</h2>
        <p class="ayuda">Elige una cosa o varias: van todas juntas en un mismo saludo.</p>
        <div class="opciones" role="group" aria-label="Qué incluir">${TIPOS.map(t => `<button type="button" class="opcion" data-accion="tipo" data-tipo="${t.id}" aria-pressed="${A.tipos.has(t.id)}">${ico(t.ico)}<span><b>${t.titulo}</b><span>${t.texto}</span></span><span class="casilla">${ico('check')}</span></button>`).join('')}</div>
        <div class="pie-paso"><button type="button" class="btn btn-haz btn-grande" id="as-continuar" data-accion="continuar-tipos" ${n ? '' : 'disabled'}>${n > 1 ? `Continuar con ${n} cosas` : 'Continuar'}</button></div>
      </div>`;
    } else if (A.paso === 3) {
      const lista = elegidos(), varias = lista.length > 1;
      html = `<form class="paso" data-form="saludo" novalidate>
        <p class="rotulo">${soyEl ? esc(C.textos.elAsistenteRotulo) : 'Paso 3 de 3'}</p><h2 id="as-titulo">${varias ? 'Arma tu saludo' : lista[0].titulo}</h2>
        ${lista.map(t => htmlParte(t, varias)).join('')}
        ${lista.length < TIPOS.length && !A.subiendo ? `<button type="button" class="btn-texto" data-accion="mas-tipos" style="justify-self:start">${ico('mas')}Agregar otra cosa a este saludo</button>` : ''}
        <p class="error" id="as-error" role="alert" ${A.error ? '' : 'hidden'}>${esc(A.error)}</p>
        ${A.subiendo ? `<div class="progreso" role="progressbar" aria-valuenow="${Math.round(A.prog * 100)}" aria-valuemin="0" aria-valuemax="100"><u id="as-prog" style="width:${Math.round(A.prog * 100)}%"></u></div><p class="tenue" id="as-estado">Enviando… no cierres esta ventana.</p>` : ''}
        <div class="pie-paso"><button class="btn btn-haz btn-grande" type="submit" ${A.subiendo ? 'disabled' : ''}>${ico('enviar')}${A.subiendo ? 'Enviando…' : soyEl ? 'Publicar' : 'Enviar mi saludo'}</button></div>
      </form>`;
    } else {
      html = `<div class="paso listo">${pieza('♞')}
        <p class="rotulo">${soyEl ? 'Transmisión enviada' : '¡Bazinga! Saludo enviado'}</p>
        <h2 id="as-titulo">${soyEl ? 'Publicado' : `¡Gracias, ${esc(yo.nombre)}!`}</h2>
        <p>${soyEl ? 'Ya lo pueden ver todos.' : `Tu saludo ya es parte del mosaico. ${esc(h.nombre)} lo verá el ${fechaDia(h.fecha)}.`}</p>
        <button type="button" class="btn btn-haz btn-grande" data-accion="ver-mosaico">Ver el mosaico</button>
        ${soyEl ? '' : `<button type="button" class="btn btn-grande" data-accion="otro-saludo">Dejar otro saludo</button>`}
      </div>`;
    }
    c.innerHTML = html; c.scrollTop = 0;
    const primero = c.querySelector(A.paso === 1 ? '#as-nombre' : 'h2');
    if (primero && primero.focus && !/Mobi|Android/i.test(navigator.userAgent)) { if (primero.tagName === 'H2') primero.tabIndex = -1; primero.focus({ preventScroll: true }); }
  }
  function errorAsistente(msg) { A.error = msg; const e = $('#as-error'); if (e) { e.textContent = msg; e.hidden = !msg; e.scrollIntoView({ block: 'center', behavior: 'smooth' }); } }

  // Achica las fotos antes de subirlas: cargan rápido y ocupan poco.
  async function achicar(archivo) {
    if (!/^image\/(jpeg|png|webp|heic|heif)$/i.test(archivo.type) && archivo.type) return archivo;
    try {
      const bmp = await createImageBitmap(archivo, { imageOrientation: 'from-image' });
      const k = Math.min(1, 1920 / Math.max(bmp.width, bmp.height));
      if (k === 1 && archivo.size < 900 * 1024 && /jpeg|webp/.test(archivo.type)) return archivo;
      const cv = document.createElement('canvas'); cv.width = Math.round(bmp.width * k); cv.height = Math.round(bmp.height * k);
      cv.getContext('2d').drawImage(bmp, 0, 0, cv.width, cv.height);
      const blob = await new Promise(r => cv.toBlob(r, 'image/jpeg', .86));
      return blob ? new File([blob], (archivo.name || 'foto').replace(/\.\w+$/, '') + '.jpg', { type: 'image/jpeg' }) : archivo;
    } catch { return archivo; }
  }

  async function enviarSaludo() {
    if (A.subiendo) return;
    sincronizar();
    if (grab) return errorAsistente('Termina la grabación primero: toca el cuadrado.');
    const con = k => A.tipos.has(k);
    const texto = con('texto') ? A.texto.trim() : '';
    const enlace = con('musica') ? arreglarEnlace(A.enlace) : '';
    const vacio = { texto: !texto, foto: !A.fotos.length, video: !A.video, audio: !A.audio, musica: !enlace && !A.cancion };
    const faltan = elegidos().filter(t => vacio[t.id]);
    if (faltan.length) return errorAsistente(A.tipos.size === 1 ? faltan[0].solo : `Te falta ${enLista(faltan.map(t => t.falta))}. Complétalo o quítalo de tu saludo.`);
    A.error = ''; A.subiendo = true; A.prog = 0; pintarAsistente();
    try {
      const archivos = [...(con('foto') ? await Promise.all(A.fotos.map(achicar)) : []), ...(con('video') ? [A.video] : []), ...(con('audio') ? [A.audio] : [])];
      const total = archivos.reduce((s, f) => s + f.size, 0) || 1;
      let hecho = 0; const adjuntos = [];
      for (const f of archivos) {
        const r = await api.subir(f, p => { A.prog = (hecho + p * f.size) / total; const u = $('#as-prog'); if (u) u.style.width = Math.round(A.prog * 100) + '%'; const e = $('#as-estado'); if (e) e.textContent = `Subiendo… ${Math.round(A.prog * 100)} %. No cierres esta ventana.`; });
        hecho += f.size; adjuntos.push(r);
      }
      if (con('musica') && A.cancion) adjuntos.push({ tipo: 'cancion', ...A.cancion });
      const soyEl = rol === 'homenajeado';
      const principal = ['video', 'audio', 'foto', 'musica', 'texto'].find(con);
      const fila = await api.publicar({ seccion: 'saludo', autor: soyEl ? C.homenajeado.nombre : yo.nombre, relacion: soyEl ? '' : yo.relacion, tipo: principal, mensaje: texto, enlace, adjuntos, homenajeado: soyEl });
      posts.push(fila); huella = '';
      A.subiendo = false; A.paso = 4; pintarAsistente();
      cargar(true);
    } catch (e) {
      A.subiendo = false; pintarAsistente(); errorAsistente(decirError(e));
    }
  }

  // ---------- grabadora de audio ----------
  async function alternarGrabacion() {
    if (grab) return detenerGrabacion(false);
    if (!navigator.mediaDevices || !window.MediaRecorder) return errorAsistente('Este navegador no permite grabar aquí. Graba el audio con tu teléfono y súbelo con el botón de abajo.');
    let flujo;
    try { flujo = await navigator.mediaDevices.getUserMedia({ audio: true }); }
    catch { return errorAsistente('No pudimos usar el micrófono. Dale permiso cuando el teléfono lo pida, o sube un audio ya grabado.'); }
    const tipo = ['audio/mp4', 'audio/webm;codecs=opus', 'audio/webm', 'audio/ogg'].find(t => MediaRecorder.isTypeSupported(t)) || '';
    const mr = new MediaRecorder(flujo, tipo ? { mimeType: tipo } : undefined);
    const trozos = []; const inicio = Date.now();
    mr.ondataavailable = e => { if (e.data.size) trozos.push(e.data); };
    mr.onstop = () => {
      flujo.getTracks().forEach(t => t.stop()); clearInterval(grab && grab.reloj);
      const descartar = grab && grab.descartar; grab = null;
      if (descartar || !A) return;
      const mime = (mr.mimeType || tipo || 'audio/webm').split(';')[0];
      A.audio = new File(trozos, `audio.${mime.includes('mp4') ? 'm4a' : mime.includes('ogg') ? 'ogg' : 'webm'}`, { type: mime });
      sincronizar(); A.error = ''; pintarAsistente();
    };
    grab = { mr, descartar: false, reloj: setInterval(() => {
      const s = Math.floor((Date.now() - inicio) / 1000); const r = $('#as-reloj'); if (r) r.textContent = `${dos(Math.floor(s / 60))}:${dos(s % 60)}`;
      if (s >= 300) detenerGrabacion(false);
    }, 500) };
    mr.start();
    sincronizar(); A.error = ''; pintarAsistente();
  }
  function detenerGrabacion(descartar) {
    if (!grab) return;
    grab.descartar = descartar;
    try { grab.mr.stop(); } catch { grab = null; }
  }

  // ---------- acciones ----------
  async function pedirNombre() {
    if (rol === 'homenajeado') return true;
    if (yo.nombre) return true;
    abrirAsistente(); A.soloNombre = true; pintarAsistente();
    return false;
  }
  async function publicarCorto(datos, claveBorrador) {
    try {
      const soyEl = rol === 'homenajeado';
      const fila = await api.publicar({ autor: soyEl ? C.homenajeado.nombre : yo.nombre, relacion: soyEl ? '' : yo.relacion, tipo: 'texto', homenajeado: soyEl, ...datos });
      posts.push(fila); huella = ''; delete borradores[claveBorrador];
      pintar(); cargar(true);
      return true;
    } catch (e) { tostada(decirError(e), 5000); return false; }
  }

  document.addEventListener('click', async ev => {
    const nav = ev.target.closest('[data-ir]');
    if (nav) { ev.preventDefault(); temaAbierto = nav.dataset.ir === 'foro' ? temaAbierto : null; ir(nav.dataset.ir); return; }
    const el = ev.target.closest('[data-accion]');
    if (!el) return;
    const acc = el.dataset.accion, id = el.dataset.id;
    switch (acc) {
      case 'saludar': abrirAsistente(); break;
      case 'filtrar': filtro = el.dataset.filtro; pintar(); break;
      case 'refrescar': pintar(); break;
      case 'ver-foto': $('#visor-img').src = el.dataset.url; $('#visor').hidden = false; break;
      case 'tocar-cancion':
        $('#cancion-caja').innerHTML = `<div class="reproductor"><iframe src="https://www.youtube-nocookie.com/embed/${encodeURIComponent(el.dataset.yt)}?autoplay=1&rel=0" title="Canción en YouTube" allow="autoplay; encrypted-media; fullscreen; picture-in-picture" allowfullscreen referrerpolicy="strict-origin-when-cross-origin"></iframe></div>`;
        break;
      case 'megusta': {
        if (vistaPreviaEl) break;
        const p = posts.find(x => x.id === id); if (!p) break;
        p.megusta = !p.megusta; p.likes = Math.max(0, (p.likes || 0) + (p.megusta ? 1 : -1)); huella = '';
        el.classList.toggle('activo', p.megusta); el.setAttribute('aria-pressed', p.megusta); el.querySelector('span').textContent = p.likes || 'Me encanta';
        try { const r = await api.megusta(id); p.megusta = r.megusta; p.likes = r.likes; } catch (e) { tostada(decirError(e)); }
        break;
      }
      case 'abrir-respuesta':
        abiertos.has(id) ? abiertos.delete(id) : abiertos.add(id); pintar();
        if (abiertos.has(id)) { const t = $('#r-' + id); if (t) t.focus(); }
        break;
      case 'borrar':
      case 'moderar': {
        const que = el.dataset.que || 'borrar';
        if (que === 'borrar' && el.dataset.seguro !== '1') {
          el.dataset.seguro = '1'; const s = el.querySelector('span') || el; const antes = s.textContent; const eraOculto = s.classList.contains('solo-lector');
          s.textContent = '¿Seguro? Toca otra vez'; s.classList.remove('solo-lector');
          setTimeout(() => { if (el.isConnected) { el.dataset.seguro = ''; s.textContent = antes; s.classList.toggle('solo-lector', eraOculto); } }, 3500); break;
        }
        try {
          acc === 'moderar' ? await api.moderar(id, que) : await api.borrar(id);
          tostada(que === 'borrar' ? 'Borrado' : que === 'ocultar' ? 'Oculto: ya solo lo ves tú' : 'Visible otra vez');
          await cargar(true);
        } catch (e) { tostada(decirError(e)); }
        break;
      }
      case 'abrir-tema': temaAbierto = el.dataset.tema; pintar(); window.scrollTo(0, document.body.scrollHeight); break;
      case 'cerrar-tema': temaAbierto = null; pintar(); window.scrollTo(0, 0); break;
      case 'quitar-adjunto-foro': delete adjuntoForo[temaAbierto]; pintar(); break;
      case 'copiar': {
        const t = el.dataset.texto;
        try { await navigator.clipboard.writeText(t); tostada('Copiado. Pégalo en WhatsApp.'); }
        catch { const ta = document.createElement('textarea'); ta.value = t; document.body.appendChild(ta); ta.select(); try { document.execCommand('copy'); tostada('Copiado.'); } catch { tostada('Mantén presionado el enlace para copiarlo.'); } ta.remove(); }
        break;
      }
      case 'ver-como-el': vistaPreviaEl = true; mostrarTelon(); ir('inicio'); pintarSalirVista(); break;
      case 'salir-vista': vistaPreviaEl = false; pintarSalirVista(); ir('panel'); break;
      case 'salir-admin': guarda.del('admin'); claveAdmin = ''; esAdmin = false; await cargar(true); ir('inicio'); tostada('Saliste del modo organizadora'); break;
      case 'respaldo': {
        const blob = new Blob([JSON.stringify({ exportado: new Date().toISOString(), posts }, null, 2)], { type: 'application/json' });
        const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `saludos-${fechaDia(C.homenajeado.fecha).replace(/\//g, '-')}.json`; a.click();
        break;
      }
      // asistente
      case 'relacion': yo.relacion = yo.relacion === el.dataset.rel ? '' : el.dataset.rel; $$('[data-accion="relacion"]').forEach(b => b.setAttribute('aria-pressed', b.dataset.rel === yo.relacion)); break;
      case 'cambiar-nombre': A.paso = 1; pintarAsistente(); break;
      case 'tipo': {
        const k = el.dataset.tipo; A.tipos.has(k) ? A.tipos.delete(k) : A.tipos.add(k);
        el.setAttribute('aria-pressed', A.tipos.has(k));
        const b = $('#as-continuar'); if (b) { b.disabled = !A.tipos.size; b.textContent = A.tipos.size > 1 ? `Continuar con ${A.tipos.size} cosas` : 'Continuar'; }
        break;
      }
      case 'continuar-tipos': if (A.tipos.size) { A.paso = 3; A.error = ''; pintarAsistente(); } break;
      case 'mas-tipos': sincronizar(); detenerGrabacion(true); A.paso = 2; A.error = ''; pintarAsistente(); break;
      case 'quitar-tipo': sincronizar(); if (el.dataset.tipo === 'audio') detenerGrabacion(true); A.tipos.delete(el.dataset.tipo); A.error = ''; pintarAsistente(); break;
      case 'quitar-foto': sincronizar(); A.fotos.splice(+el.dataset.i, 1); pintarAsistente(); break;
      case 'quitar-video': sincronizar(); A.video = null; pintarAsistente(); break;
      case 'quitar-audio': sincronizar(); A.audio = null; pintarAsistente(); break;
      case 'elegir-cancion': sincronizar(); A.cancion = A.resultados[+el.dataset.i] || null; A.error = ''; pintarAsistente(); break;
      case 'quitar-cancion': sincronizar(); A.cancion = null; pintarAsistente(); break;
      case 'ver-enlace': sincronizar(); A.verEnlace = true; pintarAsistente(); break;
      case 'grabar': sincronizar(); alternarGrabacion(); break;
      case 'ver-mosaico': cerrarAsistente(); ir('mosaico'); break;
      case 'otro-saludo': Object.assign(A, saludoVacio(), { paso: 2, error: '' }); pintarAsistente(); break;
      case 'ir-pieza': {
        const d = el.dataset;
        if (d.destino === 'saludar') { abrirAsistente(); break; }
        if (d.destino === 'foro') { temaAbierto = d.tema; ir('foro'); break; }
        if (d.destino === 'carta') { ir('inicio', false); const c = $('.carta'); if (c) c.scrollIntoView({ block: 'start' }); break; }
        filtro = 'todos'; ir('saludos', false);
        const c = d.id && document.getElementById('p-' + d.id);
        if (c) { c.scrollIntoView({ block: 'center' }); c.classList.add('destacada'); setTimeout(() => c.classList.remove('destacada'), 2400); } else window.scrollTo(0, 0);
        break;
      }
    }
  });

  document.addEventListener('submit', async ev => {
    const f = ev.target.closest('[data-form]'); if (!f) return;
    ev.preventDefault();
    const tipo = f.dataset.form;
    if (tipo === 'quien') {
      const n = $('#as-nombre').value.trim();
      if (n.length < 2) return errorAsistente('Escribe tu nombre para continuar.');
      yo.nombre = n.slice(0, 60); guarda.set('nombre', yo.nombre); guarda.set('relacion', yo.relacion || '');
      if (A.soloNombre) { cerrarAsistente(); tostada(`Listo, ${yo.nombre}. Ya puedes enviar tu mensaje.`); return; }
      A.paso = 2; A.error = ''; pintarAsistente();
    } else if (tipo === 'saludo') {
      enviarSaludo();
    } else if (tipo === 'respuesta') {
      if (vistaPreviaEl) return tostada('Estás viendo la página como él.');
      const t = f.querySelector('textarea'), msg = t.value.trim(); if (!msg) return t.focus();
      if (!(await pedirNombre())) return;
      f.querySelector('button').disabled = true;
      await publicarCorto({ seccion: 'respuesta', parent: f.dataset.id, mensaje: msg }, 'r-' + f.dataset.id);
    } else if (tipo === 'foro') {
      if (vistaPreviaEl) return tostada('Estás viendo la página como él.');
      const tema = f.dataset.tema, t = f.querySelector('textarea'), msg = t.value.trim(), foto = adjuntoForo[tema];
      if (!msg && !foto) return t.focus();
      if (!(await pedirNombre())) return;
      f.querySelector('button[type="submit"]').disabled = true;
      let adjuntos = [];
      try { if (foto) { tostada('Subiendo la foto…', 20000); adjuntos = [await api.subir(await achicar(foto))]; } }
      catch (e) { tostada(decirError(e), 5000); f.querySelector('button[type="submit"]').disabled = false; return; }
      const ok = await publicarCorto({ seccion: 'foro', tema, mensaje: msg, adjuntos, tipo: foto ? 'foto' : 'texto' }, 'f-' + tema);
      if (ok) { delete adjuntoForo[tema]; pintar(); window.scrollTo(0, document.body.scrollHeight); if (foto) tostada('Enviado'); }
    }
  });

  document.addEventListener('input', ev => {
    const t = ev.target;
    if (t.dataset && t.dataset.borrador) { borradores[t.dataset.borrador] = t.value; t.style.height = 'auto'; t.style.height = Math.min(220, Math.max(52, t.scrollHeight + 2)) + 'px'; }
    if (!A) return;
    if (t.id === 'as-texto') A.texto = t.value;
    if (t.id === 'as-busca') { A.busca = t.value; buscarCancion(t.value); }
    if (t.id === 'as-enlace') { A.enlace = t.value; const enl = arreglarEnlace(t.value); clearTimeout(pintarAsistente._t); pintarAsistente._t = setTimeout(() => { const v = $('#as-vista-enlace'); if (v) v.innerHTML = enl ? htmlEnlace(enl) : ''; }, 500); }
  });
  document.addEventListener('change', ev => {
    const t = ev.target;
    if (t.id === 'foro-foto' && t.files[0]) { adjuntoForo[temaAbierto] = t.files[0]; pintar(); return; }
    if (!A) return;
    sincronizar();
    if (t.id === 'as-fotos') {
      const nuevas = [...t.files].filter(f => f.type.startsWith('image/') || !f.type);
      const sobran = A.fotos.length + nuevas.length > MAX_FOTOS;
      A.fotos = A.fotos.concat(nuevas).slice(0, MAX_FOTOS); A.error = '';
      pintarAsistente();
      if (sobran) errorAsistente(`Caben hasta ${MAX_FOTOS} fotos por saludo. Puedes dejar otro saludo con las demás.`);
    } else if (t.id === 'as-video' && t.files[0]) {
      const f = t.files[0];
      if (f.size > MAX_VIDEO) { pintarAsistente(); return errorAsistente(`Ese video pesa ${peso(f.size)} y el máximo es 50 MB. Prueba con uno más corto, o súbelo a YouTube y pega el enlace en "Una canción".`); }
      A.video = f; A.error = ''; pintarAsistente();
    } else if (t.id === 'as-audio' && t.files[0]) {
      if (t.files[0].size > MAX_VIDEO) return errorAsistente('Ese audio pesa más de 50 MB.');
      A.audio = t.files[0]; A.error = ''; pintarAsistente();
    }
  });
  $('#as-cerrar').addEventListener('click', () => { if (A && A.subiendo) return tostada('Espera a que termine de enviarse.'); cerrarAsistente(); });
  $('#as-atras').addEventListener('click', () => {
    if (!A || A.subiendo) return;
    detenerGrabacion(true);
    sincronizar();
    if (A.paso === 3) A.paso = 2; else if (A.paso === 2) A.paso = 1;
    A.error = ''; pintarAsistente();
  });
  $('#visor').addEventListener('click', () => { $('#visor').hidden = true; $('#visor-img').src = ''; });
  document.addEventListener('keydown', ev => {
    if (ev.key === 'Enter' && ev.target.id === 'as-busca') { ev.preventDefault(); return; }
    if (ev.key !== 'Escape') return;
    if (!$('#visor').hidden) $('#visor').hidden = true;
    else if (A && !A.subiendo) cerrarAsistente();
  });
  window.addEventListener('hashchange', () => { const v = location.hash.slice(1); if (C && v !== vista && !v.includes('=')) ir(v); });

  // ---------- telón del homenajeado ----------
  function mostrarTelon() {
    const T = C.textos, h = C.homenajeado, n = posts.filter(p => p.seccion === 'saludo' && !p.oculto).length;
    $('#telon-rotulo').textContent = fechaDia(h.fecha);
    $('#telon-intro').textContent = T.telonIntro;
    $('#telon-firma').textContent = T.telonFirma;
    $('#telon-titulo').textContent = `${T.elTitulo} ${h.nombre}`;
    $('#telon-texto').textContent = n ? T.telon.replace('{saludos}', plural(n, 'saludo', 'saludos')) : T.telonVacio;
    const t = $('#telon'); t.classList.remove('saliendo'); t.hidden = false;
  }
  $('#telon-abrir').addEventListener('click', () => {
    const t = $('#telon'); t.classList.add('saliendo'); setTimeout(() => { t.hidden = true; }, 750);
    try { sessionStorage.setItem('rn_telon', '1'); } catch { /* */ }
  });
  function pintarSalirVista() {
    let b = $('#salir-vista');
    if (!vistaPreviaEl) { if (b) b.remove(); return; }
    if (!b) { b = document.createElement('button'); b.id = 'salir-vista'; b.type = 'button'; b.className = 'btn btn-sodio btn-chico salir-vista'; b.dataset.accion = 'salir-vista'; b.textContent = 'Salir de la vista de él'; document.body.appendChild(b); }
  }

  // ---------- las gatas, Pura y Tapioca: aparecen de rato en rato, porque sí ----------
  const gatos = (() => {
    const PELAJE = {
      pura: { nombre: 'Pura', base: '#9a8b78', medio: '#84766a', sombra: '#6d6055', raya: '#2f2620', claro: '#e9dcc6', crema: '#f4ead8', pata: '#a59682', oreja: '#d9a79a', nariz: '#b8604c', narizBorde: '#3a2a22', ojo: '#b6c182', ojoBorde: '#2a211b', bigote: '#fffaf0', contorno: 'none' },
      tapioca: { nombre: 'Tapioca', base: '#1d1b20', medio: '#2b282e', sombra: '#0c0b0e', raya: '#1d1b20', claro: '#fbfaf6', crema: '#fbfaf6', pata: '#fbfaf6', oreja: '#5a3f47', nariz: '#2a2428', narizBorde: '#0c0b0e', ojo: '#a9c98a', ojoBorde: '#0c0b0e', bigote: '#ffffff', contorno: '#b9b4ab' }
    };

    // Cabeza de frente. Origen en el centro de la cara; mide unos 92 x 96.
    function cabeza(k) {
      const p = PELAJE[k], T = k === 'tapioca';
      const ojo = s => `<g transform="translate(${s * 19} -3)">
          <path d="M-13 1C-8 -8 6 -9 13 0C7 8 -7 9 -13 1Z" fill="${p.ojo}" stroke="${p.ojoBorde}" stroke-width="1.8" stroke-linejoin="round" transform="scale(${s} 1)"/>
          <ellipse cx="0" cy="0" rx="${T ? 3.6 : 2.6}" ry="6.2" fill="#0d0b0a"/>
          <circle cx="${2.2}" cy="-2.6" r="1.5" fill="#fff" opacity=".9"/>
          ${T ? `<path d="M-15 -11H15V-2.200C7 -4.200 -7 -4.200 -15 -1.600Z" fill="${p.base}"/><path d="M-13.500 -1.900C-7 -4.300 7 -4.300 13.500 -2.300" fill="none" stroke="${p.ojoBorde}" stroke-width="1.600" stroke-linecap="round"/>` : ''}
        </g>`;
      const marcas = T
        ? `<path d="M0 -8C-3 4 -16 13 -27 24C-25 38 -12 45 0 46C12 45 25 38 27 24C16 13 3 4 0 -8Z" fill="${p.claro}"/>
           <path d="M-1.500 -30C-2.500 -20 -1.500 -12 0 -8C1.500 -12 2.500 -20 1.500 -30Z" fill="${p.claro}" opacity=".85"/>
           <path d="M-8 6C-4 2 4 2 8 6C6 14 -6 14 -8 6Z" fill="${p.base}"/>`
        : `<path d="M-13 -36L-11 -20M0 -38V-21M13 -36L11 -20M-25 -30C-21 -26 -19 -20 -19 -15M25 -30C21 -26 19 -20 19 -15" fill="none" stroke="${p.raya}" stroke-width="3" stroke-linecap="round"/>
           <path d="M-33 -1C-39 2 -43 8 -45 14M33 -1C39 2 43 8 45 14M-44 22C-38 21 -33 23 -29 27M44 22C38 21 33 23 29 27M-41 31C-36 31 -32 33 -29 36M41 31C36 31 32 33 29 36" fill="none" stroke="${p.raya}" stroke-width="2.600" stroke-linecap="round"/>
           <path d="M-34 -4C-26 -16 -8 -16 -4 -4C-8 8 -28 8 -34 -4ZM34 -4C26 -16 8 -16 4 -4C8 8 28 8 34 -4Z" fill="${p.claro}" opacity=".55"/>
           <path d="M0 4C-12 8 -24 16 -24 26C-22 38 -10 44 0 44C10 44 22 38 24 26C24 16 12 8 0 4Z" fill="${p.crema}"/>`;
      const bigotes = (T
        ? ['M-14 22L-62 8', 'M-15 25L-66 22', 'M-15 28L-63 36', 'M-13 31L-54 48', 'M-25 -15L-40 -33', 'M-20 -16L-31 -37']
        : ['M-15 23L-58 14', 'M-15 26L-60 27', 'M-14 29L-55 40', 'M-22 -15L-36 -34'])
        .map(d => `<path d="${d}"/><path d="${d}" transform="scale(-1 1)"/>`).join('');
      return `
        <path d="M-45 -6C-47 -22 -47 -40 -42 -57C-30 -52 -19 -43 -12 -33Z" fill="${p.base}"/>
        <path d="M45 -6C47 -22 47 -40 42 -57C30 -52 19 -43 12 -33Z" fill="${p.base}"/>
        <path d="M-40 -18C-41 -30 -40 -40 -38 -48C-30 -43 -23 -37 -18 -30Z" fill="${p.oreja}"/>
        <path d="M40 -18C41 -30 40 -40 38 -48C30 -43 23 -37 18 -30Z" fill="${p.oreja}"/>
        <path d="M-36 -22L-30 -36M-32 -19L-25 -32M36 -22L30 -36M32 -19L25 -32" fill="none" stroke="${T ? p.medio : p.crema}" stroke-width="1.600" stroke-linecap="round" opacity=".8"/>
        <path d="M0 -38C20 -38 40 -28 45 -8C49 6 46 20 38 30C28 42 14 47 0 47C-14 47 -28 42 -38 30C-46 20 -49 6 -45 -8C-40 -28 -20 -38 0 -38Z" fill="${p.base}"/>
        ${marcas}${ojo(-1)}${ojo(1)}
        <path d="M-6.500 12C-3 10.500 3 10.500 6.500 12C5 17.500 1.500 19.500 0 19.500C-1.500 19.500 -5 17.500 -6.500 12Z" fill="${p.nariz}" stroke="${p.narizBorde}" stroke-width="1.200" stroke-linejoin="round"/>
        ${T ? `<path d="M-3 12.500C-1 11.800 1.500 11.800 3 12.600" fill="none" stroke="#8d868c" stroke-width="1.400" stroke-linecap="round"/>` : ''}
        <path d="M0 19.500V25M0 25C-3 31 -10 31 -13 26M0 25C3 31 10 31 13 26" fill="none" stroke="${T ? '#3b3338' : '#4a372d'}" stroke-width="1.500" stroke-linecap="round" stroke-linejoin="round"/>
        <g fill="none" stroke="${p.bigote}" stroke-width="1.100" stroke-linecap="round" opacity=".95">${bigotes}</g>`;
    }

    // Sentada, erguida y mirando de frente, como en la foto de Pura.
    function sentada(k) {
      const p = PELAJE[k], T = k === 'tapioca';
      const linea = T ? p.medio : p.sombra;
      const pelaje = T
        ? `<path d="M68 100C60 124 68 152 84 166C92 172 100 172 108 166C124 152 132 124 124 100C106 110 86 110 68 100Z" fill="${p.claro}"/>`
        : `<path d="M72 106C66 126 70 152 82 170C90 176 100 176 108 170C118 152 120 126 116 106C102 112 86 112 72 106Z" fill="${p.claro}" opacity=".38"/>
           <path d="M66 118C84 129 104 129 122 118M64 134C84 146 106 146 124 134" fill="none" stroke="${p.raya}" stroke-width="3" stroke-linecap="round"/>
           <path d="M136 132C150 150 156 172 152 196M150 152C162 170 166 192 162 214M124 120C136 140 140 164 138 186M54 132C50 146 50 160 52 172" fill="none" stroke="${p.raya}" stroke-width="3.400" stroke-linecap="round"/>`;
      const pata = x => `<path d="M${x + 2} 150C${x} 182 ${x + 1} 214 ${x} 238C${x + 1} 248 ${x + 25} 248 ${x + 26} 238C${x + 25} 214 ${x + 26} 182 ${x + 24} 150Z" fill="${p.base}" stroke="${linea}" stroke-width="1.600" stroke-linejoin="round"/>
          ${T ? `<path d="M${x + .5} 218C${x} 228 ${x} 234 ${x} 238C${x + 1} 248 ${x + 25} 248 ${x + 26} 238C${x + 26} 230 ${x + 26} 224 ${x + 25.500} 218C${x + 17} 214 ${x + 9} 214 ${x + .5} 218Z" fill="${p.pata}" stroke="${p.contorno}" stroke-width="1.200"/>`
              : `<path d="M${x + 2} 172H${x + 24}M${x + 1.500} 188H${x + 24.500}M${x + 1} 204H${x + 25}M${x + 1} 220H${x + 25}" fill="none" stroke="${p.raya}" stroke-width="3" stroke-linecap="round"/>`}
          <path d="M${x + 9} 240V246M${x + 17} 240V246" fill="none" stroke="${T ? '#c9c4bb' : p.sombra}" stroke-width="1.400" stroke-linecap="round"/>`;
      return `<svg viewBox="0 -10 200 260" width="100%">
        <path class="cola" d="M168 238C150 246 126 246 108 240" fill="none" stroke="${p.base}" stroke-width="13" stroke-linecap="round"/>
        ${T ? '' : `<path class="cola" d="M168 238C150 246 126 246 108 240" fill="none" stroke="${p.raya}" stroke-width="13" stroke-dasharray="5 9" stroke-dashoffset="4"/>`}
        <g class="cuerpo-gato">
          <path d="M62 96C48 118 44 160 50 204L54 244H160C178 236 184 204 174 172C164 140 144 112 130 96Z" fill="${p.base}"/>
          <path d="M128 100C146 118 162 146 170 176C178 204 174 232 160 244H132C150 218 150 160 128 100Z" fill="${p.sombra}" opacity="${T ? .5 : .28}"/>
          ${pelaje}${pata(60)}${pata(88)}
          <path d="M62 96C78 110 112 110 130 96C118 90 76 90 62 96Z" fill="${p.sombra}" opacity=".3"/>
          <g transform="translate(96 56)">${cabeza(k)}</g>
        </g></svg>`;
    }

    // Caminando de lado, con la cabeza vuelta hacia quien mira.
    function paseando(k) {
      const p = PELAJE[k], T = k === 'tapioca';
      const pata = (x, lejos, fase, trasera) => {
        const col = lejos ? p.sombra : p.base;
        const forma = trasera
          ? 'M-13 -6C-16 12 -3 24 -7 40C-9 50 -7 58 -8 63C-9 66 -11 67 -11 69H9C10 64 6 61 6 55C6 44 13 30 13 12C13 4 11 -2 9 -8Z'
          : 'M-8 -2C-9 20 -4 38 -6 56C-7 61 -9 63 -9 65H9C10 61 7 59 6 54C6 38 9 20 8 -2Z';
        const y = trasera ? 52 : 48, fin = trasera ? 69 : 65;
        return `<g transform="translate(${x} ${trasera ? 98 : 102})"><g class="pata ${fase}">
          <path d="${forma}" fill="${col}"/>
          ${T ? `<path d="M-7.500 ${y}C-9 ${y + 8} -10 ${fin - 3} -10 ${fin}H9C10 ${fin - 4} 7 ${fin - 6} 6.500 ${y}Z" fill="${lejos ? '#d5d1c8' : p.pata}"/>`
              : `<path d="M-7 ${trasera ? 30 : 16}H7M-6.500 ${trasera ? 42 : 28}H6.500M-6.500 ${trasera ? 53 : 40}H6.500" fill="none" stroke="${p.raya}" stroke-width="2.800" stroke-linecap="round" opacity="${lejos ? .45 : 1}"/>`}
        </g></g>`;
      };
      const pelaje = T
        ? `<path d="M176 114C172 98 188 82 208 84C216 96 212 110 198 118C190 122 180 120 176 114Z" fill="${p.claro}"/>`
        : `<path d="M92 66C86 82 88 100 94 112M108 62C102 80 103 100 109 114M124 61C118 80 119 100 125 115M140 61C134 80 135 100 141 115M156 62C151 80 152 98 157 113M172 65C168 80 169 95 173 107" fill="none" stroke="${p.raya}" stroke-width="3.600" stroke-linecap="round"/>
           <path d="M70 108C100 121 160 121 198 106C190 118 150 124 112 122C92 122 76 116 70 108Z" fill="${p.claro}" opacity=".5"/>`;
      return `<svg viewBox="0 0 260 178" width="100%">
        <path class="cola" d="M70 86C44 84 28 62 34 34C36 24 46 22 48 32" fill="none" stroke="${p.base}" stroke-width="12" stroke-linecap="round"/>
        ${T ? '' : `<path class="cola" d="M70 86C44 84 28 62 34 34C36 24 46 22 48 32" fill="none" stroke="${p.raya}" stroke-width="12" stroke-dasharray="5 10" stroke-dashoffset="2"/>`}
        ${pata(92, true, 'b', true)}${pata(182, true, '', false)}
        <g class="tronco">
          <path d="M62 84C74 62 110 57 150 59C178 59 202 64 210 80C216 96 208 112 192 118C172 125 132 119 110 121C88 123 64 117 58 103C56 96 58 89 62 84Z" fill="${p.base}"/>
          ${pelaje}
        </g>
        ${pata(76, false, '', true)}${pata(196, false, 'b', false)}
        <g class="tronco"><g transform="translate(214 56) scale(.66)">${cabeza(k)}</g></g></svg>`;
    }

    const caja = $('#gatos');
    const sinMovimiento = matchMedia('(prefers-reduced-motion: reduce)').matches;
    let actual = null, reloj = null;   // la escena en curso
    function quitar() {
      if (!actual) return;
      cancelAnimationFrame(actual.raf); clearTimeout(actual.t); (actual.tiempos || []).forEach(clearTimeout);
      actual.els.forEach(e => e.remove()); actual = null;
    }
    function decir(el, txt, ms = 1700) {
      let g = el.querySelector('.globito');
      if (!g) { g = document.createElement('span'); g.className = 'globito'; el.appendChild(g); }
      g.textContent = txt; clearTimeout(g._t); if (ms) g._t = setTimeout(() => g.remove(), ms);
      g.style.marginLeft = '0px';   // que el globito no se salga de la pantalla
      const r = g.getBoundingClientRect();
      g.style.marginLeft = (Math.min(0, innerWidth - 8 - r.right) + Math.max(0, 8 - r.left)) + 'px';
    }
    function botonCerca() {
      const raiz = !$('#asistente').hidden ? $('#asistente') : $('#app');
      const c = $$('.cta-circulo, .btn-haz, .btn-grande, .tema, .hueco.w2, .chip', raiz).filter(b => {
        const r = b.getBoundingClientRect();
        return r.width >= 56 && r.top > 150 && r.bottom <= innerHeight && r.left >= 0 && r.right <= innerWidth;
      });
      return c.length ? c[Math.floor(Math.random() * c.length)] : null;
    }
    function crear(k, clase, svg) {
      const el = document.createElement('div');
      el.className = 'gato ' + clase; el.innerHTML = svg;
      el.addEventListener('click', () => decir(el, `¡Miau! Soy ${PELAJE[k].nombre}`, 2000));
      caja.appendChild(el); return el;
    }
    function pasear(k) {
      const el = crear(k, 'pasea' + (Math.random() < .5 ? ' izq' : ''), paseando(k));
      el.style.setProperty('--dur', (11 + innerWidth / 130) + 's');
      el.addEventListener('animationend', ev => { if (ev.animationName.startsWith('pasear')) quitar(); });
      el.addEventListener('click', () => { el.classList.add('quieto'); setTimeout(() => el.classList.remove('quieto'), 2000); });
      actual = { els: [el] };
    }
    function sentar(k, boton) {
      const el = crear(k, 'sentado', sentada(k));
      const escena = { els: [el] }; actual = escena;
      decir(el, 'prrr…', 0);
      const irse = () => { if (actual !== escena) return; el.classList.add('yendose'); escena.t = setTimeout(() => { if (actual === escena) quitar(); }, 420); };
      const seguir = () => {
        if (actual !== escena) return;
        const r = boton.isConnected ? boton.getBoundingClientRect() : null;
        if (!r || !r.width || r.top < 110 || r.bottom > innerHeight + 8) return irse();
        el.style.left = (boton.classList.contains('cta-circulo') ? r.left + (r.width - el.offsetWidth) / 2 : Math.max(4, r.right - el.offsetWidth - Math.min(18, r.width * .12))) + 'px';
        el.style.top = (r.top - el.offsetHeight + 7) + 'px';
        escena.raf = requestAnimationFrame(seguir);
      };
      escena.t = setTimeout(irse, 7500);
      seguir();
    }
    // Entran por lados opuestos, chocan, juegan (una salta por encima de la otra) y una sale corriendo con la otra detrás.
    function jugar() {
      const [k1, k2] = Math.random() < .5 ? ['pura', 'tapioca'] : ['tapioca', 'pura'];
      let L = crear(k1, 'suelto', paseando(k1)), R = crear(k2, 'suelto izq', paseando(k2));   // L mira a la derecha; R, a la izquierda
      const escena = { els: [L, R], tiempos: [] }; actual = escena;
      const W = innerWidth, w = L.offsetWidth, alto = L.offsetHeight;
      const cabe = W - 1.85 * w >= .7 * w;            // ¿hay sitio para saltar por encima?
      const saltaL = Math.random() < .5;
      let centro = W * (.38 + Math.random() * .24);
      if (cabe) centro = saltaL ? Math.min(Math.max(W * (.3 + Math.random() * .2), .7 * w), W - 1.85 * w) : Math.max(Math.min(W * (.5 + Math.random() * .2), W - .7 * w), 1.85 * w);
      let xL = centro - w * .93, xR = centro - w * .07;      // hocico con hocico
      const viva = () => actual === escena;
      const mover = (el, de, hasta, ms, curva = 'linear') => el.animate([{ transform: `translateX(${de}px)` }, { transform: `translateX(${hasta}px)` }], { duration: Math.max(200, ms), easing: curva, fill: 'forwards' }).finished;
      const salto = (el, x, dx, h, ms) => el.animate([{ transform: `translate(${x}px, 0)` }, { transform: `translate(${x + dx}px, ${-h}px)`, offset: .45 }, { transform: `translate(${x}px, 0)` }], { duration: ms, easing: 'ease-out', fill: 'forwards' }).finished;
      const brinco = (el, de, hasta, h, ms) => el.animate([{ transform: `translate(${de}px, 0)`, easing: 'cubic-bezier(.3, .6, .6, 1)' }, { transform: `translate(${(de + hasta) / 2}px, ${-h}px)`, easing: 'cubic-bezier(.4, 0, .7, .4)' }, { transform: `translate(${hasta}px, 0)` }], { duration: ms, fill: 'forwards' }).finished;
      const pausa = ms => new Promise(r => escena.tiempos.push(setTimeout(r, ms)));
      const chispa = x => { const c = document.createElement('span'); c.className = 'chispa'; c.textContent = '✦'; c.style.left = x + 'px'; caja.appendChild(c); escena.els.push(c); escena.tiempos.push(setTimeout(() => c.remove(), 480)); };
      const choque = () => { chispa(xL + w * .93); return Promise.all([salto(L, xL, -24, 16, 430), salto(R, xR, 24, 16, 430)]); };
      L.style.transform = `translateX(${-w - 20}px)`; R.style.transform = `translateX(${W + 20}px)`;
      (async () => {
        const v = .12;   // píxeles por milisegundo
        await Promise.all([mover(L, -w - 20, xL, (xL + w + 20) / v), mover(R, W + 20, xR, (W + 20 - xR) / v)]);
        if (!viva()) return;
        L.classList.add('quieto'); R.classList.add('quieto');
        await choque(); if (!viva()) return;
        decir(L, '¡miau!', 900); await salto(L, xL, 14, 22, 440); if (!viva()) return;
        decir(R, '¡mrrau!', 900); await salto(R, xR, -14, 22, 440); if (!viva()) return;
        if (cabe) {
          await pausa(180); if (!viva()) return;
          if (saltaL) { const x = xR + w * .86; decir(L, '¡hop!', 800); await brinco(L, xL, x, alto * .95, 720); xL = xR; xR = x; }
          else { const x = xL - w * .86; decir(R, '¡hop!', 800); await brinco(R, xR, x, alto * .95, 720); xR = xL; xL = x; }
          if (!viva()) return;
          L.classList.add('izq'); R.classList.remove('izq'); [L, R] = [R, L];   // se dan la vuelta y quedan otra vez de frente
          await pausa(260); if (!viva()) return;
          await choque(); if (!viva()) return;
        }
        await salto(L, xL, 16, 28, 430); if (!viva()) return;
        await salto(R, xR, -12, 32, 460); if (!viva()) return;
        await pausa(250); if (!viva()) return;
        const aDer = Math.random() < .5, huye = aDer ? R : L, sigue = aDer ? L : R, meta = aDer ? W + 40 : -w - 40;
        const xh = aDer ? xR : xL, xs = aDer ? xL : xR;
        huye.classList.toggle('izq', !aDer); huye.classList.remove('quieto'); huye.classList.add('corre'); decir(huye, '¡a que no me alcanzas!', 1300);
        const huida = mover(huye, xh, meta, Math.abs(meta - xh) / .3, 'ease-in');
        await pausa(320); if (!viva()) return;
        sigue.classList.remove('quieto'); sigue.classList.add('corre');
        await Promise.all([huida, mover(sigue, xs, meta, Math.abs(meta - xs) / .28, 'ease-in')]);
        if (viva()) quitar();
      })().catch(() => { if (viva()) quitar(); });
    }
    function aparecer(k, modo) {
      if (actual) quitar();
      // Mientras alguien arma su saludo, las gatas no interceptan los toques
      caja.classList.toggle('pasivo', !$('#asistente').hidden);
      if (modo === 'jugar' || (!modo && !k && !sinMovimiento && Math.random() < .4)) return jugar();
      k = String(k || '').toLowerCase(); if (!PELAJE[k]) k = Math.random() < .5 ? 'pura' : 'tapioca';
      const boton = modo === 'pasear' ? null : botonCerca();
      if (boton && (modo === 'sentar' || sinMovimiento || Math.random() < .5)) sentar(k, boton);
      else if (!sinMovimiento) pasear(k);
    }
    function programar(primera) {
      clearTimeout(reloj);
      reloj = setTimeout(() => {
        const libre = !document.hidden && $('#telon').hidden && $('#visor').hidden && !$('#app').hidden && !(A && A.subiendo) && !grab && !actual;
        if (libre) aparecer();
        programar(false);
      }, primera ? 4500 + Math.random() * 3000 : 12000 + Math.random() * 12000);
    }
    return { iniciar: () => programar(true), aparecer };
  })();
  window.miau = gatos.aparecer;   // travesura: escribe miau('pura'), miau('tapioca') o miau('', 'jugar') en la consola

  // ---------- arranque ----------
  function leerEnlace() {
    const h = location.hash.slice(1);
    if (!h.includes('=')) return { vista: h };
    const p = new URLSearchParams(h);
    const out = { clave: p.get('clave') || '', admin: p.get('admin') || '', para: p.get('para') || '' };
    try { history.replaceState(null, '', location.pathname + location.search); } catch { /* */ }
    return out;
  }

  async function entrar(textoClave, desdeEnlace) {
    if (PREVIA) { C = PREVIA.contenido; }
    else {
      try {
        const guardada = guarda.get('llave');
        if (!textoClave && guardada) llave = await crypto.subtle.importKey('raw', b64(guardada), 'AES-GCM', false, ['decrypt']);
        else llave = await abrirLlave(textoClave);
        C = JSON.parse(new TextDecoder().decode(await descifrar('contenido.bin', true)));
      } catch (e) {
        guarda.del('llave');
        if (e && e.message === 'no_encontrado' || e instanceof TypeError) throw new Error('sin_datos');
        throw new Error('clave_mala');
      }
    }
    clave = norm(C.claveVisible);
    guarda.set('clave', clave);
    document.title = C.tituloPestana;
    $('#marca-texto').textContent = C.marca;
    $('#logo-letra').textContent = C.homenajeado.nombre.charAt(0);
    $('#puerta').hidden = true; $('#app').hidden = false;
    const demo = $('#aviso-demo');
    if (!NUBE) { demo.hidden = false; demo.textContent = PREVIA ? 'Vista previa: lo que publiques aquí es de prueba y solo lo ves tú.' : 'Modo de prueba: falta conectar la base de datos. Lo que publiques solo se guarda en este dispositivo.'; }
    if (!NUBE && claveAdmin && C.adminHash) {
      const hh = [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(claveAdmin)))].map(b => b.toString(16).padStart(2, '0')).join('');
      if (hh !== C.adminHash) claveAdmin = '';
    }
    pintar();
    await cargar(true);
    let yaVisto = false; try { yaVisto = sessionStorage.getItem('rn_telon') === '1'; } catch { /* */ }
    if (rol === 'homenajeado' && !yaVisto) mostrarTelon();
    if (esAdmin && desdeEnlace && desdeEnlace.admin) ir('panel');
    gatos.iniciar();
    setInterval(() => { if (!document.hidden) cargar(); }, 25000);
    document.addEventListener('visibilitychange', () => { if (!document.hidden) cargar(); });
  }

  $('#puerta-form').addEventListener('submit', async ev => {
    ev.preventDefault();
    const inp = $('#puerta-clave'), err = $('#puerta-error'), btn = ev.target.querySelector('button');
    if (!inp.value.trim()) return inp.focus();
    btn.disabled = true; btn.textContent = 'Abriendo…'; err.hidden = true;
    try { await entrar(inp.value); }
    catch (e) {
      err.textContent = e.message === 'sin_datos' ? 'No pudimos cargar la página. Revisa tu conexión y vuelve a intentar.' : 'Esa no es la palabra clave. Revisa el mensaje de invitación y vuelve a intentar.';
      err.hidden = false; btn.disabled = false; btn.textContent = 'Entrar'; inp.select();
    }
  });

  (async () => {
    const L = leerEnlace();
    if (L.admin) { claveAdmin = L.admin; guarda.set('admin', claveAdmin); }
    if (L.para) { rol = 'homenajeado'; guarda.set('rol', rol); }
    else if (L.clave) { rol = 'familia'; guarda.set('rol', rol); }
    if (L.vista && ['mosaico', 'saludos', 'foro', 'panel'].includes(L.vista)) vista = L.vista;
    if (PREVIA) return entrar('', L);
    if (L.clave || guarda.get('llave')) {
      try { await entrar(L.clave || '', L); return; }
      catch { if (L.clave) { $('#puerta-error').textContent = 'El enlace no trae la palabra clave correcta. Escríbela aquí.'; $('#puerta-error').hidden = false; } }
    }
    $('#puerta').hidden = false;
  })();
})();
