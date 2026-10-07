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
  const ico = n => `<svg class="ico" aria-hidden="true"><use href="#i-${n}"/></svg>`;
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
  async function descifrar(url) {
    const r = await fetch(url);
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
      return `<div class="incrustado ${e.clase}"><iframe src="${esc(e.src)}" ${e.alto ? `height="${e.alto}"` : ''} loading="lazy" title="Música en ${e.sitio}" allow="autoplay; clipboard-write; encrypted-media; fullscreen; picture-in-picture" allowfullscreen referrerpolicy="strict-origin-when-cross-origin"></iframe></div>`;
    }
    let sitio = e ? e.sitio : ''; try { sitio = sitio || new URL(enlace).hostname.replace(/^www\./, ''); } catch { /* */ }
    return `<a class="tarjeta-enlace" href="${esc(enlace)}" target="_blank" rel="noopener">${ico(e ? 'musica' : 'enlace')}<span><b>Abrir en ${esc(sitio)}</b></span></a>`;
  }

  // ---------- piezas de interfaz ----------
  const esFoto = a => (a.tipo || '').startsWith('image/');
  const esVideo = a => (a.tipo || '').startsWith('video/');
  const esAudio = a => (a.tipo || '').startsWith('audio/');
  // Un saludo puede traer varias cosas a la vez
  function contiene(p) { const a = p.adjuntos || []; return { texto: !!p.mensaje, foto: a.some(esFoto), video: a.some(esVideo), audio: a.some(esAudio), musica: !!p.enlace }; }
  function htmlAdjuntos(p) {
    const a = p.adjuntos || [];
    const fotos = a.filter(x => (x.tipo || '').startsWith('image/'));
    let h = '';
    if (fotos.length) h += `<div class="fotos ${fotos.length === 1 ? 'una' : ''}">${fotos.map(f => `<button type="button" data-accion="ver-foto" data-url="${esc(f.url)}" aria-label="Ver foto en grande"><img src="${esc(f.url)}" alt="Foto de ${esc(p.autor)}" loading="lazy"></button>`).join('')}</div>`;
    a.filter(x => (x.tipo || '').startsWith('video/')).forEach(v => { h += `<video src="${esc(v.url)}" controls playsinline preload="metadata"></video>`; });
    a.filter(x => (x.tipo || '').startsWith('audio/')).forEach(v => { h += `<audio src="${esc(v.url)}" controls preload="metadata"></audio>`; });
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
          <small>${p.relacion ? esc(p.relacion) + ' · ' : ''}Jugada ${n} · ${fecha(p.creado)}${p.oculto ? ' · OCULTO' : ''}</small></div>
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

  const EDADES = [
    { desde: 0, nombre: 'Alta Edad Media' }, { desde: 5, nombre: 'Edad Feudal' },
    { desde: 15, nombre: 'Edad de los Castillos' }, { desde: 30, nombre: 'Edad Imperial' }
  ];
  function htmlMarcador(saludos) {
    const c = t => saludos.filter(p => contiene(p)[t]).length;
    const n = saludos.length;
    let i = EDADES.length - 1; while (i > 0 && n < EDADES[i].desde) i--;
    const sig = EDADES[i + 1];
    const tramos = EDADES.map((e, k) => {
      const fin = EDADES[k + 1] ? EDADES[k + 1].desde : e.desde;
      const pct = k < i ? 100 : k > i ? 0 : !EDADES[k + 1] ? 100 : Math.round(((n - e.desde) / (fin - e.desde)) * 100);
      return `<i><u style="width:${pct}%"></u></i>`;
    }).join('');
    return `<div class="marcador">
      <div class="recursos" role="list" aria-label="Lo que ha dejado la gente">
        <div role="listitem">${ico('pluma')}<b>${c('texto')}</b><span>Mensajes</span></div>
        <div role="listitem">${ico('foto')}<b>${c('foto')}</b><span>Fotos</span></div>
        <div role="listitem">${ico('video')}<b>${c('video')}</b><span>Videos</span></div>
        <div role="listitem">${ico('audio')}<b>${c('audio')}</b><span>Audios</span></div>
        <div role="listitem">${ico('musica')}<b>${c('musica')}</b><span>Música</span></div>
      </div>
      <div class="edad">
        <div class="edad-titulo"><b>${EDADES[i].nombre}</b><span>${sig ? `${plural(sig.desde - n, 'saludo', 'saludos')} para la ${sig.nombre}` : 'La aldea llegó a su máximo esplendor'}</span></div>
        <div class="edad-barra" aria-hidden="true">${tramos}</div>
      </div>
    </div>`;
  }

  // ---------- vistas ----------
  function htmlBloqueCarta(b) {
    if (b.t === 'saludo') return `<p class="saludo-carta">${esc(b.texto)}</p>`;
    if (b.t === 'p') return `<p>${esc(b.texto)}</p>`;
    if (b.t === 'firma') return `<p class="firma">${esc(b.texto)}</p>`;
    if (b.t === 'foto') return `<figure><div class="marco ${b.alto ? 'alto' : ''}"><img data-medio="${esc(b.medio)}" alt="${esc(b.alt || '')}" width="${b.ancho || 800}" height="${b.altoPx || 1000}"></div><figcaption>${esc(b.pie || '')}</figcaption></figure>`;
    if (b.t === 'par') return `<div class="par">${b.fotos.map(f => htmlBloqueCarta({ t: 'foto', ...f })).join('')}</div>`;
    if (b.t === 'video') return `<figure><div class="video-vertical"><video data-medio="${esc(b.medio)}" data-cartel="${esc(b.cartel || '')}" controls playsinline preload="none"></video></div><figcaption>${esc(b.pie || '')}</figcaption></figure>`;
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

  const altitud = (capa, cota) => `<div class="altitud" aria-hidden="true"><span>${capa}</span><b>${cota}</b></div>`;
  const CORDILLERA = `<svg viewBox="0 0 800 110" preserveAspectRatio="none" aria-hidden="true">
    <path d="M0 110V84l60-10 58 8 82-30 50 12 76-42 44 24 40-32 44 30 46-14 62 36 78-12 82 22 78-10v44z" fill="#c9dcf0"/>
    <path d="M326 22l-20 22 12-3 8 8 10-9 12 6zM410 14l-16 20 10-2 8 9 9-10 11 5zM500 30l-14 14 9-2 7 6 8-7 10 3z" fill="#ffffff"/>
    <path d="M0 110V98l90-12 96 10 120-22 110 16 124-18 130 14 130-10v34z" fill="#a9c6e6"/>
  </svg>`;

  function vistaInicio() {
    const h = C.homenajeado, T = C.textos;
    const saludos = posts.filter(p => p.seccion === 'saludo' && !p.oculto);
    const gente = new Set(saludos.map(p => norm(p.autor))).size;
    const d = diasPara(h.fecha), f = fechaDia(h.fecha);
    const cuenta = d > 1 ? `<b>${d}</b> días para el ${f}` : d === 1 ? `<b>1</b> día: es mañana` : d === 0 ? `<b>Hoy</b> es el día` : `Fue el ${f}. Todavía puedes sumar tu saludo`;
    const portada = esEl()
      ? `<p class="rotulo">${f} · ${esc(T.elRotulo)}</p>
         <h1>${esc(T.elTitulo)} <em>${esc(h.nombre)}.</em></h1>
         <p class="bajada">${esc(saludos.length ? T.elBajada.replace('{personas}', plural(gente, 'persona', 'personas')).replace('{saludos}', plural(saludos.length, 'saludo', 'saludos')) : T.elBajadaVacia)}</p>
         <div class="portada-acciones">
           <a class="btn btn-haz btn-grande" href="#mosaico" data-ir="mosaico">${esc(T.elVer)}</a>
           <button type="button" class="btn btn-grande" data-accion="saludar">${esc(T.elEscribir)}</button>
         </div>`
      : `<p class="rotulo">Sorpresa de cumpleaños · ${f}</p>
         <h1>${esc(h.nombre)} cumple lejos de casa. <em>Llevémosle la casa.</em></h1>
         <p class="bajada">Déjale un mensaje, fotos, un video, un audio o una canción. O todo junto. Toma dos minutos y no necesitas crear ninguna cuenta.</p>
         <p class="cuenta">${cuenta}</p>
         <div class="portada-acciones">
           <button type="button" class="btn btn-haz btn-grande" data-accion="saludar">${ico('mas')}Dejar mi saludo</button>
           <a class="btn btn-grande" href="#mosaico" data-ir="mosaico">Ver el mosaico</a>
         </div>`;

    return `<div class="portada cielo-alto">
        <div class="columna portada-texto">${portada}</div>
        <figure class="portada-marco"><img class="portada-foto" data-medio="${esc(C.portada.medio)}" alt="${esc(C.portada.alt)}"></figure>
      </div>
      <p class="portada-pie">${esc(C.portada.pie)}</p>
      <div class="columna">
        ${esEl() ? '' : `
        <div class="secreto" style="margin-top:1.75rem">${pieza('♞')}<p><b>Es sorpresa.</b> No le reenvíes este enlace a ${esc(h.nombre)}: él recibirá el suyo el ${f}.</p></div>
        ${altitud('Tropopausa', '17 km')}
        <section class="seccion">
          <h2>Tres pasos y listo</h2>
          <ol class="como">
            <li><div><b>Dinos quién eres</b><span>Solo tu nombre, para que ${esc(h.nombre)} sepa de quién viene.</span></div></li>
            <li><div><b>Elige qué dejarle</b><span>Unas palabras, fotos, un video, un audio, una canción. Una cosa o varias.</span></div></li>
            <li><div><b>Envía</b><span>Tu saludo se suma al mosaico al instante.</span></div></li>
          </ol>
        </section>`}
        ${altitud('Troposfera libre', '9 km')}
        <section class="seccion">
          <p class="rotulo">${esc(C.ficha.rotulo)}</p>
          <h2>${esc(C.ficha.titulo)}</h2>
          <div class="ficha">${C.ficha.lineas.map(l => `<div>${pieza(l.pieza)}<p><b>${esc(l.titulo)}</b><span>${esc(l.texto)}</span></p></div>`).join('')}</div>
        </section>
        ${altitud('Chacaltaya', '5 240 m')}
        <section class="carta">
          <p class="rotulo">${esc(C.carta.rotulo)}</p>
          ${C.carta.bloques.map(htmlBloqueCarta).join('')}
        </section>
        <footer class="pie">${CORDILLERA}<span class="cota">La Paz · 3 640 m s.n.m.</span><span>${esc(C.pie)}</span></footer>
      </div>`;
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
    const base = `class="tesela ${p.t === 'foto' || p.t === 'video' ? '' : colorDe(p.autor || 'x')} w${p.w} h${p.h} ${nueva ? 'nueva' : ''} ${{ texto: 'con-texto', musica: 'con-texto', audio: 'con-texto', respuesta: 'con-texto', gustos: 'chica' }[p.t] || ''}" style="--w:${p.w};--h:${p.h};--i:${Math.min(i, 28)}" data-accion="ir-pieza" data-destino="${p.destino}" ${p.id ? `data-id="${p.id}"` : ''} ${p.tema ? `data-tema="${esc(p.tema)}"` : ''}`;
    const quien = esc(p.autor || '');
    if (p.t === 'foto') return `<button type="button" ${base} aria-label="Foto de ${quien}"><img ${p.medio ? `data-medio="${esc(p.medio)}"` : `src="${esc(p.url)}" loading="lazy"`} alt=""><span class="sello">${quien}</span></button>`;
    if (p.t === 'video') return `<button type="button" ${base} aria-label="Video de ${quien}">${p.medio ? `<img data-medio="${esc(p.medio)}" alt="">` : `<video src="${esc(p.url)}#t=0.4" muted playsinline preload="metadata" tabindex="-1"></video>`}<span class="play">${ico('play')}</span><span class="sello">${quien}</span></button>`;
    if (p.t === 'texto') return `<button type="button" ${base}><span class="cita ${p.texto.length < 48 ? 'corta' : ''}">${esc(p.texto.slice(0, 220))}</span><span class="autor">${quien}${p.pie ? ' · ' + esc(p.pie) : ''}</span></button>`;
    if (p.t === 'audio') return `<button type="button" ${base}>${ico('audio')}<span class="autor">Audio de ${quien}</span></button>`;
    if (p.t === 'musica') return `<button type="button" ${base}>${ico('musica')}<span class="autor">${esc(p.texto)} · ${quien}</span></button>`;
    if (p.t === 'respuesta') return `<button type="button" ${base}>${ico('responder')}<span class="autor">${quien} le respondió a ${esc(p.a)}</span></button>`;
    if (p.t === 'gustos') return `<button type="button" ${base} aria-label="${p.n} me encanta">${ico('corazon')}<span class="autor">${p.n}</span></button>`;
    return '';
  }
  function vistaMosaico() {
    const P = piezasMosaico(), h = C.homenajeado;
    const huecos = esEl() ? '' : `
      <button type="button" class="tesela hueco w2 h1" style="--w:2;--h:1" data-accion="ir-pieza" data-destino="saludar">${ico('mas')}Tu pieza va aquí</button>
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
        <p>${esEl() ? esc(C.textos.elTableroBajada) : 'Cada saludo es una jugada. Con cada una, la aldea avanza de edad.'}</p>
      </header>
      ${htmlMarcador(todos.filter(p => !p.oculto))}
      <div class="filtros" role="group" aria-label="Filtrar saludos">${FILTROS.map(([k, t]) => `<button type="button" class="chip" data-accion="filtrar" data-filtro="${k}" aria-pressed="${filtro === k}">${t}</button>`).join('')}</div>
      <div class="muro">
        ${visibles.length ? visibles.map(p => htmlTarjeta(p, numero.get(p.id))).join('') : `<div class="vacio">${pieza('♙')}
          <h3>${todos.length ? 'Nada de este tipo todavía' : 'El tablero está listo'}</h3>
          <p>${todos.length ? 'Prueba con otro filtro o sé quien lo estrene.' : esEl() ? esc(C.textos.elVacio) : 'Aún no hay jugadas. La primera puede ser la tuya.'}</p>
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
        <header class="cab-vista"><p class="rotulo">Centro urbano</p><h2>${esc(C.foro.titulo)}</h2><p>${esc(C.foro.texto)}</p></header>
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
          ${(p.adjuntos || []).filter(a => (a.tipo || '').startsWith('image/')).map(a => `<img src="${esc(a.url)}" alt="Foto de ${esc(p.autor)}" loading="lazy" data-accion="ver-foto" data-url="${esc(a.url)}">`).join('')}
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
    { id: 'musica', ico: 'musica', titulo: 'Una canción', texto: 'Un enlace de YouTube o Spotify. También sirve una playlist.', falta: 'la canción', solo: 'Pega un enlace válido de la canción.' }
  ];
  const RELACIONES = ['Familia', 'Amistad', 'Colega', 'Estudiante', 'Otro'];
  let A = null;   // estado del asistente
  let grab = null; // grabadora

  const saludoVacio = () => ({ tipos: new Set(), texto: '', fotos: [], video: null, audio: null, enlace: '' });
  const elegidos = () => TIPOS.filter(t => A.tipos.has(t.id));
  const enLista = l => l.length < 2 ? l.join('') : `${l.slice(0, -1).join(', ')} y ${l[l.length - 1]}`;
  function sincronizar() {
    if (!A) return;
    const t = $('#as-texto'); if (t) A.texto = t.value;
    const e = $('#as-enlace'); if (e) A.enlace = e.value;
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
      cuerpo = `<label class="campo"><span>Enlace de la canción o playlist</span><input type="text" id="as-enlace" inputmode="url" autocapitalize="none" autocorrect="off" spellcheck="false" placeholder="https://" value="${esc(A.enlace)}"><small>En YouTube o Spotify: Compartir → Copiar enlace. Luego pégalo aquí.</small></label>
        <div id="as-vista-enlace">${enl ? htmlEnlace(enl) : ''}</div>`;
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
    const vacio = { texto: !texto, foto: !A.fotos.length, video: !A.video, audio: !A.audio, musica: !enlace };
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
    if (ev.key !== 'Escape') return;
    if (!$('#visor').hidden) $('#visor').hidden = true;
    else if (A && !A.subiendo) cerrarAsistente();
  });
  window.addEventListener('hashchange', () => { const v = location.hash.slice(1); if (C && v !== vista && !v.includes('=')) ir(v); });

  // ---------- telón del homenajeado ----------
  function mostrarTelon() {
    const T = C.textos, h = C.homenajeado, n = posts.filter(p => p.seccion === 'saludo' && !p.oculto).length;
    $('#telon-rotulo').textContent = fechaDia(h.fecha);
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
      atigrado: { nombre: 'Pura', base: '#8f9199', sombra: '#70727a', raya: '#3c3e46', claro: '#dfe0e5', pata: '#9d9fa7', oreja: '#dba3aa', nariz: '#c98078', ojo: '#a8c56b', bigote: '#ffffff', parpado: '#2f3138' },
      esmoquin: { nombre: 'Tapioca', base: '#1f1c22', sombra: '#0f0d11', raya: '#1f1c22', claro: '#faf8f3', pata: '#faf8f3', oreja: '#7a5560', nariz: '#4a3d42', ojo: '#b5d27e', bigote: '#ffffff', parpado: '#b5d27e' }
    };
    function cabeza(k, dormido) {
      const p = PELAJE[k];
      const ojo = x => dormido
        ? `<path d="M${x - 5} -3q5 4.500 10 0" fill="none" stroke="${p.parpado}" stroke-width="1.8" stroke-linecap="round"/>`
        : `<ellipse cx="${x}" cy="-3" rx="5.4" ry="5.9" fill="${p.ojo}"/><ellipse cx="${x}" cy="-3" rx="1.8" ry="4.700" fill="#15110f"/><circle cx="${x + 1.6}" cy="-5.200" r="1.100" fill="#fff"/>`;
      const marcas = k === 'atigrado'
        ? `<path d="M-8 -21v8M0 -23v9M8 -21v8M-27 2l8 1.500M-26 9l7 -.500M27 2l-8 1.500M26 9l-7 -.500" fill="none" stroke="${p.raya}" stroke-width="2.500" stroke-linecap="round"/><ellipse cx="0" cy="10" rx="12" ry="8" fill="${p.claro}"/>`
        : `<path d="M-16 21C-19 8-7 3 0 -3C7 3 19 8 16 21C8 25-8 25-16 21Z" fill="${p.claro}"/>`;
      return `<path d="M-25 -8L-27 -33L-7 -19Z" fill="${p.base}"/><path d="M-22.500 -13L-23.500 -27L-12 -19Z" fill="${p.oreja}"/>
        <path d="M25 -8L27 -33L7 -19Z" fill="${p.base}"/><path d="M22.500 -13L23.500 -27L12 -19Z" fill="${p.oreja}"/>
        <ellipse cx="0" cy="0" rx="28" ry="23" fill="${p.base}"/>${marcas}${ojo(-11)}${ojo(11)}
        <path d="M-3.200 6h6.400l-3.200 3.800z" fill="${p.nariz}"/>
        <path d="M0 9.800q-3.500 4.500-7 1.500M0 9.800q3.500 4.500 7 1.500" fill="none" stroke="#2a2022" stroke-width="1.200" stroke-linecap="round"/>
        <path d="M-9 10L-31 6M-9 12L-32 12.500M-9 14L-30 19M9 10L31 6M9 12L32 12.500M9 14L30 19" fill="none" stroke="${p.bigote}" stroke-width=".9" stroke-linecap="round" opacity=".9"/>`;
    }
    function sentado(k) {
      const p = PELAJE[k];
      const rayas = k === 'atigrado' ? `<path d="M29 84q6-2 9 2M28 95q7-2 10 2M71 84q-6-2-9 2M72 95q-7-2-10 2" fill="none" stroke="${p.raya}" stroke-width="2.400" stroke-linecap="round"/>` : '';
      return `<svg viewBox="0 0 100 112" width="100%"><path class="cola" d="M72 99C96 101 99 79 88 69" fill="none" stroke="${p.base}" stroke-width="9" stroke-linecap="round"/>
        <g class="cuerpo-gato"><path d="M27 107C20 83 30 57 50 57C70 57 80 83 73 107Z" fill="${p.base}"/>
          <path d="M41 107C37 89 42 69 50 64C58 69 63 89 59 107Z" fill="${p.claro}"/>${rayas}
          <ellipse cx="41" cy="106" rx="8" ry="5" fill="${p.pata}" stroke="${p.sombra}" stroke-opacity=".35"/><ellipse cx="59" cy="106" rx="8" ry="5" fill="${p.pata}" stroke="${p.sombra}" stroke-opacity=".35"/>
          <g transform="translate(50 35)">${cabeza(k, true)}</g></g></svg>`;
    }
    function paseando(k) {
      const p = PELAJE[k];
      const pata = (x, lejos, fase) => `<g class="pata ${fase}"><rect x="${x}" y="52" width="10" height="31" rx="5" fill="${lejos ? p.sombra : p.base}"/><rect x="${x}" y="74" width="10" height="9" rx="4.500" fill="${k === 'esmoquin' ? p.pata : (lejos ? p.sombra : p.pata)}"/></g>`;
      const pelaje = k === 'atigrado'
        ? `<path d="M56 33q-3 10 1 21M68 31q-3 12 1 24M80 31q-3 12 1 24M92 34q-2 9 1 18" fill="none" stroke="${p.raya}" stroke-width="3" stroke-linecap="round"/>`
        : `<path d="M88 67C94 53 110 50 113 58C111 67 100 71 88 67Z" fill="${p.claro}"/>`;
      return `<svg viewBox="0 0 150 90" width="100%"><path class="cola" d="M38 47C16 46 10 28 18 12" fill="none" stroke="${p.base}" stroke-width="8" stroke-linecap="round"/>
        ${pata(46, true, 'b')}${pata(100, true, '')}
        <g class="tronco"><ellipse cx="76" cy="50" rx="40" ry="19" fill="${p.base}"/>${pelaje}</g>
        ${pata(56, false, '')}${pata(108, false, 'b')}
        <g class="tronco"><g transform="translate(118 33) scale(.8)">${cabeza(k, false)}</g></g></svg>`;
    }

    const caja = $('#gatos');
    const sinMovimiento = matchMedia('(prefers-reduced-motion: reduce)').matches;
    let actual = null, reloj = null;
    function quitar() { if (!actual) return; cancelAnimationFrame(actual.raf); clearTimeout(actual.t); actual.el.remove(); actual = null; }
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
      const c = $$('.btn-haz, .btn-grande, .tema, .hueco.w2, .chip', raiz).filter(b => {
        const r = b.getBoundingClientRect();
        return r.width >= 56 && r.top > 150 && r.bottom <= innerHeight && r.left >= 0 && r.right <= innerWidth;
      });
      return c.length ? c[Math.floor(Math.random() * c.length)] : null;
    }
    function pasear(k) {
      const el = document.createElement('div');
      el.className = 'gato pasea' + (Math.random() < .5 ? ' izq' : '');
      el.style.setProperty('--dur', (12 + innerWidth / 120) + 's');
      el.innerHTML = paseando(k);
      el.addEventListener('animationend', ev => { if (ev.animationName.startsWith('pasear')) quitar(); });
      el.addEventListener('click', () => { el.classList.add('quieto'); decir(el, `¡Miau! Soy ${PELAJE[k].nombre}`, 2000); setTimeout(() => el.classList.remove('quieto'), 2000); });
      caja.appendChild(el); actual = { el };
    }
    function sentar(k, boton) {
      const el = document.createElement('div');
      el.className = 'gato sentado'; el.innerHTML = sentado(k);
      caja.appendChild(el); decir(el, 'prrr…', 0);
      const irse = () => { if (!actual || actual.el !== el) return; el.classList.add('yendose'); setTimeout(quitar, 420); };
      const seguir = () => {
        const r = boton.isConnected ? boton.getBoundingClientRect() : null;
        if (!r || !r.width || r.top < 110 || r.bottom > innerHeight + 8) return irse();
        el.style.left = Math.max(4, r.right - el.offsetWidth - Math.min(18, r.width * .12)) + 'px';
        el.style.top = (r.top - el.offsetHeight + 7) + 'px';
        actual.raf = requestAnimationFrame(seguir);
      };
      el.addEventListener('click', () => decir(el, `¡Miau! Soy ${PELAJE[k].nombre}`, 2200));
      actual = { el, t: setTimeout(irse, 8500) };
      seguir();
    }
    function aparecer(k, modo) {
      if (actual) quitar();
      k = { pura: 'atigrado', tapioca: 'esmoquin' }[String(k || '').toLowerCase()] || k || (Math.random() < .5 ? 'atigrado' : 'esmoquin');
      const boton = modo === 'pasear' ? null : botonCerca();
      if (boton && (modo === 'sentar' || sinMovimiento || Math.random() < .55)) sentar(k, boton);
      else if (!sinMovimiento) pasear(k);
    }
    function programar(primera) {
      clearTimeout(reloj);
      reloj = setTimeout(() => {
        const libre = !document.hidden && $('#telon').hidden && $('#visor').hidden && !$('#app').hidden && !(A && A.subiendo) && !grab && !actual;
        if (libre) aparecer();
        programar(false);
      }, primera ? 9000 + Math.random() * 6000 : 40000 + Math.random() * 45000);
    }
    return { iniciar: () => programar(true), aparecer };
  })();
  window.miau = gatos.aparecer;   // travesura: escribe miau('pura') o miau('tapioca') en la consola

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
        C = JSON.parse(new TextDecoder().decode(await descifrar('contenido.bin')));
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
