
import http from "node:http"

const ROUTES = ["energy", "sign", "register", "request_token", "submit"]

function buildUpstream(url) {
  const src = new URL(url)
  const upstream = new URL(src.origin + src.pathname)
  for (const [k, v] of src.searchParams) upstream.searchParams.set(k, v)
  return upstream
}

const PLATFORM = {
  1: "android",
  2: "apad",
  3: "watch",
  4: "imac",
  5: "tim",
}

function startServer(upstream, platform) {
  const pingtai = PLATFORM[platform] || "android"
  const server = http.createServer((req, res) => {
    const chunks = []
    req.on("data", c => chunks.push(c))
    req.on("end", () => {
      const local = new URL(req.url, "http://127.0.0.1")
      const target = new URL(upstream)
      for (const [k, v] of local.searchParams) target.searchParams.set(k, v)

      const segs = [
        ...local.pathname.split("/"),
        ...local.searchParams.keys(),
      ].filter(Boolean)
      const tail = [...segs].reverse().find(s => ROUTES.includes(s))
      if (tail) {
        target.pathname = `/${tail}`
        for (const k of ROUTES) target.searchParams.delete(k)
      }

      const form = new URLSearchParams(chunks.join(""))
      for (const [k, v] of form) target.searchParams.set(k, v)

      if (!target.searchParams.has("pingtai")) target.searchParams.set("pingtai", pingtai)
      if (process.env.SIGN_PROXY_VER) target.searchParams.set("ver", process.env.SIGN_PROXY_VER)

      const fail = err => {
        if (res.headersSent) return
        res.writeHead(200, { "content-type": "application/json" })
        res.end(JSON.stringify({ code: -1, msg: `sign-proxy: ${err.message}` }))
      }

      if (process.env.SIGN_PROXY_DEBUG) console.log("[sign-proxy]", req.method, req.url, "→", target.href)

      const started = Date.now()
      fetch(target, { method: "GET", signal: AbortSignal.timeout(90000) })
        .then(r => r.text())
        .then(text => {
          if (process.env.SIGN_PROXY_DEBUG)
            console.log(`[sign-proxy] ${target.pathname} ${Date.now() - started}ms ${text.slice(0, 80)}`)
          res.writeHead(200, { "content-type": "application/json" })
          res.end(text)
        })
        .catch(fail)
    })
  })
  return new Promise((resolve, reject) => {
    server.once("error", reject)
    server.listen(0, "127.0.0.1", () => resolve(server))
  })
}

export async function ensureSignProxy(upstream, platform) {
  if (!upstream) return null
  const cacheKey = `${upstream}#${platform ?? ""}`
  if (ensureSignProxy.cache?.[cacheKey]) return ensureSignProxy.cache[cacheKey]

  const server = await startServer(buildUpstream(upstream), platform)
  const { port } = server.address()
  const key = new URL(upstream).searchParams.get("key") || ""
  const local = `http://127.0.0.1:${port}/${key ? `?key=${encodeURIComponent(key)}` : ""}`
  ensureSignProxy.cache ??= {}
  ensureSignProxy.cache[cacheKey] = local
  return local
}
