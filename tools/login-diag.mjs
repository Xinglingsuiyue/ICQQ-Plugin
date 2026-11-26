#!/usr/bin/env node

import fs from "node:fs"
import fsp from "node:fs/promises"
import path from "node:path"
import { fileURLToPath, pathToFileURL } from "node:url"
import { parseTokenBlob, inspectV3 } from "./icqq-token-bridge.mjs"

const __filename = fileURLToPath(import.meta.url)
const PLUGIN_DIR = path.resolve(path.dirname(__filename), "..")
const TRSS_DIR = path.resolve(PLUGIN_DIR, "../..")

const PLATFORM_NAME = { 1: "Android", 2: "aPad", 3: "Watch", 4: "iMac", 5: "iPad", 6: "Tim" }

const stamp = () => new Date().toTimeString().slice(0, 8)

export function attributeLoginError(data = {}) {
  const code = Number(data.code)
  const msg = String(data.message ?? "")
  if (code === 45 || /45|版本过低|版本太低|版本不正确/.test(msg))
    return "服务端判版本过低：常见于签名未生效（qsign 超时后 icqq 用无签名 t544 发包）或用了 iMac 6.8.2 这类低版本 apk；aPad 9.1.70 可过版本门控，先确认签名服务正常再重试"
  if (/频繁|frequency|too many|限制/.test(msg))
    return "触发登录频率限制：签名失败仍发包、短时间内反复登录、或同号双开互踢都会导致；先修好签名再登录"
  if (/签名|sign/i.test(msg))
    return "签名服务异常：检查 sign_api_addr 是否可达、key 是否正确、apk_ver 是否在白名单"
  if (/token|令牌/i.test(msg))
    return "token 无效或已过期：需要重新生成有效的 v3 token"
  if (/密码|password/i.test(msg)) return "密码错误或密码登录被拒"
  if (/网络|network|timeout/i.test(msg)) return "网络/服务端超时"
  return "未归类，请结合上方「登录包」与 verbose 日志判断"
}

function describe(v) {
  if (v == null) return String(v)
  if (Buffer.isBuffer(v) || ArrayBuffer.isView(v)) return `<Buffer ${v.length}B>`
  if (typeof v === "object") {
    if (Array.isArray(v)) return `[${v.length}]`
    try { return JSON.stringify(v).slice(0, 160) } catch { return "<object>" }
  }
  if (typeof v === "string") return v.length > 60 ? `${v.slice(0, 60)}…(${v.length})` : v
  return String(v)
}

function makeLogger(logger) {
  if (!logger) return (level, text) => console.log(`[diag ${stamp()}] ${text}`)
  const fn = logger.info || logger.mark || logger.debug || console.log
  return (level, text) => {
    try { fn.call(logger, `[diag] ${text}`) } catch { console.log(`[diag] ${text}`) }
  }
}

async function readDeviceSummary(dataDir) {
  try {
    const d = JSON.parse(await fsp.readFile(path.join(dataDir, "device.json"), "utf8"))
    return {
      product: d.product, device: d.device, board: d.board, brand: d.brand, model: d.model,
      android_id: d.android_id, mac_address: d.mac_address, ip_address: d.ip_address,
      proc_version: d.proc_version,
    }
  } catch {
    return null
  }
}

async function querySignVersion(signUrl) {
  if (!signUrl) return { reachable: false, version: null, error: "未配置 sign_api_addr" }
  try {
    const u = new URL(signUrl)
    if (!u.pathname.endsWith("/")) u.pathname = u.pathname.replace(/\/sign$/, "/")
    const res = await fetch(u, { signal: AbortSignal.timeout(15000) })
    const j = await res.json()
    return { reachable: true, version: j?.data?.protocol?.version || null, raw: j?.data?.protocol }
  } catch (e) {
    return { reachable: false, version: null, error: e.message }
  }
}

export async function preflight({ uin, dataDir, platform, ver, sign, password, logger }) {
  const log = makeLogger(logger)
  const id = Number(uin)
  const tokenPath = path.join(dataDir, `${id}_token`)
  const bakPath = tokenPath + "_bak"
  const bigdataPath = path.join(dataDir, `${id}_bigdata`)

  log("info", "===== 登录环境诊断 =====")
  log("info", `账号=${id}  平台=${platform}(${PLATFORM_NAME[platform] || "?"})  配置版本=${ver || "(未指定)"}  签名=${sign || "(未配置)"}`)

  let tokenInfo = null
  if (!fs.existsSync(tokenPath)) {
    log("warn", `token 文件不存在：${tokenPath}`)
  } else {
    const st = fs.statSync(tokenPath)
    log("info", `token 文件：${tokenPath}  ${st.size}B  修改于 ${st.mtime.toISOString()}`)
    try {
      const buf = await fsp.readFile(tokenPath)
      const p = parseTokenBlob(buf)
      if (p.ver === 3) {
        const { info, segs } = inspectV3(buf)
        tokenInfo = { ver: 3, apk: info.apk, segs }
        log("info", `token_ver=3  apk=${info.apk?.name}/${info.apk?.ver} (${info.apk?.version}, subid=${info.apk?.subid})`)
        const names = ["t119", "tgtgt", "a1", "d2", "d2key", "tgt", "tgt_key", "ticket_key", "sig_key", "srm_token", "device_token", "t543", "randkey", "session"]
        log("info", "票据: " + segs.map((s, i) => `${names[i]}=${s.length ? "有" : "无"}`).join(" "))
        if (!segs[5].length || !segs[6].length || !segs[3].length || !segs[4].length) {
          log("warn", "关键旧版票据缺失（tgt/tgt_key/d2/d2key），token 登录大概率失败")
        }
        const headerText = buf.subarray(2, 2 + buf.readUInt16BE(0)).toString("utf8")
        if (!headerText.includes("icqq")) {
          log("error", 'token 头不含 "icqq" 字样：icqq 会整段跳过解析，以空票据继续登录，必然失败')
        }
      } else if (p.ver === 6) {
        const fns = new Set(p.fields.filter((f) => f.wt === 2 && f.val.length).map((f) => f.fn))
        const need = [0x106, 0x10a, 0x10d, 0x143, 0x305]
        tokenInfo = { ver: 6, missing: need.filter((n) => !fns.has(n)) }
        log("warn", "token_ver=6（icqq-onebot 格式）：原生 icqq 0.6.10 不能直接读，必须先转 v3")
        log("info", "旧版票据: " + need.map((n) => `0x${n.toString(16)}=${fns.has(n) ? "有" : "无"}`).join(" "))
      } else {
        log("warn", `token_ver=${p.ver}：未知格式`)
      }
    } catch (e) {
      log("warn", `token 解析失败：${e.message}`)
    }
  }
  if (fs.existsSync(bakPath)) log("warn", `存在 ${path.basename(bakPath)}：icqq 启动时会用它覆盖新 token，建议删除`)
  if (fs.existsSync(bigdataPath)) log("info", `存在 ${path.basename(bigdataPath)}：旧会话 bigdata，换 token 后建议删除`)

  const dev = await readDeviceSummary(dataDir)
  log("info", dev ? `device.json：${dev.brand}/${dev.model} android_id=${dev.android_id || "-"}` : "device.json：不存在（首次登录会重新生成）")

  try {
    const devMod = await import(new URL("../Model/device.js", import.meta.url).href)
    const list = devMod.getApkInfoList(Number(platform))
    const apk = (ver && list.find((a) => a.ver === ver)) || list[0]
    if (apk) {
      log("info", `icqq 将使用 APK：${apk.name}  ${apk.version}  ver=${apk.ver}  subid=${apk.subid}`)
      const tv = tokenInfo?.apk?.version
      if (tokenInfo?.ver === 3 && tv && String(tv) !== String(apk.version)) {
        log("warn", `token apk 版本(${tv}) ≠ 将使用的 APK(${apk.version})：可能触发 token_expire 或 switchQQVer`)
      }
      if (tokenInfo?.ver === 3 && tokenInfo.apk?.id && tokenInfo.apk.id !== apk.id) {
        log("warn", `token apk id(${tokenInfo.apk.id}) ≠ ${apk.id}：token 必失效`)
      }
    }
  } catch (e) {
    log("warn", `无法读取 Model/device.js 的 APK 列表：${e.message}`)
  }

  if (fs.existsSync(tokenPath)) {
    if (tokenInfo?.ver === 6) log("warn", "→ 将走 token 登录，但 token 是 v6，必然失败")
    else log("info", "→ 将优先走 token 登录")
    if (password) log("warn", "→ token 失败后还会回落密码登录（旧协议；aPad 可过版本门控，但签名失败会换来 45/237，且增加频繁风险）")
  } else if (password) {
    log("error", "→ 没有 token，将走密码登录（aPad 可过版本门控；签名失败会换来 45/237）")
  } else {
    log("error", "→ 没有 token 也没有密码，将走扫码登录")
  }

  return { tokenPath, tokenInfo, dev }
}

export function attachLoginDiagnostics(bot, opts = {}) {
  const uin = Number(opts.id ?? bot.uin)
  const dataDir = opts.dataDir || bot.dir
  const logger = opts.logger || bot.logger
  const log = makeLogger(logger)
  const verbose = opts.verbose ?? process.env.ICQQ_LOGIN_DIAG === "1"

  const state = { stage: "初始化", startedAt: Date.now(), loginCmd: null }

  const note = (level, text) => log(level, `${text}`)

  preflight({ uin, dataDir, platform: bot.config?.platform ?? opts.platform ?? 2, ver: bot.apk?.ver, sign: bot.sig?.sign_api_addr, password: opts.password, logger }).then(async (pf) => {
    if (bot.sig?.sign_api_addr) {
      const s = await querySignVersion(bot.sig.sign_api_addr)
      if (s.reachable) {
        note("info", `签名服务可达：上报协议版本=${s.version || "(未上报)"}`)
        if (s.version && bot.apk?.ver && s.version !== bot.apk.ver)
          note("warn", `签名服务版本(${s.version}) 与本地 apk(${bot.apk.ver}) 不一致，token 可能被判失效`)
      } else {
        note("warn", `签名服务不可达：${s.error}`)
      }
    }
    if (pf?.tokenInfo?.apk?.ver && bot.apk?.ver && pf.tokenInfo.apk.ver !== bot.apk.ver)
      note("warn", `token 内 apk 版本(${pf.tokenInfo.apk.ver}) 与当前 apk(${bot.apk.ver}) 不一致`)
  }).catch((e) => note("debug", `预检异常：${e.message}`))

  for (const m of ["tokenLogin", "passwordLogin", "qrcodeLogin", "register", "refreshToken", "queryQrcodeResult"]) {
    if (typeof bot[m] !== "function") continue
    const orig = bot[m].bind(bot)
    bot[m] = async function (...args) {
      const brief = args.map((a) => (typeof a === "string" ? describe(a) : Buffer.isBuffer(a) ? describe(a) : describe(a))).join(", ")
      note("debug", `→ ${m}(${brief})`)
      const t = Date.now()
      try {
        const r = await orig(...args)
        note("debug", `← ${m} => ${describe(r)} (${Date.now() - t}ms)`)
        return r
      } catch (e) {
        note("error", `✖ ${m} 抛错：${e.code ?? ""} ${e.message}`)
        throw e
      }
    }
  }

  const proto = Object.getPrototypeOf(bot)
  const sendLoginSym = Object.getOwnPropertySymbols(proto).find((s) => s.description === "FN_SEND_LOGIN")
  if (sendLoginSym && typeof proto[sendLoginSym] === "function") {
    const orig = proto[sendLoginSym]
    bot[sendLoginSym] = async function (cmd, body) {
      state.loginCmd = cmd
      state.stage = `发送登录包 ${cmd}`
      note("info", `→ 登录包 ${cmd}  ${body?.length ?? 0}B`)
      const t = Date.now()
      try {
        return await orig.call(this, cmd, body)
      } finally {
        note("info", `← 登录包 ${cmd} 结束 ${Date.now() - t}ms`)
      }
    }
  }

  bot.on("internal.error.token", (code, msg) => {
    state.stage = "token 登录被拒"
    note("error", `token 登录被拒：${msg} (code=${code})`)
  })
  bot.on("internal.error.network", (code, msg) => {
    state.stage = "网络错误"
    note("error", `网络错误：${msg} (code=${code})`)
  })
  bot.on("internal.verbose", (msg, level) => {
    if (verbose) note("debug", `verbose: ${msg}`)
    else if (/失败|错误|45|频繁|过期/.test(String(msg))) note("warn", `verbose: ${msg}`)
  })
  bot.on("system.login.slider", (d) => {
    state.stage = "等待滑块验证"
    note("warn", `需要滑块验证：${d?.url || ""}`)
  })
  bot.on("system.login.device", (d) => {
    state.stage = "等待设备验证"
    note("warn", `需要设备验证：${describe(d)}`)
  })
  bot.on("system.login.qrcode", async (d) => {
    state.stage = "等待扫码"
    note("warn", "需要扫码登录")
    try {
      const out = path.join(dataDir || ".", `${uin}_qrcode.png`)
      await fsp.mkdir(path.dirname(out), { recursive: true })
      await fsp.writeFile(out, d.image)
      note("mark", `二维码已保存：${out}（用手机 QQ 扫码）`)
    } catch (e) {
      note("warn", `二维码保存失败：${e.message}`)
    }
  })
  bot.on("system.login.auth", (d) => {
    state.stage = "等待 auth 验证"
    note("warn", `需要 auth 验证：${describe(d)}`)
  })
  bot.on("system.login.error", (d) => {
    state.stage = "登录失败"
    note("error", `登录失败：${d?.message} (code=${d?.code})`)
    note("error", `结论：${attributeLoginError(d)}`)
  })
  bot.on("system.online", () => {
    state.stage = "上线成功"
    note("info", `上线成功，耗时 ${Date.now() - state.startedAt}ms`)
    note("info", "===== 诊断结束 =====")
  })
  bot.on("system.offline", (d) => {
    state.stage = "已下线"
    note("warn", `下线：${d?.message} (code=${d?.code ?? ""})`)
  })

  return { state, preflight }
}

function readYamlToken(yamlPath, uin) {
  try {
    const text = fs.readFileSync(yamlPath, "utf8")
    const re = new RegExp(`^\\s*-\\s*['"]?(${uin}:[^'"\\r\\n]*)['"]?\\s*$`, "m")
    const m = text.match(re)
    if (m) return { token: m[1], text }
    const b = text.split(/^bot:\s*$/m)[1] || ""
    const platform = Number(b.match(/^\s+platform:\s*['"]?([1-6])/m)?.[1] || 2)
    const ver = b.match(/^\s+ver:\s*['"]?([0-9][0-9.]*)/m)?.[1] || ""
    const sign = b.match(/^\s+sign_api_addr:\s*['"]?([^\s'"]+)/m)?.[1] || ""
    return { token: null, text, platform, ver, sign }
  } catch {
    return { token: null, text: "" }
  }
}

async function loadIcqq() {
  const errors = []
  for (const i of ["Model", "node_modules"]) {
    const dir = path.join(PLUGIN_DIR, i, "icqq")
    let pkg
    try {
      pkg = JSON.parse(await fsp.readFile(path.join(dir, "package.json"), "utf8"))
    } catch {
      continue
    }
    try {
      const mod = await import(pathToFileURL(path.join(dir, pkg.main)).href)
      const icqq = mod.default ?? mod
      icqq.package = pkg
      return { icqq, pkg }
    } catch (e) {
      errors.push(`${dir}: ${e.message}`)
    }
  }
  throw new Error(
    "找不到可用的 icqq（Model/icqq 或 node_modules/icqq）" +
      (errors.length ? `\n  ${errors.join("\n  ")}` : ""),
  )
}

function parseCli(argv) {
  const opt = { wait: 45 }
  const takes = new Set(["--token", "--uin", "--icqq-yaml", "--data-dir", "--platform", "--ver", "--wait"])
  for (let i = 0; i < argv.length; ++i) {
    const a = argv[i]
    if (takes.has(a)) opt[a.slice(2).replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = argv[++i]
    else if (a.startsWith("--")) opt[a.slice(2).replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = true
    else if (/^\d+$/.test(a)) opt.uin = a
  }
  opt.wait = Number(opt.wait) || 45
  return opt
}

async function main() {
  const opt = parseCli(process.argv.slice(2))
  if (opt.help) {
    console.log(fs.readFileSync(__filename, "utf8").replace(/^#!.*\r?\n/, "").split("*/")[0].replace(/^\/\*\*?/, "").replace(/^ \* ?/gm, ""))
    return
  }
  if (!opt.uin) throw new Error("请提供 QQ 号")

  const yamlPath = path.resolve(opt.icqqYaml || path.join(TRSS_DIR, "config", "ICQQ.yaml"))
  const y = readYamlToken(yamlPath, opt.uin)
  const token = opt.token || y.token
  if (!token) throw new Error(`没有在 ${yamlPath} 找到该号的 token 行，请用 --token 传入`)

  const parts = token.split(":")
  const uin = Number(parts.shift())
  const password = parts.shift()
  const platform = Number(parts.shift() || opt.platform || y.platform || 2)
  const ver = parts.shift() || opt.ver || y.ver || ""
  const sign = parts.join(":") || y.sign || ""

  const { icqq, pkg } = await loadIcqq()
  console.log(`[diag] 使用 icqq ${pkg.name}@${pkg.version}（${pkg.version.startsWith("0") ? "旧协议，非 NTQQ" : "NT 版本"}）`)
  console.log(`[diag] useNTLogin 支持：${typeof icqq.createClient === "function" ? "待创建后检测" : "?"}`)

  const dataDir = path.resolve(opt.dataDir || path.join(TRSS_DIR, "data", "icqq", String(uin)))
  const logger = {}
  for (const lv of ["trace", "debug", "info", "mark", "warn", "error", "fatal"]) {
    logger[lv] = (...args) => console.log(`[icqq:${lv} ${stamp()}]`, ...args.map((a) => (typeof a === "string" ? a : describe(a))))
  }

  const bot = icqq.createClient({ data_dir: dataDir, platform, ver, sign_api_addr: sign, cache_group_member: false })
  bot.logger = logger

  console.log(`[diag] 创建完成：useNTLogin=${!!bot.useNTLogin}  平台=${bot.config?.platform}/${bot.apk?.display}  apk=${bot.apk?.ver}`)
  attachLoginDiagnostics(bot, { id: uin, dataDir, logger, password, verbose: !!opt.verbose, platform })

  if (opt.preflight) {
    await preflight({ uin, dataDir, platform, ver, sign, password, logger })
    const s = await querySignVersion(sign)
    if (s.reachable) console.log(`[diag] 签名服务可达，上报协议版本=${s.version || "(未上报)"}`)
    else console.log(`[diag] 签名服务不可达：${s.error}`)
    return
  }

  let settled = false
  const finish = (code, why) => {
    if (settled) return
    settled = true
    console.log(`[diag] ${why}`)
    setTimeout(() => process.exit(code), 300)
  }
  bot.once("system.online", () => finish(0, "✔ 登录成功"))
  bot.once("system.login.error", (d) => finish(3, `✖ 登录失败：${d?.message} (${d?.code}) → ${attributeLoginError(d)}`))

  console.log("[diag] 开始登录 ...")
  bot.login(uin, password).catch((e) => finish(3, `✖ bot.login 抛错：${e.code ?? ""} ${e.message}`))
  setTimeout(() => finish(5, `⏱ ${opt.wait}s 内未拿到 system.online / system.login.error，请看上面的阶段日志`), opt.wait * 1000)
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(__filename)) {
  main().catch((e) => {
    console.error("[diag] ✖", e.message || e)
    process.exit(1)
  })
}
