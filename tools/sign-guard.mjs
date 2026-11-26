
import { createRequire } from "node:module"
import { ensureSignProxy } from "./sign-proxy.mjs"

export function needSignProxy(addr) {
  try {
    const { hostname } = new URL(addr)
    return /^(sign\.)?qsign\.icu$/i.test(hostname)
  } catch {
    return false
  }
}

function watchSignError(bot, pattern, cmd) {
  let hit = null
  const onLog = msg => {
    const s = String(msg)
    if (s.startsWith("签名api异常") && s.includes(pattern)) hit = s
  }
  bot.on("internal.verbose", onLog)
  return {
    get hit() { return hit },
    off() {
      try {
        if (bot.off) bot.off("internal.verbose", onLog)
        else bot.removeListener("internal.verbose", onLog)
      } catch {}
    },
  }
}

function fixSwitchQQVer(req) {
  try {
    const base = req("./lib/core/base-client.js")
    const BaseClient = base.BaseClient
    if (!BaseClient || BaseClient.prototype.__verFixed) return
    const orig = BaseClient.prototype.switchQQVer
    BaseClient.prototype.switchQQVer = async function (ver = "") {
      const want = this.config.ver
      if (!want) return orig.call(this, ver)
      if (this.config.sign_api_addr && !this.sig.sign_api_init) {
        await this.setSignServer(this.config.sign_api_addr)
      }
      if (this.statistics.ver === want) return false
      let apk
      try {
        apk = this.getApkInfo(this.config.platform, want)
      } catch {}
      if (!apk || apk.ver !== want) {
        return orig.call(this, ver)
      }
      Object.defineProperty(this, "apk", { writable: true })
      this.apk = apk
      Object.defineProperty(this, "apk", { writable: false })
      this.device.apk = apk
      this.statistics.ver = want
      return true
    }
    BaseClient.prototype.__verFixed = true
  } catch {}
}

export function guardSign(icqqDir) {
  const req = createRequire(`${icqqDir}package.json`)
  const qsign = req("./lib/core/qsign.js")
  if (qsign.__signGuarded) return
  qsign.__signGuarded = true

  fixSwitchQQVer(req)

  const origGetT544 = qsign.getT544
  qsign.getT544 = async function (cmd) {
    const w = watchSignError(this, `[qsign]getT544:${cmd}`, cmd)
    try {
      const pkt = await origGetT544.call(this, cmd)
      if (w.hit) {
        const err = new Error(
          `签名服务未返回有效 t544（${w.hit}），已中止本次登录，避免被服务端判为 45/237`,
        )
        err.code = "SIGN_FAILED"
        throw err
      }
      return pkt
    } finally {
      w.off()
    }
  }

  const origGetSign = qsign.getSign
  qsign.getSign = async function (cmd, seq, body) {
    if (this.isOnline) return origGetSign.call(this, cmd, seq, body)
    const w = watchSignError(this, `[qsign]sign:${cmd}`, cmd)
    try {
      const res = await origGetSign.call(this, cmd, seq, body)
      if (w.hit) {
        const err = new Error(
          `登录包签名失败（${w.hit}），已中止本次登录，避免被服务端判为 45/237`,
        )
        err.code = "SIGN_FAILED"
        throw err
      }
      return res
    } finally {
      w.off()
    }
  }
}
