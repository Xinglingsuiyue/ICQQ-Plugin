<div align="center">

# Yunzai ICQQ Plugin

Yunzai ICQQ Bot 适配器 插件

[![Stars](https://img.shields.io/github/stars/Xinglingsuiyue/ICQQ-Plugin?color=yellow&label=收藏)](https://github.com/Xinglingsuiyue/ICQQ-Plugin/stargazers)
[![Downloads](https://img.shields.io/github/downloads/Xinglingsuiyue/ICQQ-Plugin/total?color=blue&label=下载)](https://github.com/Xinglingsuiyue/ICQQ-Plugin/archive/main.tar.gz)
[![Releases](https://img.shields.io/github/v/release/Xinglingsuiyue/ICQQ-Plugin?color=green&label=发行版)](https://github.com/Xinglingsuiyue/ICQQ-Plugin/releases/latest)

</div>

## 安装

```sh
git clone https://github.com/Xinglingsuiyue/ICQQ-Plugin.git ./plugins/ICQQ-Plugin
cd plugins/ICQQ-Plugin
pnpm install
```

## 格式示例

- 密码登录：QQ号 `114514` 密码 `1919810` 登录设备 `安卓手机(1)/平板(2)`

```
#QQ设置114514:1919810:2
```

- 扫码登录：QQ号 `114514` 登录设备 `安卓手表(3)`

```
#QQ设置114514::3
```

## 使用教程

- #QQ账号
- #QQ设置 + `QQ号:密码(留空扫码):登录设备:版本号:独立签名地址`
- #QQ签名 + `签名服务器地址`
