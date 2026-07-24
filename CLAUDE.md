# @smart-wing/auth — 开发规范

本仓库是 Smart Wing 平台的共享认证包（`@smart-wing/auth`），门户（签发方）与
各业务模块（验签方）共用同一份实现——见 `README.md` "为什么要有这个包"。

它是平台共享规则里的 **platform-core** 一类仓库（GitHub Topic:
`platform-core` + `smart-wing-platform`，见平台规则 8.1），不是走契约优先
生成流程的业务模块，所以不套用 `smart-wing-portal/templates/CLAUDE.md`
里那些跟"模块"相关的规则（`contracts/`、`form-schema.json`、
`registry/modules.json` 注册这些不适用于本仓库）。

适用于本仓库的平台共享约束：
- 不直接 commit 到 `main`；改动走 `feature/简短描述` 分支 → PR → 等
  `.github/CODEOWNERS` 里的协调人 review。
- 端口、主机名、绝对路径等环境相关值不写死进 tracked 源码。
- 密钥/凭证不进代码、fixture、日志、文档。

如果本仓库恰好和 `smart-wing-portal` 以同级目录 checkout 在同一个
workspace 下（多仓库联调场景，见
`smart-wing-portal/docs/workspace-agents.md`），额外遵守那边记录的多仓库
协作规则（合并协调、部署协调、多主机注意事项）；单独 clone/`npm install`
本仓库（作为依赖包使用）时不需要，也不依赖那个 workspace 结构存在。

完整的平台强制规则源文本在
`smart-wing-portal/templates/CLAUDE.md`——本仓库不维护一份平行拷贝，避免
出现"改一处忘改另一处"的重复问题（这在其他模块仓库已经踩过一次坑）。
