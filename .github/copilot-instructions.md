# GitHub Copilot 指令 — @smart-wing/auth（共享认证包）

完整规则见本仓库根目录的 `AGENTS.md`。生成代码前请先读那份文件；这里只是
补充的强提醒——Copilot 不一定会主动去读链接指向的文件。

- 本仓库是 platform-core 一类的共享包（门户签发、各模块验签共用同一份
  实现），不是走契约优先生成流程的业务模块——不要往这里加
  `contracts/schema.prisma`/`form-schema.json` 这类只属于业务模块的东西。
- 对外发布走 git tag（`npm install
  "git+https://github.com/GEHC-WX/smart-wing-auth.git#<tag>"`），改动要考虑
  对所有下游模块（门户 + 三个业务模块）的兼容性，不是只改自己这一个仓库。
- 密钥/凭证不进代码、fixture、日志、文档；`*.pem`/`*.key` 一律 gitignore。
- 不直接 commit 到 `main`：新分支 → commit → push → `gh pr create` → 停下
  等人工 review。
