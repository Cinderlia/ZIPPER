# NAVI 链契约（下游接口与约束）

本文档定义 NAVI 导航分析对下游（agent、报告生成器、评测脚本）暴露的**稳定接口**：链名、链的语义、输出目录、JSON 字段、漏洞类型对应关系，以及下游必须遵守的约束。链名与目录结构属于契约，不可随意改名；新增链只能追加。

- 实现：`zipper-scan/src/main/java/bee/zipper/cli/scan/cmd/NaviAnalysis.scala`（`NaviConfig.defaultChains`）
- 图形构造：`zipper-core/src/main/java/bee/zipper/core/analysis/taint/TaintSlice.scala`（`SinkGraphBuilder`）
- 提交：`983d59f`（六链 + 单文件输出）、`f91f34a`（二次 SQL 放宽写点）

---

## 1. 调用方式

```bash
# 复用已有 CPG
java -Xmx24g -jar zipper-scan/target/zipper-scan-jar-with-dependencies.jar taint \
  --load-cpg /home/so/share/<app>/cpg.bin \
  --custom-source /home/so/zipper-test/source.json \
  --custom-navi default \
  --output-dir /home/so/share/<app>-navi /home/so/share/<app>-navi

# 从源码构建 CPG（其余参数同上，去掉 --load-cpg，最后给源码目录）
java -Xmx24g -jar zipper-scan/target/zipper-scan-jar-with-dependencies.jar taint \
  --custom-source /home/so/zipper-test/source.json --custom-navi default \
  --output-dir /home/so/share/<app>-navi /app/<app>
```

- `--custom-navi default` 使用**内置六链**（推荐，名字固定）；`--custom-navi <file.json>` 加载同结构的自定义配置（`/home/so/zipper-test/navi-wp4.json` 与内置六链内容一致）。
- `--custom-source` 决定 SQL 源识别范围（`sqlQueries`），不同应用/不同实验之间必须保持一致，否则数字不可比。
- `--enable-navi-debug-dump` 才会额外写出分段目录与 `result/slices/flows`（调试用，默认关闭）。
- `--enable-template-sinks` 会把 Twig 模板与 JS 文件里的输出点也建成 sink（见 §7）。

---

## 2. 六条链

| 链名 | 段（source → sink） | join | 语义 |
|---|---|---|---|
| `xss-direct` | `default → Xss` | 否 | 一次 XSS：请求值直接被输出 |
| `xss-second-order` | `default → sqlRead`；`sqlRead → Xss` | 是 | 二次 XSS：请求值入库，再从库里读出并输出 |
| `sqlwrite-direct` | `default → sqlWrite` | 否 | 一次注入：请求值直接进入写语句（`INSERT/UPDATE/DELETE`） |
| `read-to-write` | `sqlRead → sqlWriteLoose` | 否 | 库中取出的值再次被拼进写语句（二次 SQL 的写回半段） |
| `sqlread-direct` | `default → sqlRead` | 否 | 请求值到达 SQL 读调用（一次 SQL 的读半段，本身不是漏洞） |
| `sqlwrite-second-order` | `default → sqlRead`；`sqlRead → sqlWriteLoose` | 是 | 二次 SQL：请求值入库，库值再进写语句 |

约定：

- 六条链**互不去重**。同一条 sink 行可以同时出现在 `xss-direct` 与 `xss-second-order`，下游按需并集，不做互相删除。
- 段结果会按 `(source, sink, 控制流模式)` 缓存复用：`default → sqlRead` 只算一次，被 `xss-second-order`、`sqlread-direct`、`sqlwrite-second-order` 共用。
- 链内非最后一段启用控制流分析并保留“未被污染的中间 sink”，以便与下一段拼接；最后一段只保留真实污染路径。

---

## 3. 选择器语义

### 3.1 source 选择器

| 选择器 | 含义 |
|---|---|
| `default` | 请求入口：超全局变量直读/间读（`$_GET`、`$_POST`、`$_REQUEST`、`$_COOKIE`、`$_SERVER`、`$_FILES`、`$_SESSION` 等）**加上**配置在 `taint/source/php/builtin.json` 的 `PHP.methods` 里的包装式请求 API（如 `$request->getContent()`、`$request->query->get()`，全部 receiver 限定） |
| `sqlRead` / `sql` / `sqlQuery` | 数据库读调用本身，来自 `PHP.sqlQueries`（`mysqli_query`、`mysql_query`、`pg_query`、`sqlQuery`、`sqlStatement`、`formFetch`、`fetchRecords`、`runQuery` 等），`--custom-source` 可扩充 |
| `fileread` | 文件内容读取调用（`fopen`、`file_get_contents`、`readfile`、`fpassthru`、`fread`、`stream_get_contents`），用于文件系统上的二次流 |
| `wpobject` | WordPress 内容字段读取（`$post->post_content` 等）的特殊缝 |

### 3.2 sink 选择器

| 选择器 | 含义 |
|---|---|
| 任意漏洞类型名 | `Xss`、`SqlInjection`、`CmdInjection`、`CodeInjection`、`FileInclusion`、`FileManipulation`、`ObjectInjection`、`Ssrf`、`LogicFlaws`（大小写不敏感，来自 `taint/sink/php/builtin.json`） |
| `sqlRead` | 第一段终点：既是“读库调用被请求值触及”的 sink，又和第二段的 source 是**同一个调用节点**（拼接依赖这一点） |
| `sqlWrite` | 写点：调用名属于数据库执行器（`query/exec/execute/prepare/.../runQuery`）**且**语句能被判定为 `INSERT/UPDATE/DELETE/...`。按名字与语句判定，不要求接收者类型：应用层数据库包装（`$db->query(...)`）才是注入点最常见的形态 |
| `sqlWriteLoose` | 与 `sqlWrite` 同一解析规则，保留这个名字只为兼容旧配置（报告里 `kind` 记为 `SqlWriteLoose`）。**仅用于二次 SQL 两条链** |
| `sql` / `sqlQuery` | 所有 SQL 类 sink（读 + 写） |

> 写点为什么按名字解析：`$db->query("UPDATE ...")` 里的 `$db` 是框架自己的数据库类，CPG 里没有 `PDO`/`mysqli` 类型信息，按类型匹配会让整类注入点消失（PhoenixCart 的 7 个 `set_flag.php` 全部漏掉）。
>
> 数值强转的口径：`(int) $_GET['id']` 在 SQL sink 上不再中断数据流，请求值到写语句的链路照常报告（`PathFilter` 只对 XSS 等输出类型保留 cast 作为净化）。这类链路在“请求值是否真的能改变 SQL 结构”上需要人工判断。

---

## 4. 拼接（join）规则

两段链（`xss-second-order`、`sqlwrite-second-order`）的产物由以下步骤得到：

1. `prefix.path.last.id() == tail.path.head.id()` 对齐——**同一个读库调用节点**既是第一段的 sink，又是第二段的 source。
2. **额外并入**（`from empty intermediate sinks`）：第二段里 head 未被第一段真实命中的路径单独保留，避免“中间 sink 恰好没被第一段命中就整条丢失”。空 sink（路径长度 1）不并入。
3. 按 `(head.id, last.id, path.size)` 去重。
4. `PathFeasibility.keepConnected` 过滤不可达路径，`BranchTrimming.trim` 裁掉旁支。

日志一行可核对：

```
navi[xss-second-order] joined: 104 paths (6 linked, 101 from empty intermediate sinks)
```

`linked` 是真正拼接成功的条数；括号里的第二部分是“中间 sink 为空而单列”的条数。

---

## 5. 输出目录

```
<out>/navi/
  xss-direct/taint-analysis-graphs.json
  xss-second-order/taint-analysis-graphs.json
  sqlwrite-direct/taint-analysis-graphs.json
  read-to-write/taint-analysis-graphs.json
  sqlread-direct/taint-analysis-graphs.json
  sqlwrite-second-order/taint-analysis-graphs.json
```

- **每条链只有一个文件**：`taint-analysis-graphs.json`。没有 `joined/`，没有 `1-segment-1/`、`2-segment-2/`。
- 链命中为空时目录仍存在，文件内容为 `{"sinkSize":0,"sinks":[]}`。
- 调试模式（`--enable-navi-debug-dump`）会额外写：`<chain>/1-<label>/`、`<chain>/2-<label>/`、`<chain>/joined/`，每个目录含 `taint-analysis-result.json`、`-slices.json`、`-flows.json`、`-graphs.json`。**下游不应依赖这些调试文件。**

---

## 6. 报告格式

### 6.1 `taint-analysis-graphs.json`（下游唯一入口）

```json
{
  "sinkSize": 18,
  "sinks": [
    {
      "kind": "SqlWriteLoose",
      "sink": "sqli_12.php:162  $db->exec($sql)",
      "params": [],
      "nodes": [
        { "id": "n1", "at": "sqli_12.php:154", "code": "$db->query($sql)" },
        { "id": "n2", "at": "sqli_12.php:160", "code": "\"INSERT INTO blog ... VALUES (\" . ++$id . ..." },
        { "id": "n3", "at": "sqli_12.php:162", "code": "$db->exec($sql)" }
      ],
      "edges": [
        { "from": "n1", "to": "n2", "kind": "data" },
        { "from": "n2", "to": "n3", "kind": "data" }
      ],
      "optionalGuards": []
    }
  ]
}
```

| 字段 | 类型 | 语义 |
|---|---|---|
| `sinkSize` | int | **sink 条目数**（不是路径数）。同一 sink 的多个来源/多条路径合并为一条 |
| `sinks[].kind` | string | 该 sink 的漏洞类型或选择器名，见 §8 映射 |
| `sinks[].sink` | string | `"<相对路径>:<行号>  <源码整行>"`（分隔为两个空格；源码行读不到时回退为节点 code） |
| `sinks[].params` | string[] | 从源节点代码里正则抽出的参数名（`$_GET["x"]` → `x`），去重排序，可能为空 |
| `sinks[].nodes[]` | object | 路径上的**代码行**，按 `file:line` 去重，`id` 形如 `n1…nN`（首次出现顺序） |
| `sinks[].nodes[].at` | string | `"<相对路径>:<行号>"`，行号 1-based |
| `sinks[].nodes[].code` | string | 该行源码（过长会截断） |
| `sinks[].edges[]` | object | 有向边，`from`/`to` 是 node id |
| `sinks[].edges[].kind` | string | `data`（数据流）/ `control`（控制流）/ `call-arg`（实参→形参）/ `return`（返回值）/ `field`（对象字段） |
| `sinks[].optionalGuards` | string[] | 路径上可选分支的守卫代码，可能为空 |

**格式约束（下游必须知道）**

1. 只包含 `path.size > 1` 的路径；单节点路径（源即 sink）被丢弃，因此**空结果不等于“没有该链”，只是没有多步链**。
2. `nodes` 是按行去重的**集合 + 边**，不是原始执行序列；还原顺序请按 `edges` 拓扑遍历，不要按数组下标。
3. `sink` 字段里的源码行可能被截断；需要精确源码请按 `at` 的 `file:line` 回读。
4. 一次运行内同一链的 `sinkSize` 与“路径数”不同（一条 sink 可聚合多条路径）；评测按 **sink 行**计数。

### 6.2 切片信息（调试产物，`--enable-navi-debug-dump`）

`taint-analysis-slices.json`：

```json
{"sliceSize": 60,
 "slices": [{
   "kind": "Xss",
   "sinkFile": "header.php", "sinkLine": 22, "sinkCode": "echo \"...\" . ucfirst($_SESSION[\"user\"]) . \"...\"",
   "sqlProbe": {"file": "login.php", "line": 8, "function": "login.php:<global>",
                "code": "$conn1->prepare($sql)", "role": "dispatch", "score": 0.7,
                "reasons": ["query dispatch", "app-level callsite", "SQL built in the same method"],
                "extensionConfig": {"file": "login.php", "line": "8", "output": "result_login_8.json"},
                "alternatives": []},
   "sources": [{"file": "login.php", "line": 8, "code": "$conn1->prepare($sql)", "param": null}],
   "nodeCount": 9,
   "nodes": [{"file": "header.php", "line": 22, "code": "echo ..."}],
   "pathCount": 3,
   "optionalGuards": [],
   "sinkSet": [],
   "reviewPriority": "normal",
   "deprioritizedBy": []
 }]}
```

- `sources` 是**这条切片认定的源**（二次链里就是读库调用），`sqlProbe` 给出“SQL 在哪构建/是否应用层调用”的置信信息（`role`、`score`、`reasons`），仅供人工复核排序。
- 调试文件不承诺稳定，下游不要依赖字段名。

---

## 7. 与其它开关的关系

| 开关 | 影响 |
|---|---|
| `--custom-source <json>` | 扩充 `sqlQueries`（例如 `mysqli_*` 系列）。**不同应用之间要比数字，必须用同一份 source** |
| `--enable-template-sinks` | 把 `{{ x|raw }}` 变成合成 sink（`sink` 形如 `<template assets/templates/default/faq.twig:30> {{ question|raw }}`），把 `*.js` 的 `innerHTML=/.html()/.append()/document.write` 也变成 sink。不开启时，`xss-second-order` 里 Twig/JS 输出点不会出现 |
| `--enable-extract-flow` | 桥接 `extract(mysqli_fetch_array(...))`，ChurchCRM 一类应用的二次 XSS 依赖它 |
| `--enable-output-buffer` | 捕获 `ob_start()+include` 的缓冲输出（PhoenixCart 的模板渲染依赖它） |
| `--enable-field-summary=class\|class+global` | 同类/跨类对象字段读写桥接 |
| `--enable-navi-debug-dump` | 写 §6.2 与分段目录（默认关） |

---

## 8. 漏洞类型对应关系

| 链 | `kind`（报告里的值） | 对应漏洞类型 | CWE | 说明 |
|---|---|---|---|---|
| `xss-direct` | `Xss` | 反射型 XSS | CWE-79 | 请求值直接进入输出点 |
| `xss-second-order` | `Xss` | 存储型 XSS | CWE-79 | 请求值入库、读回、再输出；跨文件/跨请求 |
| `sqlwrite-direct` | `SqlInjection` | 一次 SQL 注入（写） | CWE-89 | 请求值直接拼进写语句 |
| `read-to-write` | `SqlWriteLoose` | 二次 SQL（写回半段） | CWE-89 | 库值再拼进写语句；**单独看不足以定漏洞**，需与 `sqlread-direct` 或 `sqlwrite-second-order` 合看 |
| `sqlread-direct` | `SqlRead` | 请求值到达 SQL 读调用 | — | 不是漏洞本身，是“注入前段/数据来源”的证据 |
| `sqlwrite-second-order` | `SqlWriteLoose` | 二次 SQL 注入（完整链） | CWE-89 | 请求值入库 → 库值 → 写语句 |

补充约定：

- `kind` 是**最终 sink 的选择器名**，不是 CVE 类别。下游把 `SqlWriteLoose` 映射为“二次 SQL 写点”，`SqlInjection` 映射为“一次注入”，`Xss` 区分一次/二次要看它来自哪条链。
- `xss-direct` 与 `xss-second-order` 的 `kind` 都是 `Xss`，**链名才是区分一次/二次的依据**。
- `sqlread-direct` 的 sink 是读库调用本身（`sqlRead` 选择器），因此它永远不是“漏洞”，只是路径上的中间节点集合。

---

## 9. 下游使用约束（重要）

1. **按链读，不要跨链去重**：同一条 sink 出现在多条链是预期行为，链名承载语义。
2. **按 sink 行计数**：`sinkSize` 是 sink 条目数；一条 sink 对应多条路径时不会膨胀。
3. **空结果合法**：某链目录只有 `{"sinkSize":0,"sinks":[]}` 表示该链无多步路径，不代表运行失败。运行失败会有非零退出码/无目录。
4. **不要依赖调试文件**：`result/slices/flows` 与分段目录仅在 `--enable-navi-debug-dump` 下存在；`taint-analysis-result.json` 里的 `command` 字段是复现用的辅助信息。
5. **不要依赖 `sink` 字符串里的源码**：用 `at` 的 `file:line` 回读源码。
6. **比较不同应用的数字时必须固定**：同一 jar、同一 `--custom-source`、同一开关集合（尤其 `--enable-template-sinks`、`--enable-extract-flow`）。
7. `at` / `sink` 是**相对源码根**的路径，换版本会变，不要把它当 CVE 的稳定主键；主键请用 (CVE 编号, 该版本的 file:line)。
8. `sqlWrite` 与 `sqlWriteLoose` 如今同义，两者都带上“数值强转不中断 SQL 链路”的口径；下游统计一次注入时需把经 `(int)`/`(float)` 强转的链路单独计数，它们说明请求值到达了写语句但不一定能改变 SQL 结构。

---

## 10. 已知限制

- **echo 粒度**：sink 以整个 `echo` 调用为单位，任一实参被污染即报（PhoenixCart `:15 echo "...", sprintf(..., htmlspecialchars($name))` 属此类误报）。
- **单节点路径被丢弃**（§6.1 约束 1）：`$x = $_GET['a']; echo $x;` 这种会出现在图里，但“源本身就在输出行”的不会。
- **二次 SQL 覆盖有限**：只有语句能通过局部定义解析为写、且调用名在 26 个执行器内才会被放宽口径识别；`$stmt->bindParam()` 之后 `execute()` 的参数化写法不会报（本来就是安全的）。
- **JS/Twig 深处数据流不做**：`--enable-template-sinks` 只把模板/脚本的输出点建 sink 并按键名桥接，模板内部复杂运算不追。
- **ORM 读库（Propel/Eloquent 等）不是 sqlRead 源**：`findPk()`/`getUserName()` 这类链路会整段缺失（见 `UNRESOLVED-ISSUES.md` §13）。

## 11. WordPress 表级 join（`wp-table-xss`）

WordPress 的读写发生在不同请求、不同文件，中间隔着数据库，节点级拼接天然不通，因此 `--enable-wordpress` 时额外追加一条三段链：

| 段 | source | sink | name |
|---|---|---|---|
| 1 | `default` | `sqlWrite` | `write` |
| 2 | `default` | `sqlRead` | `read` |
| 3 | `wpObject` | `Xss` | `render` |

`bridge = "table+wp"`：先按 **表** 把写路径与读路径接起来（`joinPathsByTable`），再按 WP 对象桥把读路径接到渲染路径（`bridgeWpPaths`）。

表级拼接的收敛条件（缺一不可）：

1. 写、读两侧都能从 SQL 文本里解析出表名（`$wpdb->posts`、`$wpdb->prefix}posts` 等写法都认）；
2. 交集必须命中内容表 `posts / postmeta / comments / commentmeta / terms / term_taxonomy`；
3. 读侧必须能解析出列；解析不出就拒绝（`SELECT *` 视为可覆盖任意列）；两侧都给出列时要求列交集非空；
4. 渲染调用与读库调用必须在**同一文件**（`sameFile`）。渲染锚点是 `Right(class)` 时，用 `wpClassTables` 把 WP 实体类映射回表（`wp_comment` → comments/commentmeta 等）。

实测（WordPress 6.x，`--enable-wordpress`）：`default→sqlWrite` 186、`default→sqlRead` 228、`wpObject→Xss` 255，表级接出 809 条候选、324 条读后渲染，最终 **237 条路径、6 个 sink**。收敛靠的是第 3、4 条：去掉第 4 条会膨胀到 134151 条渲染、12927 条路径。

开关：`--enable-table-join`（默认关，WordPress 模式下自动开启；单独打开时仅对 `bridge` 含 `table` 的链生效）。
