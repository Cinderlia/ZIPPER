# Zipper 功能开关速查

本文只讲**已经做完、可以直接用**的功能开关：每个开关做什么、怎么开、代价大概多少。未修复的问题见
`UNRESOLVED-ISSUES.md`。

---

## 0. 基础命令

生成 CPG 并分析（旗舰命令，包含目前全部增益开关）：

```bash
docker exec -it php84-dev bash -c 'cd /app && java -Xmx24g -Xss16m \
  -Dzipper.controlflow.provenance.depth=16 \
  -jar /home/so/ZIPPER-SourceCode/zipper-scan/target/zipper-scan-jar-with-dependencies.jar taint \
  --enable-deduplicate-flow \
  --enable-enhanced-dynamic-call \
  --enable-indirect-superglobal-fetching \
  --enable-object-data-dependency \
  --enable-sanitizer-keyword-match \
  --fix-joern-call-graph \
  --enable-ControlStructure \
  --enable-Implicit-taint \
  --enable-include-scope \
  --enable-global-data-dependency \
  --enable-field-summary=class+global \
  --output-dir=/home/so/share/<项目名>-full \
  --custom-sink=/home/so/zipper-test/sink.json \
  --custom-source=/home/so/zipper-test/source.json \
  --custom-navi=/home/so/zipper-test/navi-wp4.json \
  --exclude-dirs=vendor \
  /app/<项目名>'
```

复用已有 CPG（不重新解析源码，迭代配置时用这个，快很多）：

```bash
--load-cpg=/home/so/share/<项目名>-full/cpg.bin
```

注意：`--load-cpg` 只重跑分析，**不会**重跑 CPG 生成阶段的 pass（超全局桥、字段桥、回调、缓冲等），
而这些 pass 的边是写进 CPG 的。改了这类开关必须重新生成 CPG。

`--exclude-dirs` 的语义：写 `vendor` 会排除**任意层级**名为 `vendor` 的目录（不只是根目录）；也接受路径片段。

---

## 1. 场景（`--scan-scenarios`）

一次扫描按场景分目录输出，`<output-dir>/scenarios/<场景名>/`。

| 场景 | 含义 |
|---|---|
| `once-xss` / `once-sql` | 一次性漏洞：请求 → 直接进 sink；会过滤掉“经由数据库中转”的路径 |
| `second-xss` / `second-sql` | 二次漏洞：请求 → 读库 → sink（两段 navi） |
| `second-injection` | 请求 → 写库 |

多选：`--scan-scenarios=once-xss,second-xss`。不传该参数时，若给了 `--custom-navi`，直接按 navi 配置跑。

---

## 2. navi 两段链（`--custom-navi`）

配置文件里的链由“段”组成，每段是 `source → sink`，段之间用 `join` 串起来：

```json
{
  "chains": [
    {
      "name": "wp-default-sql-xss",
      "segments": [
        {"source": "default", "sink": "sqlRead"},
        {"source": "sqlRead", "sink": "Xss"}
      ],
      "join": true
    }
  ]
}
```

只跑第二段（“读库 → sink”）就把 `segments` 写成一段 `{"source": "sqlRead", "sink": "Xss"}`，`join: false`。

可用的 source 选择器：`default`（请求源）、`sql` / `sqlQuery` / `sqlRead`（读库调用）、`wpobject`、`fileread`。
可用的 sink 选择器：`sqlRead`、`sqlWrite`、`sql`、`sqlQuery`、或任意 sink kind 名（如 `Xss`、`FileManipulation`）。

输出：`<output-dir>/navi/<链名>/1-<段名>/`、`2-<段名>/`、`joined/`，每层都有
`taint-analysis-flows.json` / `-slices.json` / `-graphs.json` / `-result.json`。

`join` 的语义：把上一段的 sink 节点和下一段的 source 节点按同一节点（或同一 `文件:行:代码` / `文件:行`）拼接；
拼不上的第二段路径会以“只有第二段”的身份进入 joined（所以 joined 条数 ≥ 真正拼接上的条数）。

调试：`-Dzipper.navi.debug=true` 会打印每个 sql source 和每个 sink。

---

## 3. 数据流增强开关（本项目新增）

### 3.1 `--enable-include-scope`

把 `include`/`require` 的被包含文件当作**同一作用域**：调用方在被 include 之前的局部变量赋值，会连到被包含文件里
同名自由变量的读取点，最多向上传播 6 层。

- 收益：`cm_t_list.php` 里构造的 SQL 能连到 `tpl_cm_t_list.php` 里的 `fetch_assoc`/`echo`。
- 代价：很小（只加边），可默认开。

### 3.2 `--enable-global-data-dependency`（超全局容器 + `$GLOBALS`）

在原有的 `$GLOBALS[...]` 桥之外，新增**超全局容器 + 下标**的跨文件桥：`$_SESSION[...]`、`$_COOKIE[...]`、
`$_SERVER[...]`、`$_REQUEST[...]`、`$_GET/$_POST[...]` 等按“容器名 + 下标”配对写入点和读取点。

- 收益：`login.php:68 $_SESSION['login'] = $row->login;` → `xss_stored_3.php:58 $login = $_SESSION['login'];` 这类
  跨文件、经会话的链能通（bWAPP `xss_stored_3` 因此从 0 条变成 2 条）。
- 代价：小（bWAPP 上 814 条边）。每条的读取点上限 5000，超出会截断并告警。

### 3.3 `--enable-field-summary=class|class+global`

把 `$this->f` 当作方法之间的数据通道（字段写入 → 字段读取），这是引擎原生不支持的。

- `class`：只桥同一个类内部的字段读写。
- `class+global`：额外把 `<global>` 方法（被 include 进来、`$this` 仍指向宿主对象的 handler/action 文件）里的
  `$this->f` 读点，接到“字段名能唯一确定到 ≤3 个类”的字段上；并把这类文件里 `$this->Method(...)` 的接收者
  解析到具体类（否则这些调用都是 `<unresolvedNamespace>` 桩）。
- 收益（openemr）：`C_Prescription.class.php:575`（`Patient::populate()` → `get_name_display()`）从 0 条变成 1 条；
  新增路径 +254（含误报，见下）。
- 收益（yeswiki）：`$this->page` 的 76 个 handler 读点接通，第二段 6 → 14 条。
- 代价：openemr 上 64k 条边、运行时间 ~28 分钟（基线 ~20 分钟）、RSS ~30GB。
- 限流参数（`ClassFieldFlowPass` 里可调）：每字段读点上限 200、写点 ≤2 才桥、`<global>` 字段最多 3 个类共享。
- 误报：写点多/同名字段多的类会串（openemr 新增里约 100 条来自 fpdf/options.inc.php 之类的通用 echo）。

### 3.4 `--enable-callback-flow`（默认**开**）

解析传给高阶函数的 callable 实参，把回调体接回调用图。

覆盖：`preg_replace_callback`、`array_map`、`array_filter`、`array_walk`、`usort/uasort/uksort`、`array_reduce`、
`call_user_func`。

做的事：
1. 从 `'func'`、`'Cls::m'`、`[$this,'m']`、`[Foo::class,'m']` 里取出方法名（数组字面量在前端被降级成
   `$tmp0[1] = "m"` 的赋值块，名字藏在 AST 子节点里）；
2. 目标必须唯一：先找调用所在类的同名方法，否则全库唯一同名方法，歧义跳过；
3. 补 `CALL` 边（回调 `return` 的值即高阶调用的值）；
4. 把 subject 实参的污点导到回调参数，以及该参数在回调体内的读取点。

- 收益：`formatters/wakka.php` 的 `preg_replace_callback(..., [$this,'callback'], $text)` 从“回调体不可达”变成可达；
  回调体内直接 `echo` 的 sink 能出路径。
- 代价：可忽略（yeswiki 34 个 callable、125 条边）；未解析的 235 个多为变量回调或同名歧义，属静态不可定。

### 3.5 `--enable-output-buffer`（实验，默认关）

把 `ob_start() … ob_get_clean()` 窗口里的输出，接到捕获值上。

- 窗口内 `echo/print/print_r/printf/var_dump/exit/die` 的实参 → 捕获调用（`$html = ob_get_clean()` 的 `$html`）；
- 窗口内目标可静态解析（字符串字面量、`.php` 结尾）的 `include/require`，把被包含文件里输出调用的实参也接上（一层）；
- 目标是变量的 include（如 `include $___file`）跳过。

- 收益（yeswiki）：`Bridged 186 flows in 19 capture windows`，第二段 14 → 15 条，新增的是
  `handlers/page/acls.php` 自己的捕获回传；`handlers/page/show.php:65 echo $this->Format(...)` 这类仍缺 include 目标解析。
- 代价/误报：小（19 个窗口、186 条边只多 1 条路径）。

### 3.6 `--enable-extract-flow`（实验，默认关）

PHP 的 `extract($row)` 把数据库一行变成一组局部变量：`$aRow = mysqli_fetch_array($rs)` 之后 `extract($aRow)`，
页面就能直接 `echo $per_Facebook`。行的列名只有运行时才知道，前端建不出这些变量，reaching-def 也就没有从取行到
输出的边。本开关补这条边，两道限制：

- **只桥数据库取行结果**：被 extract 的值本身是取行调用（`mysqli_fetch_array`、`PDOStatement::fetch`、
  `fetch_assoc` …），或是从这种调用赋值的变量。项目把请求数据/配置数组 extract 进作用域的情况不动；
- **变量必须没有更早的定义**：形参、或在本次使用之前的赋值（`$name = $_POST['name']`、`$name = legacyFilterInput(...)`）
  都会让这个变量跳过，因为那时打印的已经不是行里的值。

- 用法：`taint ... --enable-extract-flow`（生成 CPG 与 `--load-cpg` 两种模式都生效，`--load-cpg` 时在内存里加边）。
- 收益（ChurchCRM 7.0.0）：`Bridged 8821 extract() flows over 189 row extractions`，第二段 76 → 885 条 /
  76 → 203 个 sink 行，6 条目标 CVE 里 5 条的 sink 出现（`PersonView.php:424/430/436/845`、`FamilyEditor.php:635/652`）。
- 代价/误报：新增 137 个 sink 行里约 15% 的输出已带 `escape*`/`htmlspecialchars`、约 18% 打印的是数值变量
  （`echo $iEventID`、`echo $nEstPrice`），合计约三分之一偏噪声；列名是猜的，抽取变量名与真实列名不一致时不会误报，
  一致时才可能带出无效路径。

### 3.7 `--enable-twig-sinks`（实验，默认关）

按 `.twig` 模板里的 `{{ var|raw }}` 造出合成 echo sink。**目前只造 sink，不打通“PHP 数组 → 模板变量”**，
最小用例仍 0 条路径，暂不建议开。

---

## 4. 引擎/通用开关（有默认值，按需）

| 开关 | 作用 |
|---|---|
| `--enable-enhanced-dynamic-call` | 迭代式动态调用解析 |
| `--fix-joern-call-graph` | 修 joern 调用图里的错误边 |
| `--enable-deduplicate-flow` | 报告里去掉重复流 |
| `--enable-ControlStructure` | 控制结构感知（分支/循环）的路径与 sink 分组 |
| `--enable-Implicit-taint` | 隐式污点（条件依赖） |
| `--enable-sanitizer-keyword-match` | 按关键字识别 sanitizer |
| `--enable-object-data-dependency` | 对象字段的数据依赖（同方法内） |
| `--enable-shared-result-table` | 引擎共享结果表，省内存 |
| `--enable-indirect-superglobal-fetching` | 间接取超全局（`$k='_GET'; $$k[...]`） |
| `--enable-wordpress` | WP 特有建模 |

---

## 5. SQL 源识别与报告行为（默认生效，无需开关）

- **大小写不敏感**：`->Execute()`、`->FetchRow()` 能命中 `execute`、`fetchrow`。
- **常见 DB 包装**：内置 source 配置新增
  `sqlQuery / sqlQueryNoLog / sqlQueryNoLogIgnoreError / sqlStatement / sqlStatementNoLog / sqlStatementThrowException /
  formFetch / fetchRecords / fetchSingleValue / fetchTableColumn / dbQuery / db_select`，以及
  `getAll / getRow / getOne / getAssoc / fetchRow / fetchArray / fetchAssoc / fetchRecords / fetchSingleValue /
  fetchTableColumn` 方法名。openemr/yeswiki 这类“框架包一层”的项目靠这个才认得出读库。
- **噪声过滤**：`query/execute/exec/prepare/fetch/fetchAll` 这些名字如果参数里看不到 SQL 文本，就不再当 sqlRead 源
  （`$xpath->query()`、`$tpl->fetch()` 不再刷屏）；`fetch_object` 这类纯取行方法仍保留。
- **SQL 定义行进报告**：读库调用上游那条 `$sql = "SELECT ..."` 会作为展示节点插入路径（只影响展示，不参与 join）。
- **XSS sanitizer 降优先级**：路径经过 `htmlspecialchars/htmlentities/strip_tags/rawurlencode/urlencode`
  不删除，排到后面并标注，便于先看更可疑的。
- **sink 集合**：同一控制流分支上的多个 sink 归为一个 `sinkSet`，写进 slice/vulnerability/cluster 的 JSON。

---

## 6. 性能相关系统属性（`-D...`）

| 属性 | 默认 | 说明 |
|---|---|---|
| `zipper.vsa.depth` | 4000 | 单次 points-to 查询的递归深度上限（原来靠 `StackOverflowError` 截断，openemr 会卡死） |
| `zipper.cache.size` | 500000 | VSA 记忆化缓存容量（原来是 3000，大项目等于没缓存） |
| `zipper.cache.ttl.minutes` | 1440 | 缓存有效期，`0` 表示不过期 |
| `zipper.controlflow.provenance.depth` | 16 | 控制流溯源深度 |
| `zipper.controlflow.provenance.nodes` | 50000 | 控制流溯源节点上限 |
| `zipper.navi.debug` | false | 打印 navi 的 sql source / sink 清单 |
| `zipper.reachingdef.debug` | false | 打印 reaching-def 迭代进度 |

`-Dzipper.taint.progress.chunk` 目前**没有实现**，传了也无害。

---

## 7. 输出结构

```
<output-dir>/
  cpg.bin
  navi/<链名>/{1-段名,2-段名,joined}/
      taint-analysis-flows.json      # 每条路径的 source/sink/steps
      taint-analysis-slices.json     # 按行聚合的切片
      taint-analysis-graphs.json     # 图视图
      taint-analysis-result.json     # 按漏洞类型聚合的 cluster
  scenarios/<场景名>/                # 用 --scan-scenarios 时
```

---

## 8. 改代码后怎么构建

```bash
docker exec -d php84-dev bash -lc 'cd /home/so/ZIPPER-SourceCode && \
  mvn -B -o package -DskipTests > /home/so/share/build.log 2>&1; echo $? > /home/so/share/build.rc'
```

`-o`（离线）必须带；构建过程会跑 scalafmt，所以别手改格式后直接断言编译通过，改完用 `grep` 复核。
