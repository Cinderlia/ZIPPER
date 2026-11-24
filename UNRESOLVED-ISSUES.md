# Zipper taint 分析：已知未修复问题清单

记录时间：2026-11-21 起（容器 `php84-dev`），2026-11-22 追加第 10、11 节
用途：本阶段排查 openemr / bWAPP / showdoc / DVWA / phpMyFAQ / yeswiki 时发现的、**尚未修复**的问题。每条都带最小复现和实测结果，方便以后接手。
已实现的功能开关见 `FEATURES.md`。

复现工程都在 `/home/so/share/`（宿主 `/tmp/share/`），统一用
`--custom-navi=/home/so/share/navi-read-xss.json`（单段 `sqlRead → Xss`）、
`--custom-sink=/home/so/zipper-test/sink.json`、`--custom-source=/home/so/zipper-test/source.json`，
并带 `--enable-object-data-dependency`（除特别说明）。

---

## 1. 跨方法对象字段丢失（P1，影响面最大）

**现象**：字段在 A 方法写、在 B 方法读，污点丢失；同方法内读写则正常。

| 复现 | 结果 |
|---|---|
| `p1.php`：`function f($v){ $this->x = $v; echo $this->x; }` | ✅ 1 条 |
| `p2.php`：`$q->set2($c['u']); echo $q->get2();`（`set2` 写 `$this->x`，`get2` 返回 `$this->x`） | ❌ 0 条 |
| `p3.php`：`__construct($v){ $this->x=$v; }` + `get3(){ return $this->x; }` | ❌ 0 条 |

目录：`/home/so/share/t-pl11`（p1/p2/p3）。

**真实影响**：
- `controllers/C_Prescription.class.php:575`（`echo $p->patient->get_name_display()`）——`Patient::populate()` 写 `$this->fname/$this->lname`，`get_name_display()` 读；`library/classes/Patient.class.php:73-76`。
- `interface/patient_file/summary/create_portallogin.php:79` 链路中的 `setData()/getData()`（见问题 3）。

**根因**：对象字段的污点只在“同一方法内写后读”时保留，跨方法没有字段摘要（field summary）。

**修复方向**：给每个类字段建“写入方法 → 字段 → 读取方法”的摘要并在调用点代入；或在 ICFG 上为字段建节点。

---

## 2. 把“数组字面量整体”传出去会丢污点（P1）

**现象**：数组字面量在**同作用域**里读下标是通的，但把数组本身（或直接把字面量）作为实参传给函数/方法后，污点丢失。

| 复现 | 结果 |
|---|---|
| `j1.php`：`$arr = ['u' => $c['u']]; echo $arr['u'];` | ✅ |
| `j2.php`：`$arr = []; $arr['u'] = $c['u']; echo $arr['u'];` | ✅ |
| `j3.php`：`$arr = [$c['u']]; echo $arr[0];` | ✅ |
| `n1.php`：`echo (new K1())->passK1(['u' => $c['u']]);` | ❌ 0 条 |
| `n2.php`：`echo passK2(['u' => $c['u']]);` | ❌ 0 条 |
| `n3.php`：`$arr = ['u' => $c['u']]; echo (new K3())->passK3($arr);` | ❌ 0 条 |

目录：`/home/so/share/t-pl9`（j）、`/home/so/share/t-pl10`（n）。

**真实影响**：`create_portallogin.php:79` 的第三个实参是数组字面量 `['login_uname' => $credentials['portal_login_username'], ...]`。

**修复方向**：让数组字面量的“元素污点”同时挂到数组变量/实参节点上（现在只挂在 `indexAccess` 读上）。

---

## 3. Twig 模板里的 sink 不在 CPG 里（P2）

`create_portallogin.php:79 echo $patientAccessOnSiteService->filterTwigTemplateData($pid,'patient/portal_login/print.html.twig',[...])`：

- 真正的注入点在 `templates/patient/portal_login/print.html.twig:83 <input ... value="{{ login_uname }}">`（`autoescape=false`，`src/Common/Twig/TwigContainer.php:67`）；
- `.twig` 不在 PHP CPG 中，`filterTwigTemplateData()`（`src/Services/PatientAccessOnsiteService.php:192-212`）返回 `$this->twig->render($templateName, $paramData)`，`render` 也没建模成“回显 data 数组”。

**修复方向**：把模板文件作为 sink 建模（或把 `render($name,$data)` 视为“data 全部回显”），并保留模板名到数据键的映射。

---

## 4. gad7：CPG 有链，整库规模下引擎不展开（P2，暂时放弃）

`interface/forms/gad7/view.php:102/247 echo text($obj[...])`（`$obj = formFetch("form_gad7", $_GET["id"])`）。

- 已排除：sink 已识别、source 已识别（`[navi-debug] sql source: ... view.php:29 formFetch(...)`）、flag 无关；
- 隔离工程 `/home/so/share/t-oe`（真实 view.php + library/{api.inc.php,sql.inc.php,htmlspecialchars.inc.php} + globals.php）用同一套 flags → **10 条** flow；
- 整库 CPG 里这条链存在（javac 探针 `Probe13.java`：`formFetch(29) → $obj(29) → $obj["nervous_score"](102) → text(102) → echo(102)`，CFG 也连通）；
- 全库只这一类 `echo text($obj[...])` 为 0，其它 74 条 `echo text($row[...])` 都能出。

**结论**：不是建模/C PG 缺边，而是整库规模下没展开（或算出来后被后处理丢弃）。下一步可用 joern 片段 `snk.reachableByFlows(src).p` 判断是引擎侧还是 `DefaultTaintAnalysis.scala:127-151` 的过滤侧。

---

## 5. `import_template.php:362` 未连（P2）

- `echo text($content)` 是 `renderEditorHtml($_REQUEST['docid'], $template_content)` 的实参；同文件 `:59 echo $template['template_content']` 已能出（2 条）。
- `:305 $template_content = $content['template_content'];` → `:312 renderEditorHtml($_REQUEST['docid'], $template_content)` → 函数内 `echo text($content)`。
- 断点未定位到最小用例（介于“参数进函数”和“text() 调用”之间）。

---

## 6. 通用 DB 帮助函数让报告量偏大（P2）

openemr 单段 `sqlRead → Xss` 过滤噪声后仍有 **3833 条**：

- `library/options.inc.php` 一个文件 1181 条、`interface/reports/clinical_reports.php` 248、`library/translation.inc.php` 193；
- 这些是“`sqlQuery(...)` 读库 → `generate_display_field()`/`text()` 输出”的**真**数据流，只是不是 CVE sink。

**方向**：源过滤已到极限（`xpath->query`/`$tpl->fetch` 一共才一百来个），要继续降噪得在**报告侧**做优先级/通用输出点过滤（例如把 `options.inc.php` 这类通用渲染函数降权），而不是删源。

---

## 7. showdoc 型“上传文件 → 静态回显”完全没建模（P1，针对该类 CVE）

`D:\files\Second Order\实验\dbfuzz\showdoc\` 那批 15 条 CVE 全部落在 `Attachment*`，链路是：
`$_FILES['tmp_name']` → `move_uploaded_file()` → `./../Public/Uploads/xxx.aspx` → Web 服务器当 HTML 静态返回。

现状：
- `$_FILES` **不是 source**（内置 globals 只有 `_REQUEST/_POST/_GET/HTTP_*_VARS/_SERVER`）；
- `move_uploaded_file` 属 `FileManipulation`，不属 `Xss`；
- 没有“写文件 → 静态目录可访问 → 浏览器执行”的桥；
- `header("location:$url")` 不在任何 sink kind 里（Xss 名单没有 `header`）；
- ThinkPHP 的 `where(...)->find()` 不在 `sqlQueries.methods`，`SqlStatementClassifier` 也看不到 SQL 文本 → 连 sqlRead 源都不是；
- 2.10.4 已被白名单封堵（`AttachmentModel.class.php:324-339 isAllowedFilename()`），要走通得回退 v2.10.3。

---

## 8. Splendor 的表/列二阶桥依赖建表 DDL（P2）

`SplendorModule` → `TwoPhaseTaintAnalysis` 按“表+列”合并 write→read。bWAPP 建表 SQL 不在 PHP 源码里，实测 `/home/so/share/bwapp-splendor/database-schema.json` = `{"tables": []}`，桥为空。

---

## 附：本阶段已修复（供对照）

| 提交 | 内容 |
|---|---|
| `cfa6ea0` | 单次 `ptsOf` 加查询内 memo + 深度上限，修 openemr VSA 阶段近指数回溯（原来半小时卡死在第一个查询） |
| `a20f7ab` | 超全局容器 + 下标跨文件桥（`$_SESSION[...]` 等，`--enable-global-data-dependency`），bWAPP `xss_stored_3` 因此可出 |
| `0721514` | 报告里带上“构造 SQL 的那一行”（`$sql = "SELECT ..."`） |
| `fc146e9` | SQL 源匹配大小写不敏感 + 常见 DB 包装（`sqlQuery`/`sqlStatement`/`fetchRecords`/`Execute` 等） |
| `9878261` | sqlRead 源过滤：`query/execute/exec/prepare/fetch/fetchAll` 无可见 SQL 文本时不再当源（`$xpath->query()`、`$tpl->fetch()` 等噪声） |
| `29c9a5d` | 修 `MemoryCache` 锁内求值导致的死锁（DVWA 卡在 memory def-use 阶段） |
| `87c0671` | 新增本文件（未修问题清单） |
| `4e6d2ed` → `d6cb55e` | 同类别 `$this->f` 字段桥（`--enable-field-summary=class`）：先是 key 里字段名丢失，后改为按 `类::字段` 分键并加限流 |
| `121dfba` | `class+global`：把 `<global>` 文件的 `$this->f` 接到唯一类，并解析这类文件里 `$this->Method(...)` 的接收者 |
| `e4104dd` | callable 回调解析（`--enable-callback-flow`，默认开） |
| `370d354` | 输出缓冲捕获（`--enable-output-buffer`，实验） |

---

## 9. phpMyFAQ：源与 sink 两头都断（Twig 未建模）（P1，当前暂停）

phpMyFAQ 4.1.1 上单段 `sqlRead → Xss` 实测 **0 条**，两段也是 0 条。两头都断：

- **源**：`grep -rhoE "\$_(GET|POST|REQUEST|COOKIE|SERVER)\b" /app/phpmyfaq --include=*.php` 零命中 → `default sources=0`。phpMyFAQ 4.x 用 Symfony HttpFoundation（`$request->query->get(...)` / `$request->request->get(...)`），超全局只出现在被排除的 `src/libs` 里。
- **sink**：CPG 里只有 95 个 Xss sink，且全是报错/调试 `echo`（`src/phpMyFAQ/Core/Error.php:63-65`、`Database.php:105`、`Instance/Database/{Mysqli,PdoMysql}.php:376-378` 等）。真实页面输出全走 Twig（`{{ answer|raw }}`、`{{ renderComments|raw }}`），而 **`.twig` 不在 CPG 里**（`FILE` 节点只有 `.php`；php2cpg 不解析 Twig）。

已实现的桥（**实验性，默认关闭**，需 `--enable-twig-sinks`）：
- `zipper-core/src/main/java/bee/zipper/core/cpgcreation/php/passes/TwigRenderPass.scala`：从 `MetaData.ROOT` 起扫 `.twig`（跳过 `vendor,libs,node_modules,fonts`），用 `{{ ... }}` 正则取变量名与行号；再找 `loadTemplate('./faq.twig')` / `render($vars)` 这类模板引用，为每个 `|raw` 变量造一个合成 `echo` 调用（`code = "<twig 模板:行> {{ name|raw }}"`），把 PHP 侧 `$vars['name'] = ...` 的赋值右值用 `REACHING_DEF` 连到该调用，并把该调用接进所在方法的 CFG/AST。
- 接线在 `zipper-scan/src/main/java/bee/zipper/cli/scan/CpgGeneration.scala`（`if (c.enableTwigSinks)`，开关在 `BasicConfig.scala`）。

实测状态（**未打通**）：
- phpMyFAQ 生成式跑（`--exclude-dirs=vendor,libs,fonts --enable-global-data-dependency --enable-twig-sinks`，输出 `/home/so/share/phpmyfaq-twig2`）：日志 `Bridged ... Twig sinks`，sink 数 95 → 1863，但 `sqlRead -> Xss: 0 paths`。
- 最小复现 `/home/so/share/t-twig`（`$row = $stmt->fetch(); $vars["name"] = $row["name"]; $tpl = $twig->loadTemplate("./t.twig"); echo $tpl->render($vars);` + `tpl/t.twig` = `{{ name|raw }}`）：`Bridged 1 values into 1 Twig sinks`，`sql sources=2`、`Xss:2`、**`paths=0`**。
- 即“合成 sink 节点已经建出来，但 taint 引擎不认为可达”。已确认不是持久化问题（必须走生成流程；对已存 CPG 用 `Cpg.withStorage(path,false)` + pass 的改动不会落盘）。

**下一步（待办）**：
1. 用 `$_POST` 源 + `{{ name|raw }}`（不经过 SQL）跑最小用例，判断是合成 sink 的 `ARGUMENT`/`CFG` 建模不被引擎接受，还是 `$row["name"]` 这层 def-use 断了；
2. 若 sink 建模有问题，参考 `DefaultTaintAnalysis.scala:235-251` 的 `extractSinks`（probe = `CallArgumentSink` 的 arguments，sink = 该 call），核对合成节点的 `ARGUMENT` 边是否带 `ARGUMENT_INDEX`、是否需要真实 `METHOD_PARAMETER_IN`；
3. 修好后重跑 phpMyFAQ，统计 6 条 4.1.1 CVE（CVE-2026-46367/46363/56736/46361/46360/85593）里能连上几条；
4. 之后再补 Symfony Request 源（`$request->query->get()` 等），否则 phpMyFAQ 仍然没有 `default` 源。

注：`.twig` 不进 CPG 也是 openemr CVE-2026-33303（`templates/patient/portal_login/print.html.twig:83`）连不上的同一原因（见问题 3）。

---

## 10. YesWiki 4.6.5：页面正文链的三个断点（P1/P2，2026-11-22 整理）

启用 `--enable-field-summary=class+global` 后页面正文链路已能定位到具体断点（第二段 `sqlRead → Xss` 从 6 条到 14 条，但仍不含页面正文）。四个断点：

### 10a. 数组字面量整体传递丢污点（P1，误报偏多，暂缓）

`includes/services/PageManager.php` 的 `getOne()`：

```php
$page = $this->checkEntriesACL([$page], $tag, $userNameForCheckingACL)[0];
```

`[$page]` 作为实参传进方法再取 `[0]`，污点在这一跳丢失。最小复现：`/home/so/share/t-fg11`（`return ['body' => $_GET[$tag]]`）→ 0 条；`/home/so/share/t-fg12`（同一结构但返回标量 `$_GET[$tag]`）→ 1 条。

- 收益：页面正文的读点能打开（`$this->page['body']` → 76 个 handler 读点、25 个 `echo ... Format(...)`），量级到几百条；顺带修 openemr 的 `create_portallogin.php:79`、`import_template.php:362`。
- 代价/风险：数组当一个聚合值传，元素之间会混流（`$a['x']` 会继承 `$b['y']`），误报明显；需要“只桥同一字面量、同一形参的元素键”之类的约束才可控。
- 状态：**用户决定暂缓**（“a 误报比较多，到时候再说”）。

### 10b. callable 回调不可达（已修）

`formatters/wakka.php:59`：

```php
$text = preg_replace_callback("/.../", [$this, 'callback'], $text);
```

第二个实参在 CPG 里是空 `Block`（前端把它降级成 `$tmp0[0] = $this; $tmp0[1] = "cb"` 这样的赋值块，自身 `code` 为空），回调方法 `YesWiki\WikiniFormatter->callback` 没有任何 `CALL`/`REF` 入边，于是 `formatters/wakka.php:422` 这个 sink 在图上不可达。

已由新增 `CallbackFlowPass` 修复（`--enable-callback-flow`，默认开）：解析 callable 名字（字符串 / `[$this,'m']` / `'Cls::m'`），解析目标必须唯一（优先调用所在类，其次全库唯一同名），补 `CALL` 边 + 把 subject 实参的污点导到回调参数与参数读点。最小用例 `/home/so/share/t-cb`、`t-cb2`、`t-cb3` 均能出路径。

### 10c. `Format()` 的返回值经输出缓冲回传（P1，未修）

`handlers/page/show.php:65` 是 `echo $this->Format($this->page['body'], 'wakka', $this->GetPageTag());`，而 `Format()` 自身：

```php
// includes/YesWiki.php:825
return $this->services->get(Performer::class)->run($formatter, 'formatter', compact('text'));
```

`Performer::run` → `runFileInBuffer()`：`ob_start()` + `extract($vars)` + `include $___file;`，formatter 文件里的 `return` / `$plugin_output_new` 才把内容带回。

- 需要建模：服务定位器（`$this->services->get(...)`）→ `ob_start()`/`ob_get_clean()` 的缓冲区语义 → 动态 include 目标的返回值 → `extract()` 把实参数组摊成局部变量。
- 影响：即使 10a 修好，`handlers/page/show.php:65`、`tools/templates/handlers/page/html.php:10`、`tools/rss/handlers/page/xml.php:18` 仍到不了 echo。
- 规避：不追 `Format` 返回值，只认直接输出点 `handlers/page/css.php:15 echo $this->page['body']`、`handlers/page/raw.php:9`、`tools/bazar/handlers/page/raw.php:9`（这些只等 10a）。
- 风险：容易把无关 include 的输出串进来，误报中低。

### 10d. Twig `|raw` 仍是实验性（P2，见第 3、9 条）

`--enable-twig-sinks` 能造出 sink 节点，但“data 数组 → 模板变量”这一跳没打通，最小用例仍 0 条。

### 10e. 上传文件 → 静态回显（见第 7 条）

`tools/bazar/fields/FileField.php:184 move_uploaded_file(...)`：`$_FILES` 不是 source，`move_uploaded_file` 只属 FileManipulation，`files/` 目录由 Web 服务器静态返回，不在“读库 → 回显”模型内。

### 10c 进度（2026-11-22）

已实现**输出缓冲捕获**这一半，作为实验开关 `--enable-output-buffer`（默认关，提交见下）：

- 每个方法内 `ob_start()` 之后的第一个 `ob_get_clean()`/`ob_get_contents()`/`ob_end_clean()` 视为窗口终点；
- 窗口内 `echo/print/print_r/printf/vprintf/var_dump/exit/die` 的实参 → 捕获调用（`$html = ob_get_clean()` 即 `$html`）；
- 窗口内**目标可静态解析**的 `include/require`（字符串字面量、以 `.php` 结尾）→ 把被 include 文件里输出调用的实参也接到捕获值，一层；
- 目标为变量的 include（如 `runFileInBuffer()` 里的 `include $___file`）跳过，避免把所有文件串进来。

实测 yeswiki（全套 flags + `--enable-field-summary=class+global --enable-output-buffer`）：`Bridged 186 output buffer flows in 19 capture windows (4 without a capture call)`，第二段 14 → **15** 条，唯一新增是 `handlers/page/acls.php:84 echo → :99 $content = ob_get_clean() → :101 echo $content`——真实的捕获回传，不是噪声机制（来源仍是不重要的 `prefered_language` 链）。

仍缺的一半：`include $___file`（`Performer::runFileInBuffer`）的目标是运行时拼出来的，需要把 `Performer::TYPES` 的目录规则 + `runFileInBuffer($file, $vars)` 的实参二者结合才能定位 formatter 文件；另外页面正文还要先过 10a。所以在 10a 与 include 目标解析完成前，CVE-2026-104466 仍出不来。

---

## 11. 待办总表（2026-11-22 整理，按建议顺序）

| # | 问题 | 优先级 | 现状 | 说明 |
|---|---|---|---|---|
| 10a | 数组字面量整体传递丢污点（`getOne` 的 `[$page][0]`） | P1 | 未做 | 收益最大（页面正文几百条 + openemr `create_portallogin.php:79`、`import_template.php:362`），但元素混流导致误报偏多，用户要求暂缓 |
| 10c-2 | `Performer::runFileInBuffer` 的动态 include 目标解析 | P1 | 未做 | `include $___file`，需用 `Performer::TYPES` 的目录规则（`formatters/`、`handlers/`、`actions/`）+ 调用点实参定位文件；是 CVE-2026-104466 出路径的最后一跳 |
| 10d / 3 / 9 | Twig `|raw` sink | P1 | 实验开关 `--enable-twig-sinks` | 能造 sink 节点，但“PHP 数组 → 模板变量”未打通，最小用例 0 条 |
| 10e / 7 | 上传文件 → 静态回显 | P1（对该族 CVE） | 未做 | `$_FILES` 非 source、`move_uploaded_file` 属 FileManipulation、静态目录回显未建模；CVE-2026-104461 / showdoc 系列都卡在这 |
| 4 | gad7：整库规模下引擎不展开 | P2 | 放弃 | CPG 里链齐全（探针证实），小工程能出 10 条 |
| 5 | `import_template.php:362` | P2 | 未做 | `renderEditorHtml()` 参数进函数后到 `text()` 未连，疑与 10a 同源 |
| 6 | 通用 DB 帮助函数让报告量大 | P2 | 部分缓解 | 噪声过滤只削 ~5%，大头是真 DB 包装（`library/options.inc.php` 一个文件 1181 条） |
| 8 | Splendor 表/列桥依赖建表 DDL | P2 | 未做 | bWAPP 无 DDL，`database-schema.json` 为空 |
| 3.3 误报 | `class+global` 字段桥的跨字段串链 | P2 | 有旋钮 | 已收紧（读点 ≤200、写点 ≤2、`<global>` 字段 ≤3 类）；openemr 仍新增约 100 条 `fpdf`/`options.inc.php` 噪声 |
| 12 | `$arr[$var]` 写入不产生内存定义（数组图缺边） | P2 | 未做 | `MemoryUtils.getMemPtrs` 的 `<operator>.indexAccess` 只认 `StringLiteral`/`IntLiteral` 下标，`$sComment[$plg_fundID] = $aRow['plg_comment']` 这类写入被丢，读点自然拿不到污点。ChurchCRM 实测（见 §12）：新增 sink 行 71、误报约 70%，唯一直接收益是 CVE-2026-40483（`PledgeEditor.php:734`）。建议做成默认关的开关 `--enable-index-write-flow` |

---

## 12. `$arr[$var]` 写入桥的收益/误报估算（2026-11-24，ChurchCRM 7.0.0 实测，未实现）

**问题**：`MemoryUtils.getMemPtrs`（`zipper-core/.../reachingdef/mem/MemoryUtils.scala:47-57`）只为字面量下标造 `ArrayIndexPtr`；变量下标读写一律丢。读侧影响较小（读未知下标有整数组兜底），**写侧**则完全不产生内存定义，污点进不了数组。

**复现**：`PledgeEditor.php:182-189`（`$rsAmounts = RunQuery($sSQL)` → `while ($aRow = mysqli_fetch_array($rsAmounts))` → `$sComment[$plg_fundID] = $aRow['plg_comment']`）→ `:715 foreach (...)` → `:734 value="<?= $sComment[$fun_id] ?>"`；CVE-2026-40483。

**量化（探针 `Probe67.java`，CPG `/home/so/share/churchcrm-full/cpg.bin`，691,829 节点）**：

| 指标 | 数量 |
|---|---|
| `$arr[...]` 写入点总数 | 12,658 |
| 其中下标为字面量（已支持） | 10,569 |
| 用变量下标的数组 | 162 个 |
| 同文件 echo 读这些数组的行（潜在新 sink） | 90 行 |
| 已在 `reg4-crm`(66 行) / `ext-crm`(203 行) 结果中 | 1 / 19 |
| **全新 sink 行** | **71** |

**误报构成**（对 90 行分类）：
- 30 行（42%）输出已包 `escapeAttribute/escapeHTML/htmlspecialchars` → 硬误报；
- 约 20 行（28%）是 `FamilyEditor.php:845-904` 的 `echo $aGenders[$iCount] == 0 ? "selected" : ""`，实际只输出常量 `"selected"` → 结构性误报；
- 1 行 `(int)` 强转，另有一批 ID/编号回显（`EditEventTypes.php:210`、`EventNames.php:310/315/319`）；
- 约 20 行像真字段回显（`GroupView.php:280/281`、`PledgeEditor.php:720-734`、`GeoPage.php:380`、`FamilyEditor.php:856/860`）。

**结论**：相对 extract 桥（+137 行、噪声约 1/3、补上 5/6 条 CVE），`$arr[$var]` 桥规模更小（+71 行、flow 约 200–300）但噪声更高（约 70%），可用增量约 20 行，唯一明确收益是 CVE-2026-40483。**决定：暂不实现，记入待办**。
