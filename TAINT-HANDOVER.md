# ZIPPER 污点分析交接文档（2026-11-02）

给下一个会话用：环境、改哪里、怎么编译、怎么跑实验、功能开关、已知坑。

## 1. 环境与路径

- 远程：`jmliang@172.28.8.69`，容器 `php84-dev`。
- 仓库：宿主 `/home/jmliang/ZIPPER-SourceCode` = 容器 `/home/so/ZIPPER-SourceCode`。
- 共享目录：宿主 `/tmp/share` = 容器 `/home/so/share`（分析输出、日志、rc 文件都放这里）。
- 远程执行：本地用 `node "$(cygpath -w ~/rx.cjs)" "<命令>"` 或 `--file <脚本>`；本地临时源码副本在 `~/zwork`。
- 同步文件：本地修改后用 base64 写回远端，例如
  `echo '<base64 -w0 file>' | base64 -d > /home/jmliang/ZIPPER-SourceCode/...`。
- 测试目标：
  - xvwa：容器 `/app/xvwa`
  - WordPress 子集：容器 `/home/so/wp-sub2`（39 个文件），CPG 在 `/home/so/share/wp-sub-full/cpg.bin`（干净版，不要删）
  - 全量 WP：`/app/wordpress/wp-includes`（1059 PHP，全量跑很重，见第 6 节）
- 配置：容器 `/home/so/zipper-test/sink.json`、`source.json`、`navi-xvwa.json`、`navi-wp4.json`（default→sqlRead→Xss）。

## 2. 改哪里

核心污点逻辑：`zipper-core/src/main/java/bee/zipper/core/analysis/taint/`
- `DefaultTaintAnalysis.scala`：主流程（引擎→去重→增强→裁剪→slice/flow/graph）
- `TaintPath.scala`：路径模型（sinkOverride/trimmed/dataflowNodes/middleNode/optionalGuards）
- `ControlStructurePathEnhancer.scala`：控制结构增强（只插条件+控制节点+依赖语句）
- `TaintControlFlowProvenance.scala`：条件溯源（逆向 16 跳、按 control 缓存、taint marks）
- `PathFeasibility.scala`：保留数据流主干 + 跨上下文增加节点过滤
- `BranchTrimming.scala`：互斥分支裁剪
- `GuardOptionality.scala`：guard 默认值判定（optionalGuards）
- `SqlProbe.scala`：sqlquery 扩展 probe 选择
- `TaintSlice.scala`：slices/flows/graphs 的构建与源码回读
- `EmptySinkControlFlowTracer.scala`、`ImplicitTaintEnhancer.scala`、`SinkGroupMerger.scala`、`PathChainMerger.scala`、`PathFilter.scala`

引擎（vendored joern）：`zipper-core/src/main/scala/io/joern/dataflowengineoss/queryengine/`
- `Engine.scala`：`EngineConfig`（`sharedTable`、`narrowUnresolvedCalls`）
- `TaskCreator.scala`：未解析/外部调用展开控制
- `SharedResultTable.scala`：跨 probe 复用结果表的 LRU

CLI：
- `zipper-scan/src/main/java/bee/zipper/cli/scan/BasicConfig.scala`（选项）
- `zipper-scan/src/main/java/bee/zipper/cli/scan/cmd/TaintModule.scala`（输出 JSON、系统属性、pass）
- `zipper-scan/src/main/java/bee/zipper/cli/scan/cmd/NaviAnalysis.scala`（navi 分段/拼接/桥接）

配置资源：`zipper-core/src/main/resources/taint/{sink,source,sanitizer}/php/builtin.json`

## 3. 编译

```bash
docker exec -d php84-dev bash -c 'cd /home/so/ZIPPER-SourceCode && \
  mvn -B -o package -DskipTests > /home/so/share/build.log 2>&1; echo $? > /home/so/share/build.rc'
# 轮询 /tmp/share/build.rc，0 即成功；grep 'BUILD SUCCESS' /tmp/share/build.log
```

- 必须加 `-o`（离线），否则可能卡在远程仓库元数据下载。
- 构建会触发 scalafmt 重排源码：**不要用未格式化的原文做字符串替换**；先 `cat` 远端文件再精确替换，替换后 `grep` 验证。
- 提交身份：`git -c user.name="ZIPPER Dev" -c user.email="dev@example.com" commit -m "..."`
- 修改后要重启 java 才会生效。

## 4. 跑实验

通用命令（容器内 `/app`）：

```bash
docker exec -d php84-dev bash -c 'cd /app && java -Xmx24g -Xss16m \
  -Dzipper.controlflow.provenance.depth=16 \
  -jar /home/so/ZIPPER-SourceCode/zipper-scan/target/zipper-scan-jar-with-dependencies.jar taint \
  --enable-deduplicate-flow --enable-enhanced-dynamic-call \
  --enable-indirect-superglobal-fetching --enable-object-data-dependency \
  --enable-sanitizer-keyword-match --fix-joern-call-graph \
  --enable-wordpress --enable-ControlStructure --enable-Implicit-taint \
  --enable-shared-result-table \
  --output-dir=/home/so/share/<out> \
  --custom-sink=/home/so/zipper-test/sink.json \
  --custom-source=/home/so/zipper-test/source.json \
  --custom-navi=/home/so/zipper-test/navi-wp4.json \
  <target> > /home/so/share/<out>.log 2>&1; echo $? > /home/so/share/<out>.rc'
```

- xvwa：`--custom-navi=/home/so/zipper-test/navi-xvwa.json /app/xvwa`，`-Xmx4g`，约 2 分钟。
- WP 子集：加 `--load-cpg=/home/so/share/wp-sub-full/cpg.bin /home/so/wp-sub2`，约 7 分钟。
- 输出：`<out>/navi/<chain>/<seg>/taint-analysis-{result,slices,flows,graphs}.json`；joined 在 `joined/`。
- 清空结果：`docker exec php84-dev bash -c 'rm -rf /home/so/share/*'`（**注意保留 cpg.bin**，先拷到别处）。
- 进度：`tail -f /tmp/share/<out>.log | grep -E '\[taint\]|\[controlflow\]|navi\[|joined'`。

## 5. 功能开关一览

| 开关 | 作用 | 默认 |
| --- | --- | --- |
| `--enable-ControlStructure` | 控制流增强（guard 链） | 关 |
| `--enable-Implicit-taint` | 隐式污点（flag 赋值） | 关 |
| `--enable-shared-result-table` | 跨 probe 复用引擎结果表（主要提速手段） | 关 |
| `-Dzipper.taint.sharedTable.max=N` | 共享表 LRU 上限 | 200000 |
| `--narrow-unresolved-calls` | 未解析/外部调用窄化为参数→返回（会丢流，不推荐默认） | 关 |
| `-Dzipper.controlflow.provenance.depth=16` | guard 溯源跳数 | 16 |
| `-Dzipper.controlflow.provenance.nodes=50000` | guard 图节点上限 | 50000 |
| `-Dzipper.taint.progress.chunk=8` | 引擎 probe 进度日志的批次 | 8 |
| `-Dzipper.taint.traceOrigins=true` | 每个节点由哪一步引入（dataflow/control-structure/control-provenance/empty-sink/implicit-taint） | 关 |
| `-Dzipper.taint.traceDeclarations=true` | 最终路径里的参数/方法节点 | 关 |
| `-Dzipper.taint.traceOptional=true` | 每个 guard 的 truth/taken/optional | 关 |
| `-Dzipper.symbolic.print.depth=8` | 符号对象 toString 深度 | 8 |

输出字段：
- `taint-analysis-slices.json`：每个 sink 一条，含 `params`、`sqlProbe`、`optionalGuards`、按行去重的 `nodes`（源码按 file:line 回读）。
- `taint-analysis-graphs.json`：每 sink 的节点/typed edges（data/call-arg/return/field/control）+ `params`/`optionalGuards`。
- `taint-analysis-flows.json`：LLM 友好的紧凑步骤。
- navi 结果：每段单独报告 + `joined/`。

## 6. 已知问题 / 坑

1. **全量 WP 不要直接跑**：开 object-data-dependency 时 MemoryFlowLayer 在 48g 堆仍 OOM；子集 39 文件是验证基准。全量建议分块或先关 object-data-dependency。
2. **-Xss 必须加**（如 `-Xss16m`）：`SymbolicArray.toString` 有自引用，默认栈会 StackOverflow；`-Dzipper.symbolic.print.depth` 只限制打印深度。
3. **声明行**：CPG 里那些 `function foo(...)` 行实际是 `MethodParameterIn`（行号=签名行）；已用 `param $x` 显示，不要按行号回读签名。
4. **optionalGuards 只标不删**：只有整条 guard 链都默认可满足才真正从 path 删除；当前 WP 上标记 27 条、删除 0（每条链至少有一个需要输入的 guard）。
5. **SqlProbe 覆盖率**：WP 上约一半 probe 落在 `class-wpdb.php` 包装层，因为子集 call graph 解析不到 app 调用点；换全量 `/app/wordpress` 或加“调用点数据流匹配”可能改善。`file` 是扫描根 + 相对路径，子集路径和 Apache 的 `/app/wordpress` 不一致。
6. **`/tmp/share` 清理**：容器内 root 创建的文件宿主要用 `docker exec ... rm -rf`；清理前备份 `wp-sub-full/cpg.bin`。
7. **日志可能很大**：traceOrigins 会产生几十万行；引擎未解析调用会打 `Too many new tasks in expansion...`。
8. **probe 常量剪枝已删除**（收益 0.03%），如需可参考提交 `e7ebe03`。

## 7. 当前结果（2026-11-02）

- WP 子集 `/tmp/share/wp-probe10`：36 sinks，graph 节点总数 852（改动前 wp-probe3 为 2935，-71%），`optionalGuards` 27 条（17 个 slice），joined 39（4 linked）。
- xvwa `/tmp/share/xvwa-opt`：11 slices，optional 5 条，节点数正常。
- 对照：`/tmp/share/wp-probe3`（旧）、`/tmp/share/wp-probe10.log`。

## 8. 后续建议

1. 判据 B：guard 可绕过（数据路径不经过该 guard 也能到 sink）→ 进一步缩短链。
2. optional guard 独立删除策略（只要不是 required guard 的祖先/后代）。
3. SqlProbe：全量 WP 验证；或按调用点数据流匹配补全 app 调用点。
4. probe 预检：不改引擎深度的前提下，用“常量/不可达”证明提前跳过（历史上收益小，谨慎）。
5. 全量 WP 的内存/分块方案。

## 9. 最近提交

```
d83163a Ignore generated report files
5b05203 Mark guards that default values already satisfy
9b6b2f3 Render function parameters as params instead of declaration lines
8f5084c Keep dataflow backbones and prune cross-context additions
4b2102a Drop declarations and opposite-branch nodes from taint paths
f918854 Suggest sqlquery extension probes in taint slices
3e7810b Remove probe, timing and cache instrumentation
5b3218f Add an LRU bound to the shared result table and narrow unresolved calls
257f89f Reuse dataflow engine results across probes
```
