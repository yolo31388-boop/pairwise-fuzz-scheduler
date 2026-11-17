# pairwise-fuzz-scheduler

覆盖率引导的模糊测试跑了 24 小时还在啃同一个入口：corpus 只按文件大小淘汰，稀有路径的种子被删；coverage bitmap 用全局哈希，碰撞后新边被当成旧边；能量调度按固定次数，深路径永远分不到 mutation；crash 去重只看返回地址，ASan 和 UBSan 的同源崩溃被算成两个；超时种子没有隔离，慢输入占满 worker；重启后没有恢复 corpus 和进度，上一轮白跑。security/fuzz_scheduler.py 是核心，tests/test_fuzz_scheduler.py 15个红。要修的是：稀有路径保留；边计数防碰撞；能量按深度/新颖度；崩溃栈去重；慢种子隔离；状态持久化。

## 运行

```bash
python -m pytest tests -q
```

初始状态：15 个用例失败。修复实现使全部用例通过，不要修改 `tests/` 下的测试。

子方向：漏洞检测与攻防；任务类型：Bugfix；语言/框架：Python 3, pytest；环境可复现等级：无外部依赖。
