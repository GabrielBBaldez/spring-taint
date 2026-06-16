---
name: Bug report
about: A false positive/negative, a crash, or wrong output
title: "[bug] "
labels: bug
---

**What happened**
A clear description of the bug.

**Type**
- [ ] False negative (a real vulnerability was not reported)
- [ ] False positive (a safe flow was reported)
- [ ] Crash / error
- [ ] Wrong output (location, trace, SARIF, …)

**Minimal example**
The smallest Spring code that reproduces it (source → sink), and the command you ran:

```bash
java -jar spring-taint-all.jar scan <classes> --libs <classpath>
```

**Expected vs actual**
What you expected the analyzer to report, and what it actually reported.

**Environment**
- Version / commit:
- Java version used to run the analysis (must be 17):
- OS:
