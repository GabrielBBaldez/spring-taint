---
name: New rule
about: Suggest a new taint source, sink, or sanitizer
title: "[rule] "
labels: new-rule
---

**Rule type**
- [ ] Source (a new entry point for external data)
- [ ] Sink (a new place where data is consumed dangerously)
- [ ] Sanitizer (a method that makes data safe)

**Which API / annotation / method**
e.g. `@RabbitListener`, `javax.naming.Context.lookup(String)`, `Jsoup.clean(String)`.
Give the full Tai-e signature if you know it:
`<fully.qualified.Class: ReturnType method(ParamTypes)>`.

**Why it matters**
What real-world flow this catches (or what false positive a sanitizer removes).

**Vulnerable example**
The smallest Spring code the rule should detect (mark the source and the sink):

```java
// source → … → sink
```

**Safe example (if any)**
Code that must NOT be flagged once the rule exists:

```java
```

**References**
Related CVEs, API docs, or write-ups, if any.
