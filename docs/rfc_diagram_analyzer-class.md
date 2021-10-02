# The Alert Class

Figure 8 from the RFC.

```
                +---------------------+
                |      Analyzer       |
                +---------------------+       0..1 +----------+
                | STRING analyzerid   |<>----------|  Node    |
                | STRING name         |            +----------+
                | STRING manufacturer |
                | STRING model        |       0..1 +----------+
                | STRING version      |<>----------| Process  |
                | STRING class        |            +----------+
                | STRING ostype       |       0..1 +----------+
                | STRING osversion    |<>----------| Analyzer |
                +---------------------+            +----------+

                       Figure 8: The Analyzer Class
```