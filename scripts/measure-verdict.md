# Synthetic verdict benchmark

Build with JDK 21 using `./mvnw.cmd verify`, then run:

```powershell
$env:JAVA_HOME = 'C:/Program Files/Eclipse Adoptium/jdk-21.0.12.101-hotspot'
./scripts/measure-verdict.ps1 -BaselineRef origin/main
```

The optional baseline ref compiles its original `RunReport` into an isolated system-temp
directory, ahead of the packaged app classes. The shared verdict always uses the new
implementation. Without that argument, both paths use the current implementation.
The script extracts dependencies from the built executable jar, compiles `VerdictBench.java`,
and runs with `-Xmx256m`. No server starts and no endpoint is contacted.

The fixture and batch method match issue #62: six passed steps, three exchanges with six
synthetic JSON bodies total, fourteen PASS findings, 4 KiB or 64 KiB padding per body
plus the JSON envelope, 300 warmups per fixture, five alternating batches of 500 full-report
and 100000 shared-verdict operations. A volatile status sink consumes each result.
`System.nanoTime` measures elapsed time; `ThreadMXBean` measures thread allocation.

Measured on Windows, JDK 21.0.12.1, Jackson core/databind 3.1.5, annotations 2.21,
baseline 6a8850e8fd3860c965fa95c8031d3531bef06d54:

| Padding per body | Full report median ?s/op | Shared verdict median ?s/op | Full report median bytes/op | Shared verdict median bytes/op |
| --- | ---: | ---: | ---: | ---: |
| 4 KiB | 369.788 | 0.043 | 107578.9 | 3.2 |
| 64 KiB | 4251.287 | 0.030 | 107538.9 | 0.0 |

Full-report batch means (?s/op):
- 4 KiB: 403.810, 435.652, 369.788, 342.177, 354.873
- 64 KiB: 4237.968, 4819.157, 4251.287, 4200.376, 4340.216

Shared-verdict batch means (?s/op):
- 4 KiB: 0.123, 0.043, 0.061, 0.036, 0.033
- 64 KiB: 0.029, 0.029, 0.036, 0.030, 0.030

Measured allocation falls by more than 99.99% and does not grow with body length.
JIT scalar replacement can eliminate the short-lived summary record; zero measured
allocation does not mean the source never constructs an object. This measures verdict
status extraction only, excluding Micrometer registration and HTTP, and is not an
end-to-end speedup claim. Timing and allocation are evidence, never CI assertions.
