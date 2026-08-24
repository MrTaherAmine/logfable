# Plugin Development

LogFable reserves the Python entry-point group `logfable.plugins`. Plugins are **trusted Python code** and are not sandboxed.

A plugin distribution can declare:
```toml
[project.entry-points."logfable.plugins"]
my_plugin = "my_package.plugin:PLUGIN"
```

Metadata listing uses Python distribution metadata and does not import the target module. Runtime plugin execution should validate API compatibility before import. The included `examples/plugin/` package demonstrates the contract shape for a report-section plugin.
