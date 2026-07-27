"""Dataset preparation. Compile Juliet to binaries; emit the sample manifest.

Build each C/C++ case twice: once with symbols (oracle mapping) and once
stripped (what the model sees). Use -DOMITGOOD / -DOMITBAD so a single binary
never contains both the flawed and the fixed variant.
"""
