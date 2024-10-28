# Building from Source
Run the following commands:
```
git clone https://github.com/welrox/project-exe/
make
```

Note: only macOS is supported for now
# Usage
```
./project-exe [exe-path]
```

This will attempt to produce a native executable `a.out` in the current folder, based on the specified Windows executable.

Note that the output executable `a.out` must be in the same directory as the `dlls` folder (i.e. the root folder of the git repo).
