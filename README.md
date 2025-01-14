# Building from Source
Run the following commands:
```
git clone https://github.com/welrox/project-exe/
cd project-exe
mkdir build/
make
```

Note: only macOS is supported for now
# Usage
```
./project-exe [exe-path]
```

This will attempt to produce a native executable `a.out` in the current folder, based on the specified Windows executable.

So far, this tool can only convert a small subset of simple C & C++ command-line programs compiled using [MinGW](https://www.mingw-w64.org/).
