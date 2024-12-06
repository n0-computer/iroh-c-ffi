# iroh `C` FFI

> FFI bindings for [iroh](https://crates.io/crates/iroh).


## Running Example

```
> cargo build
> cc -o main{,.c} -L target/debug -l iroh_c_ffi -lSystem -lc -lm

# Server
> ./main server

# Client
> ./main client
```

## Building C-headers

```
> cargo run --features headers --bin generate_headers
```
