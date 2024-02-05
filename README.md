# iroh-net-ffi

> FFI bindings for [iroh-net](https://crates.io/crates/iroh-net).


## Running Example

```
> cargo build
> cc -o main{,.c} -L target/debug -l iroh_net_ffi -lSystem -lc -lm

# Server
> ./main server

# Client
> ./main client
```

## Building C-headers

```
> cargo run --features headers --bin generate_headers
```
