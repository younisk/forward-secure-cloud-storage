# Forward-Secure Cloud Storage (FSCS)

Uses puncturable key wrapping (PKW) to implement forward-secure cloud storage. This project uses Google Cloud Storage (GCS).


## Dependencies

### Google Cloud Storage, GTest, Crypto++, Boost

These dependencies are managed using vcpkg (see vcpkg.json)


### CLI

https://github.com/daniele77/cli

The dependency is integrated using the FetchContent module of CMake (see
the [README](https://github.com/daniele77/cli) on github).

## GCS authorization

Follow https://cloud.google.com/docs/authentication/client-libraries for authentication instructions.

## Client

cmake build target ```client```

The client, called ```client```, is an interactive shell, which provides functionalities to interact with the FSCS system.
The provided functions are listed below. The client provides tab-completion and a command history.

| command      | description                                      |
|--------------|--------------------------------------------------|
| help         | display commands                                 |
| lls [*path*] | list local files                                 |
| ls          | list files (stored in cloud)                     |   
| put         | upload a file or directory                       |
| read        | display the contents of a file (stored in cloud) |
| shred       | shred a file                |
| clean       | delete orphaned files                            |
| rotate-keys     | rotate encryption keys                           |

## Benchmarks

cmake build target ```bench```: benchmark operations (put/get/shred/rot-key), with cloud storage

cmake build target ```bench2```: benchmark using a GitHub history (benchmarks/resources), without cloud storage (local operations only)
