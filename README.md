# JAQ http

A minimal, idiomatic Clojure library for HTTP.

## Rationale

In a cloud-centric, micro-service dominated world, HTTP is the common protocol
to communicate between the different components of a system.

This library is built from the ground up to depend only on Clojure including
core.async and fully asynchronous using Java NIO primitives.


## Installation

Use in ```deps.edn``` -

```
{com.alpeware/jaq-http {:git/url "https://github.com/alpeware/jaq-http"
                            :sha "LATEST SHA"}}
```

## Status

Alpha stage - not yet production ready and with some changes expected.

## Features

- minimal, idiomatic Clojure library
- data and functional first approach to building modern web applications

## Usage

The following API is provided in `jaq.http.server`:
* `(serve xrf port) ;; start server on port

The following API is provided in `jaq.http.client`:
* `(request xrf opts) ;; perform request


## Example Usage

### Server
```clojure
(require '[jaq.http [server :as server][rf :as rf])

;; start a sample server on port 8080
(server/serve rf/main 8080)
;; =>


```

### Client
```clojure
(require '[jaq.http [client :as client][rf :as rf])

;; simple request
(client/request rf/main {:host "google.com" :path "/")
;; =>

;; eval w/ session
(repl/session-repl {:input ":bar"})
;; =>


```

## Acknowledgments

Several concepts are inspired by the [Clojure][clojure], [Giraffe][giraffe]
and [http4s][http4s] projects.

## License

Copyright © 2019 Alpeware, LLC.

Distributed under the Eclipse Public License, the same as Clojure.

[clojure] https://clojure.org/reference/transducers
[http4s] https://http4s.org/
[giraffe] https://github.com/giraffe-fsharp/Giraffe
