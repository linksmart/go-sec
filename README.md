# Go-Sec: Security Packages for Go
[![tests](https://github.com/linksmart/go-sec/workflows/tests/badge.svg)](https://github.com/linksmart/go-sec/actions?query=workflow%3Atests)

This repository includes security packages for LinkSmart Go services.

## Import
```
go get github.com/linksmart/go-sec
```

It includes the following packages:
### Auth
[![GoDoc](https://godoc.org/github.com/linksmart/go-sec/auth?status.svg)](https://godoc.org/github.com/linksmart/go-sec/auth)  
Auth consists of the following subpackages:
* `github.com/linksmart/go-sec/auth/obtainer` interface to obtain OpenID Connect tokens
* `github.com/linksmart/go-sec/auth/validator` interface to validate OpenID Connect tokens
* `github.com/linksmart/go-sec/auth/keycloak` with two packages implementating obtainer and validator for Keycloak

Documentation:
* [Authentication](https://github.com/linksmart/go-sec/wiki/Authentication)

### Authz
[![GoDoc](https://godoc.org/github.com/linksmart/go-sec/authz?status.svg)](https://godoc.org/github.com/linksmart/go-sec/authz)  
Package `github.com/linksmart/go-sec/authz` is a simple rule-based authorization that can be used to implement access control in services after authentication.


Documentation:
* [Authorization](https://github.com/linksmart/go-sec/wiki/Authorization)

## Development
The dependencies of this package are managed by [Go Modules](https://blog.golang.org/using-go-modules).
