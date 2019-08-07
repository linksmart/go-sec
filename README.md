# Go-Sec: Security Packages for Go
This repository includes security packages for LinkSmart Go services.

It includes the following packages:
* `github.com/linksmart/go-sec/auth` which provides interfaces to obtain and validate OpenID Connect tokens. It also provides an implementation for [Keycloak](https://github.com/keycloak/keycloak). 
* `github.com/linksmart/go-sec/authz` which is a simple rule-based authorization that can be used to implement access control in services after authentication.


For more information, refer to docs:
* [Authentication](https://docs.linksmart.eu/display/LC/Authentication)
* [Authorization](https://docs.linksmart.eu/display/LC/Authorization)

## Development
The dependencies of this package are managed by [Go Modules](https://blog.golang.org/using-go-modules).

Usage documentation are available [here](https://docs.linksmart.eu/display/LC/Authentication+Package).