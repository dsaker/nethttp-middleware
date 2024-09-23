// Package middleware implements middleware function for net/http compatible router
// which validates incoming HTTP requests to make sure that they conform to the given OAPI 3.0 specification.
// When OAPI validation fails on the request, we return an HTTP/400.
package nethttpmiddleware

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/gorillamux"
)

const ContextKey = "oapi-codegen/nethttp-context"

// store holds the contextData and can be looked up using the contextKey that is passed back
// in the response Context
var store = make(map[string]*contextData)

// contextData holds the values added by Put that can be looked up using the contextKey in store
type contextData struct {
	deadline time.Time
	values   map[string]interface{}
	mu       sync.Mutex
}

// ErrorHandler is called when there is an error in validation
type ErrorHandler func(w http.ResponseWriter, message string, statusCode int)

// MultiErrorHandler is called when oapi returns a MultiError type
type MultiErrorHandler func(openapi3.MultiError) (int, error)

// Options to customize request validation; openapi3filter specified options will be passed through.
type Options struct {
	Options           openapi3filter.Options
	ErrorHandler      ErrorHandler
	MultiErrorHandler MultiErrorHandler
	// SilenceServersWarning allows silencing a warning for https://github.com/deepmap/oapi-codegen/issues/882 that reports when an OpenAPI spec has `spec.Servers != nil`
	SilenceServersWarning bool
	// Deadline time in seconds contextData will persist
	Deadline time.Duration `default:"5"`
	// ClearStoreInterval is time in seconds between running ClearStore func
	ClearStoreInterval time.Duration `default:"5"`
}

// OapiRequestValidator Creates middleware to validate request by swagger spec.
func OapiRequestValidator(swagger *openapi3.T) func(next http.Handler) http.Handler {
	return OapiRequestValidatorWithOptions(swagger, nil)
}

// OapiRequestValidatorWithOptions Creates middleware to validate request by swagger spec.
func OapiRequestValidatorWithOptions(swagger *openapi3.T, options *Options) func(next http.Handler) http.Handler {
	if swagger.Servers != nil && (options == nil || !options.SilenceServersWarning) {
		log.Println("WARN: OapiRequestValidatorWithOptions called with an OpenAPI spec that has `Servers` set. This may lead to an HTTP 400 with `no matching operation was found` when sending a valid request, as the validator performs `Host` header validation. If you're expecting `Host` header validation, you can silence this warning by setting `Options.SilenceServersWarning = true`. See https://github.com/deepmap/oapi-codegen/issues/882 for more information.")
	}

	router, err := gorillamux.NewRouter(swagger)
	if err != nil {
		panic(err)
	}

	// start clearStore in the background to clear all contextData that are passed deadline
	go ClearStore(options)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// validate request
			statusCode, reqWithContext, err := validateRequest(r, router, options)
			if err != nil {
				if options != nil && options.ErrorHandler != nil {
					options.ErrorHandler(w, err.Error(), statusCode)
				} else {
					http.Error(w, err.Error(), statusCode)
				}
				return
			}

			// serve
			next.ServeHTTP(w, reqWithContext)
		})
	}

}

// validateRequest is called from the middleware above and actually does the work
// of validating a request.
func validateRequest(r *http.Request, router routers.Router, options *Options) (int, *http.Request, error) {

	// Find route
	route, pathParams, err := router.FindRoute(r)
	if err != nil {
		return http.StatusNotFound, r, err // We failed to find a matching route for the request.
	}

	// Validate request
	requestValidationInput := &openapi3filter.RequestValidationInput{
		Request:    r,
		PathParams: pathParams,
		Route:      route,
	}

	contextKey := strconv.FormatInt(rand.Int63n(math.MaxInt64-1), 10)
	requestContext := context.WithValue(r.Context(), ContextKey, contextKey)
	store[contextKey] = &contextData{
		deadline: time.Now().Add(options.Deadline * time.Second).UTC(),
		values:   make(map[string]interface{}),
	}

	if options != nil {
		requestValidationInput.Options = &options.Options
	}

	if err := openapi3filter.ValidateRequest(requestContext, requestValidationInput); err != nil {
		me := openapi3.MultiError{}
		if errors.As(err, &me) {
			errFunc := getMultiErrorHandlerFromOptions(options)
			meInt, meErr := errFunc(me)
			return meInt, r, meErr
		}

		switch e := err.(type) {
		case *openapi3filter.RequestError:
			// We've got a bad request
			// Split up the verbose error by lines and return the first one
			// openapi errors seem to be multi-line with a decent message on the first
			errorLines := strings.Split(e.Error(), "\n")
			return http.StatusBadRequest, r, fmt.Errorf(errorLines[0])
		case *openapi3filter.SecurityRequirementsError:
			return http.StatusUnauthorized, r, err
		default:
			// This should never happen today, but if our upstream code changes,
			// we don't want to crash the server, so handle the unexpected error.
			return http.StatusInternalServerError, r, fmt.Errorf("error validating route: %s", err.Error())
		}
	}

	return http.StatusOK, r.WithContext(requestContext), nil
}

// attempt to get the MultiErrorHandler from the options. If it is not set,
// return a default handler
func getMultiErrorHandlerFromOptions(options *Options) MultiErrorHandler {
	if options == nil {
		return defaultMultiErrorHandler
	}

	if options.MultiErrorHandler == nil {
		return defaultMultiErrorHandler
	}

	return options.MultiErrorHandler
}

// defaultMultiErrorHandler returns a StatusBadRequest (400) and a list
// of all the errors. This method is called if there are no other
// methods defined on the options.
func defaultMultiErrorHandler(me openapi3.MultiError) (int, error) {
	return http.StatusBadRequest, me
}

// Put adds a key and corresponding value to the context data; Any existing
// value for the key will be replaced.
func Put(requestKey string, key string, val interface{}) error {
	cd, ok := store[requestKey]
	if !ok {
		return errors.New("context not found in store")
	}
	cd.mu.Lock()
	cd.values[key] = val
	cd.mu.Unlock()
	return nil
}

// Get returns the value for a given key from the session data. The return
// value has the type interface{} so will usually need to be type asserted
// before you can use it. For example:
//
//	foo, ok := session.Get(r, "foo").(string)
//	if !ok {
//		return errors.New("type assertion to string failed")
//	}
//
// Also see the GetString(), GetInt(), GetBytes() and other helper methods which
// wrap the type conversion for common types.
// from: https://github.com/alexedwards/scs
func Get(requestKey string, key string) interface{} {
	cd, ok := store[requestKey]
	if !ok {
		return errors.New("context not found in store")
	}

	cd.mu.Lock()
	defer cd.mu.Unlock()

	return cd.values[key]
}

// GetInt64 returns the int64 value for a given key from the session data. The
// zero value for an int64 (0) is returned if the key does not exist or the
// value could not be type asserted to an int64.
// from: https://github.com/alexedwards/scs
func GetInt64(requestKey string, key string) int64 {
	val := Get(requestKey, key)
	i, ok := val.(int64)
	if !ok {
		return 0
	}
	return i
}

// ClearStore runs continuously in the background removing all contextData that
// are passed the deadline
func ClearStore(options *Options) {
	for k, _ := range store {
		if store[k].deadline.Before(time.Now()) {
			delete(store, k)
		}
	}

	// time to wait in between ClearStore running
	time.Sleep(options.Deadline * time.Second)
}
