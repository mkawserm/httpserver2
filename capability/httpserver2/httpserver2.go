package httpserver2

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"github.com/julienschmidt/httprouter"
	"github.com/mkawserm/abesh/constant"
	"github.com/mkawserm/abesh/iface"
	"github.com/mkawserm/abesh/logger"
	"github.com/mkawserm/abesh/model"
	"github.com/mkawserm/abesh/registry"
	"github.com/mkawserm/abesh/utility"
	httpServer2Constant "github.com/mkawserm/httpserver2/constant"
	"go.uber.org/zap"
	"io/ioutil"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

var ErrPathNotDefined = errors.New("path not defined")
var ErrMethodNotDefined = errors.New("method not defined")

type EventResponse struct {
	Error error
	Event *model.Event
}

type HTTPServer2 struct {
	mHost string
	mPort string

	mCertFile string
	mKeyFile  string

	mStaticDir  string
	mStaticPath string
	mHealthPath string

	mRequestTimeout           time.Duration
	mDefault404HandlerEnabled bool
	mHandleMethodNotAllowed   bool
	mValues                   model.ConfigMap

	mHttpServer       *http.Server
	mHttpServerMux    *httprouter.Router
	mEventTransmitter iface.IEventTransmitter

	mDefaultContentType string

	mEmbeddedStaticFSMap map[string]embed.FS

	d401m string
	d403m string
	d404m string
	d405m string
	d408m string
	d409m string
	d499m string
	d500m string
}

func (h *HTTPServer2) Name() string {
	return httpServer2Constant.Name
}

func (h *HTTPServer2) Version() string {
	return httpServer2Constant.Version
}

func (h *HTTPServer2) Category() string {
	return string(constant.CategoryTrigger)
}

func (h *HTTPServer2) ContractId() string {
	return httpServer2Constant.ContractId
}

func (h *HTTPServer2) GetConfigMap() model.ConfigMap {
	return h.mValues
}

func (h *HTTPServer2) buildDefaultMessage(code uint32) string {
	return fmt.Sprintf(`
		{
			"code": "SE_%d",
			"lang": "en",
			"message": "%d ERROR",
			"data": {}
		}
	`, code, code)
}

func (h *HTTPServer2) SetConfigMap(values model.ConfigMap) error {
	h.mValues = values
	h.mHost = values.String("host", "0.0.0.0")
	h.mPort = values.String("port", "8080")

	h.mCertFile = values.String("cert_file", "")
	h.mKeyFile = values.String("key_file", "")

	h.mStaticDir = values.String("static_dir", "")
	h.mStaticPath = values.String("static_path", "/static/")
	h.mHealthPath = values.String("health_path", "")

	if !strings.HasSuffix(h.mStaticPath, "/") && len(h.mStaticPath) > 0 {
		h.mStaticPath = h.mStaticPath + "/"
	}

	h.mRequestTimeout = values.Duration("default_request_timeout", time.Second)

	h.mDefault404HandlerEnabled = values.Bool("default_404_handler_enabled", true)
	h.mHandleMethodNotAllowed = values.Bool("handle_method_not_allowed", false)

	h.mDefaultContentType = values.String("default_content_type", "application/json")

	h.d401m = h.buildDefaultMessage(401)
	h.d403m = h.buildDefaultMessage(403)
	h.d404m = h.buildDefaultMessage(404)
	h.d405m = h.buildDefaultMessage(405)
	h.d408m = h.buildDefaultMessage(408)
	h.d409m = h.buildDefaultMessage(409)
	h.d499m = h.buildDefaultMessage(499)
	h.d500m = h.buildDefaultMessage(500)

	return nil
}

func (h *HTTPServer2) getMessage(key, defaultValue, lang string) string {
	data := h.mValues.String(fmt.Sprintf("%s_%s", key, lang), "")

	if len(data) == 0 {
		data = h.mValues.String(key, defaultValue)
	}

	return data
}

func (h *HTTPServer2) getLanguage(r *http.Request) string {
	l := r.Header.Get("Accept-Language")
	if len(l) == 0 {
		l = "en"
	}

	return l
}

func (h *HTTPServer2) SetEventTransmitter(eventTransmitter iface.IEventTransmitter) error {
	h.mEventTransmitter = eventTransmitter
	return nil
}

func (h *HTTPServer2) GetEventTransmitter() iface.IEventTransmitter {
	return h.mEventTransmitter
}

func (h *HTTPServer2) AddEmbeddedStaticFS(pattern string, fs embed.FS) {
	// NOTE: must be called after setup otherwise panic will occur
	h.mEmbeddedStaticFSMap[pattern] = fs
}

func (h *HTTPServer2) TransmitInputEvent(contractId string, inputEvent *model.Event) {
	if h.GetEventTransmitter() != nil {
		go func() {

			err := h.GetEventTransmitter().TransmitInputEvent(contractId, inputEvent)
			if err != nil {
				logger.L(h.ContractId()).Error(err.Error(),
					zap.String("version", h.Version()),
					zap.String("name", h.Name()),
					zap.String("contract_id", h.ContractId()))
			}

		}()
	}
}

func (h *HTTPServer2) TransmitOutputEvent(contractId string, outputEvent *model.Event) {
	if h.GetEventTransmitter() != nil {
		go func() {
			err := h.GetEventTransmitter().TransmitOutputEvent(contractId, outputEvent)
			if err != nil {
				logger.L(h.ContractId()).Error(err.Error(),
					zap.String("version", h.Version()),
					zap.String("name", h.Name()),
					zap.String("contract_id", h.ContractId()))
			}
		}()
	}
}

func (h *HTTPServer2) New() iface.ICapability {
	return &HTTPServer2{}
}

func (h *HTTPServer2) AddHandlerFunc(method string, pattern string, handler http.HandlerFunc) {
	h.mHttpServerMux.HandlerFunc(method, pattern, handler)
}

func (h *HTTPServer2) AddHandler(method string, pattern string, handler httprouter.Handle) {
	h.mHttpServerMux.Handle(method, pattern, handler)
}

func (h *HTTPServer2) ServeFiles(path string, prefix string, root http.FileSystem) {
	if len(path) < 10 || path[len(path)-10:] != "/*filepath" {
		panic("path must end with /*filepath in path '" + path + "'")
	}

	fileServer := http.FileServer(root)
	h.mHttpServerMux.GET(path, func(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
		if len(prefix) != 0 {
			if strings.HasSuffix(prefix, "/") {
				req.URL.Path = prefix + ps.ByName("filepath")
			} else {
				req.URL.Path = prefix + "/" + ps.ByName("filepath")
			}
		} else {
			req.URL.Path = ps.ByName("filepath")
		}

		fileServer.ServeHTTP(w, req)
	})
}

func (h *HTTPServer2) Setup() error {
	h.mHttpServer = new(http.Server)
	h.mHttpServerMux = httprouter.New()
	h.mHttpServerMux.HandleMethodNotAllowed = h.mHandleMethodNotAllowed
	h.mEmbeddedStaticFSMap = make(map[string]embed.FS)

	// setup server details
	h.mHttpServer.Handler = h.mHttpServerMux
	h.mHttpServer.Addr = h.mHost + ":" + h.mPort

	if h.mDefault404HandlerEnabled {
		logger.L(h.ContractId()).Debug("default 404 handler enabled")
		handler404 := func(writer http.ResponseWriter, request *http.Request) {
			h.debugMessage(request)
			timerStart := time.Now()

			defer func() {
				logger.L(h.ContractId()).Debug("request completed")
				elapsed := time.Since(timerStart)
				logger.L(h.ContractId()).Debug("request execution time", zap.Duration("seconds", elapsed))
			}()
			h.s404m(request, writer, nil)
			return
		}
		h.mHttpServerMux.NotFound = http.HandlerFunc(handler404)
	}

	handlerPanic := func(writer http.ResponseWriter, request *http.Request, i interface{}) {
		h.debugMessage(request)
		logger.L(h.ContractId()).Debug("interface data", zap.Any("interface", i))

		timerStart := time.Now()

		defer func() {
			logger.L(h.ContractId()).Debug("request completed")
			elapsed := time.Since(timerStart)
			logger.L(h.ContractId()).Debug("request execution time", zap.Duration("seconds", elapsed))
		}()

		h.s500m(request, writer, nil)
		return
	}

	h.mHttpServerMux.PanicHandler = handlerPanic

	// register data path
	if len(h.mStaticDir) != 0 {
		fi, e := os.Stat(h.mStaticDir)

		if e != nil {
			logger.L(h.ContractId()).Error(e.Error())
		} else {
			if fi.IsDir() {
				logger.L(h.ContractId()).Debug("data path", zap.String("static_path", h.mStaticPath))
				h.mHttpServerMux.ServeFiles(h.mStaticPath+"*filepath", http.Dir(h.mStaticDir))
			} else {
				logger.L(h.ContractId()).Error("provided static_dir in the manifest conf is not directory")
			}
		}
	}

	// register health path
	if len(h.mHealthPath) != 0 {
		h.mHttpServerMux.HandlerFunc("GET", h.mHealthPath, func(writer http.ResponseWriter, _ *http.Request) {
			writer.WriteHeader(http.StatusOK)
			logger.L(h.ContractId()).Info("HEALTH OK")
		})
	}

	logger.L(h.ContractId()).Info("http server setup complete",
		zap.String("host", h.mHost),
		zap.String("port", h.mPort))

	return nil
}

func (h *HTTPServer2) Start(_ context.Context) error {
	logger.L(h.ContractId()).Debug("registering embedded data fs")
	for p, d := range h.mEmbeddedStaticFSMap {
		if !strings.HasSuffix(p, "/") {
			p = p + "/"
		}

		h.ServeFiles(p+"*filepath", p[0:len(p)-1], http.FS(d))
	}

	logger.L(h.ContractId()).Info("http server started at " + h.mHttpServer.Addr)

	if len(h.mCertFile) != 0 && len(h.mKeyFile) != 0 {
		if err := h.mHttpServer.ListenAndServeTLS(h.mCertFile, h.mKeyFile); err != http.ErrServerClosed {
			return err
		}
	} else {
		if err := h.mHttpServer.ListenAndServe(); err != http.ErrServerClosed {
			return err
		}
	}

	return nil
}

func (h *HTTPServer2) Stop(ctx context.Context) error {
	if h.mHttpServer != nil {
		return h.mHttpServer.Shutdown(ctx)
	}

	return nil
}

func (h *HTTPServer2) writeMessage(statusCode int, defaultMessage string, request *http.Request, writer http.ResponseWriter, errLocal error) {
	if errLocal != nil {
		logger.L(h.ContractId()).Error(errLocal.Error(),
			zap.String("version", h.Version()),
			zap.String("name", h.Name()),
			zap.String("contract_id", h.ContractId()))
	}

	writer.Header().Add("Content-Type", h.mDefaultContentType)
	writer.WriteHeader(statusCode)
	if _, err := writer.Write([]byte(h.getMessage(fmt.Sprintf("s%dm", statusCode), defaultMessage, h.getLanguage(request)))); err != nil {
		logger.L(h.ContractId()).Error(err.Error(),
			zap.String("version", h.Version()),
			zap.String("name", h.Name()),
			zap.String("contract_id", h.ContractId()))
	}
}

func (h *HTTPServer2) s401m(request *http.Request, writer http.ResponseWriter, errLocal error) {
	h.writeMessage(401, h.d401m, request, writer, errLocal)
}

func (h *HTTPServer2) s403m(request *http.Request, writer http.ResponseWriter, errLocal error) {
	h.writeMessage(403, h.d403m, request, writer, errLocal)
}

func (h *HTTPServer2) s404m(request *http.Request, writer http.ResponseWriter, errLocal error) {
	h.writeMessage(404, h.d404m, request, writer, errLocal)
}

func (h *HTTPServer2) s405m(request *http.Request, writer http.ResponseWriter, errLocal error) {
	h.writeMessage(405, h.d405m, request, writer, errLocal)
}

func (h *HTTPServer2) s408m(request *http.Request, writer http.ResponseWriter, errLocal error) {
	h.writeMessage(408, h.d408m, request, writer, errLocal)
}

func (h *HTTPServer2) s499m(request *http.Request, writer http.ResponseWriter, errLocal error) {
	h.writeMessage(499, h.d499m, request, writer, errLocal)
}

func (h *HTTPServer2) s500m(request *http.Request, writer http.ResponseWriter, errLocal error) {
	h.writeMessage(500, h.d500m, request, writer, errLocal)
}

func (h *HTTPServer2) debugMessage(request *http.Request) {
	logger.L(h.ContractId()).Debug("request local timeout in seconds", zap.Duration("timeout", h.mRequestTimeout))
	logger.L(h.ContractId()).Debug("request started")
	logger.L(h.ContractId()).Debug("request data",
		zap.String("path", request.URL.Path),
		zap.String("method", request.Method),
		zap.String("path_with_query", request.RequestURI))
}

func (h *HTTPServer2) AddService(
	authorizer iface.IAuthorizer,
	authorizerExpression string,
	triggerValues model.ConfigMap,
	service iface.IService) error {

	var methodString string
	var path string
	var methodList []string

	// url http access method
	if methodString = triggerValues.String("method", ""); len(methodString) == 0 {
		return ErrMethodNotDefined
	}
	methodString = strings.ToUpper(strings.TrimSpace(methodString))
	methodList = strings.Split(methodString, ",")
	if len(methodList) > 0 {
		sort.Strings(methodList)
	}

	// url http path
	if path = triggerValues.String("path", ""); len(path) == 0 {
		return ErrPathNotDefined
	}
	path = strings.TrimSpace(path)

	requestHandler := func(writer http.ResponseWriter, request *http.Request) {
		var err error
		timerStart := time.Now()
		params := httprouter.ParamsFromContext(request.Context())

		defer func() {
			logger.L(h.ContractId()).Debug("request completed")
			elapsed := time.Since(timerStart)
			logger.L(h.ContractId()).Debug("request execution time", zap.Duration("seconds", elapsed))
		}()

		h.debugMessage(request)

		if !utility.IsIn(methodList, request.Method) {
			h.s405m(request, writer, nil)
			return
		}

		var data []byte

		headers := make(map[string]string)

		metadata := &model.Metadata{}
		metadata.Method = request.Method
		metadata.Path = request.URL.EscapedPath()
		metadata.Headers = make(map[string]string)
		metadata.Query = make(map[string]string)
		metadata.Params = make(map[string]string)
		metadata.ContractIdList = append(metadata.ContractIdList, h.ContractId())
		for _, v := range params {
			metadata.Params[v.Key] = v.Value
		}

		for k, v := range request.Header {
			if len(v) > 0 {
				metadata.Headers[k] = v[0]
				headers[strings.ToLower(strings.TrimSpace(k))] = v[0]
			}
		}

		for k, v := range request.URL.Query() {
			if len(v) > 0 {
				metadata.Query[k] = v[0]
			}
		}

		logger.L(h.ContractId()).Debug("request params",
			zap.Any("params", metadata.Params))

		if authorizer != nil {
			if !authorizer.IsAuthorized(authorizerExpression, metadata) {
				h.s403m(request, writer, nil)
				return
			}
		}

		if data, err = ioutil.ReadAll(request.Body); err != nil {
			h.s500m(request, writer, err)
			return
		}

		inputEvent := &model.Event{
			Metadata: metadata,
			TypeUrl:  utility.GetValue(headers, "content-type", "application/text"),
			Value:    data,
		}

		// transmit input event
		h.TransmitInputEvent(service.ContractId(), inputEvent)

		nCtx, cancel := context.WithTimeout(request.Context(), h.mRequestTimeout)
		defer cancel()

		ch := make(chan EventResponse, 1)

		func() {
			if request.Context().Err() != nil {
				ch <- EventResponse{
					Event: nil,
					Error: request.Context().Err(),
				}
			} else {
				go func() {
					event, errInner := service.Serve(nCtx, inputEvent)
					ch <- EventResponse{Event: event, Error: errInner}
				}()
			}
		}()

		select {
		case <-nCtx.Done():
			h.s408m(request, writer, nil)
			return
		case r := <-ch:
			if r.Error == context.DeadlineExceeded {
				h.s408m(request, writer, r.Error)
				return
			}

			if r.Error == context.Canceled {
				h.s499m(request, writer, r.Error)
				return
			}

			if r.Error != nil {
				h.s500m(request, writer, r.Error)
				return
			}

			// transmit output event
			h.TransmitOutputEvent(service.ContractId(), r.Event)

			//NOTE: handle success from service
			for k, v := range r.Event.Metadata.Headers {
				writer.Header().Add(k, v)
			}

			writer.WriteHeader(int(r.Event.Metadata.StatusCode))

			if _, err = writer.Write(r.Event.Value); err != nil {
				logger.L(h.ContractId()).Error(err.Error(),
					zap.String("version", h.Version()),
					zap.String("name", h.Name()),
					zap.String("contract_id", h.ContractId()))
			}
		}
	}

	for _, method := range methodList {
		h.mHttpServerMux.HandlerFunc(method, path, requestHandler)
	}

	return nil
}

func init() {
	registry.GlobalRegistry().AddCapability(&HTTPServer2{})
}
