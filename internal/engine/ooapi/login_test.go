// Code generated by go generate; DO NOT EDIT.
// 2021-03-10 13:17:34.605701732 +0100 CET m=+0.000131680

package ooapi

//go:generate go run ./internal/generator -file login_test.go

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/ooni/probe-cli/v3/internal/engine/ooapi/apimodel"
)

func TestRegisterAndLoginPsiphonConfigSuccess(t *testing.T) {
	ff := &fakeFill{}
	var expect apimodel.PsiphonConfigResponse
	ff.fill(&expect)
	registerAPI := &FakeRegisterAPI{
		Response: &apimodel.RegisterResponse{
			ClientID: "antani-antani",
		},
	}
	loginAPI := &FakeLoginAPI{
		Response: &apimodel.LoginResponse{
			Expire: time.Now().Add(3600 * time.Second),
			Token:  "antani-antani-token",
		},
	}
	login := &withLoginPsiphonConfigAPI{
		API: &FakePsiphonConfigAPI{
			WithResult: &FakePsiphonConfigAPI{
				Response: expect,
			},
		},
		RegisterAPI: registerAPI,
		LoginAPI:    loginAPI,
		KVStore:     &MemKVStore{},
	}
	var req *apimodel.PsiphonConfigRequest
	ff.fill(&req)
	ctx := context.Background()
	resp, err := login.Call(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if diff := cmp.Diff(expect, resp); diff != "" {
		t.Fatal(diff)
	}
	if loginAPI.CountCall != 1 {
		t.Fatal("invalid loginAPI.CountCall")
	}
	if registerAPI.CountCall != 1 {
		t.Fatal("invalid registerAPI.CountCall")
	}
}

func TestPsiphonConfigContinueUsingToken(t *testing.T) {
	ff := &fakeFill{}
	var expect apimodel.PsiphonConfigResponse
	ff.fill(&expect)
	registerAPI := &FakeRegisterAPI{
		Response: &apimodel.RegisterResponse{
			ClientID: "antani-antani",
		},
	}
	loginAPI := &FakeLoginAPI{
		Response: &apimodel.LoginResponse{
			Expire: time.Now().Add(3600 * time.Second),
			Token:  "antani-antani-token",
		},
	}
	login := &withLoginPsiphonConfigAPI{
		API: &FakePsiphonConfigAPI{
			WithResult: &FakePsiphonConfigAPI{
				Response: expect,
			},
		},
		RegisterAPI: registerAPI,
		LoginAPI:    loginAPI,
		KVStore:     &MemKVStore{},
	}
	var req *apimodel.PsiphonConfigRequest
	ff.fill(&req)
	ctx := context.Background()
	// step 1: we register and login and use the token
	// inside a scope just to avoid mistakes
	{
		resp, err := login.Call(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if diff := cmp.Diff(expect, resp); diff != "" {
			t.Fatal(diff)
		}
		if loginAPI.CountCall != 1 {
			t.Fatal("invalid loginAPI.CountCall")
		}
		if registerAPI.CountCall != 1 {
			t.Fatal("invalid registerAPI.CountCall")
		}
	}
	// step 2: we disable register and login but we
	// should be okay because of the token
	errMocked := errors.New("mocked error")
	registerAPI.Err = errMocked
	registerAPI.Response = nil
	loginAPI.Err = errMocked
	loginAPI.Response = nil
	resp, err := login.Call(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if diff := cmp.Diff(expect, resp); diff != "" {
		t.Fatal(diff)
	}
	if loginAPI.CountCall != 1 {
		t.Fatal("invalid loginAPI.CountCall")
	}
	if registerAPI.CountCall != 1 {
		t.Fatal("invalid registerAPI.CountCall")
	}
}

func TestPsiphonConfigWithValidButExpiredToken(t *testing.T) {
	ff := &fakeFill{}
	var expect apimodel.PsiphonConfigResponse
	ff.fill(&expect)
	errMocked := errors.New("mocked error")
	registerAPI := &FakeRegisterAPI{
		Err: errMocked,
	}
	loginAPI := &FakeLoginAPI{
		Response: &apimodel.LoginResponse{
			Expire: time.Now().Add(3600 * time.Second),
			Token:  "antani-antani-token",
		},
	}
	login := &withLoginPsiphonConfigAPI{
		API: &FakePsiphonConfigAPI{
			WithResult: &FakePsiphonConfigAPI{
				Response: expect,
			},
		},
		RegisterAPI: registerAPI,
		LoginAPI:    loginAPI,
		KVStore:     &MemKVStore{},
	}
	ls := &loginState{
		ClientID: "antani-antani",
		Expire:   time.Now().Add(-5 * time.Second),
		Token:    "antani-antani-token",
		Password: "antani-antani-password",
	}
	if err := login.writestate(ls); err != nil {
		t.Fatal(err)
	}
	var req *apimodel.PsiphonConfigRequest
	ff.fill(&req)
	ctx := context.Background()
	resp, err := login.Call(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if diff := cmp.Diff(expect, resp); diff != "" {
		t.Fatal(diff)
	}
	if loginAPI.CountCall != 1 {
		t.Fatal("invalid loginAPI.CountCall")
	}
	if registerAPI.CountCall != 0 {
		t.Fatal("invalid registerAPI.CountCall")
	}
}

func TestPsiphonConfigWithRegisterAPIError(t *testing.T) {
	ff := &fakeFill{}
	var expect apimodel.PsiphonConfigResponse
	ff.fill(&expect)
	errMocked := errors.New("mocked error")
	registerAPI := &FakeRegisterAPI{
		Err: errMocked,
	}
	login := &withLoginPsiphonConfigAPI{
		API: &FakePsiphonConfigAPI{
			WithResult: &FakePsiphonConfigAPI{
				Response: expect,
			},
		},
		RegisterAPI: registerAPI,
		KVStore:     &MemKVStore{},
	}
	var req *apimodel.PsiphonConfigRequest
	ff.fill(&req)
	ctx := context.Background()
	resp, err := login.Call(ctx, req)
	if !errors.Is(err, errMocked) {
		t.Fatal("not the error we expected", err)
	}
	if resp != nil {
		t.Fatal("expected nil response")
	}
	if registerAPI.CountCall != 1 {
		t.Fatal("invalid registerAPI.CountCall")
	}
}

func TestPsiphonConfigWithLoginFailure(t *testing.T) {
	ff := &fakeFill{}
	var expect apimodel.PsiphonConfigResponse
	ff.fill(&expect)
	registerAPI := &FakeRegisterAPI{
		Response: &apimodel.RegisterResponse{
			ClientID: "antani-antani",
		},
	}
	errMocked := errors.New("mocked error")
	loginAPI := &FakeLoginAPI{
		Err: errMocked,
	}
	login := &withLoginPsiphonConfigAPI{
		API: &FakePsiphonConfigAPI{
			WithResult: &FakePsiphonConfigAPI{
				Response: expect,
			},
		},
		RegisterAPI: registerAPI,
		LoginAPI:    loginAPI,
		KVStore:     &MemKVStore{},
	}
	var req *apimodel.PsiphonConfigRequest
	ff.fill(&req)
	ctx := context.Background()
	resp, err := login.Call(ctx, req)
	if !errors.Is(err, errMocked) {
		t.Fatal("not the error we expected", err)
	}
	if resp != nil {
		t.Fatal("expected nil response")
	}
	if loginAPI.CountCall != 1 {
		t.Fatal("invalid loginAPI.CountCall")
	}
	if registerAPI.CountCall != 1 {
		t.Fatal("invalid registerAPI.CountCall")
	}
}

func TestRegisterAndLoginPsiphonConfigThenFail(t *testing.T) {
	ff := &fakeFill{}
	var expect apimodel.PsiphonConfigResponse
	ff.fill(&expect)
	registerAPI := &FakeRegisterAPI{
		Response: &apimodel.RegisterResponse{
			ClientID: "antani-antani",
		},
	}
	loginAPI := &FakeLoginAPI{
		Response: &apimodel.LoginResponse{
			Expire: time.Now().Add(3600 * time.Second),
			Token:  "antani-antani-token",
		},
	}
	errMocked := errors.New("mocked error")
	login := &withLoginPsiphonConfigAPI{
		API: &FakePsiphonConfigAPI{
			WithResult: &FakePsiphonConfigAPI{
				Err: errMocked,
			},
		},
		RegisterAPI: registerAPI,
		LoginAPI:    loginAPI,
		KVStore:     &MemKVStore{},
	}
	var req *apimodel.PsiphonConfigRequest
	ff.fill(&req)
	ctx := context.Background()
	resp, err := login.Call(ctx, req)
	if !errors.Is(err, errMocked) {
		t.Fatal("not the error we expected", err)
	}
	if resp != nil {
		t.Fatal("expected nil response")
	}
	if loginAPI.CountCall != 1 {
		t.Fatal("invalid loginAPI.CountCall")
	}
	if registerAPI.CountCall != 1 {
		t.Fatal("invalid registerAPI.CountCall")
	}
}

func TestPsiphonConfigTheDatabaseIsReplaced(t *testing.T) {
	ff := &fakeFill{}
	handler := &LoginHandler{t: t}
	srvr := httptest.NewServer(handler)
	defer srvr.Close()
	registerAPI := &simpleRegisterAPI{
		HTTPClient: &VerboseHTTPClient{T: t},
		BaseURL:    srvr.URL,
	}
	loginAPI := &simpleLoginAPI{
		HTTPClient: &VerboseHTTPClient{T: t},
		BaseURL:    srvr.URL,
	}
	baseAPI := &simplePsiphonConfigAPI{
		HTTPClient: &VerboseHTTPClient{T: t},
		BaseURL:    srvr.URL,
	}
	login := &withLoginPsiphonConfigAPI{
		API:         baseAPI,
		RegisterAPI: registerAPI,
		LoginAPI:    loginAPI,
		KVStore:     &MemKVStore{},
	}
	var req *apimodel.PsiphonConfigRequest
	ff.fill(&req)
	ctx := context.Background()
	// step 1: we register and login and use the token
	// inside a scope just to avoid mistakes
	{
		resp, err := login.Call(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if handler.logins != 1 {
			t.Fatal("invalid handler.logins")
		}
		if handler.registers != 1 {
			t.Fatal("invalid handler.registers")
		}
	}
	// step 2: we forget accounts and try again.
	handler.forgetLogins()
	resp, err := login.Call(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if handler.logins != 3 {
		t.Fatal("invalid handler.logins")
	}
	if handler.registers != 2 {
		t.Fatal("invalid handler.registers")
	}
}

func TestRegisterAndLoginPsiphonConfigCannotWriteState(t *testing.T) {
	ff := &fakeFill{}
	var expect apimodel.PsiphonConfigResponse
	ff.fill(&expect)
	registerAPI := &FakeRegisterAPI{
		Response: &apimodel.RegisterResponse{
			ClientID: "antani-antani",
		},
	}
	loginAPI := &FakeLoginAPI{
		Response: &apimodel.LoginResponse{
			Expire: time.Now().Add(3600 * time.Second),
			Token:  "antani-antani-token",
		},
	}
	errMocked := errors.New("mocked error")
	login := &withLoginPsiphonConfigAPI{
		API: &FakePsiphonConfigAPI{
			WithResult: &FakePsiphonConfigAPI{
				Response: expect,
			},
		},
		RegisterAPI: registerAPI,
		LoginAPI:    loginAPI,
		KVStore:     &MemKVStore{},
		JSONCodec: &FakeCodec{
			EncodeErr: errMocked,
		},
	}
	var req *apimodel.PsiphonConfigRequest
	ff.fill(&req)
	ctx := context.Background()
	resp, err := login.Call(ctx, req)
	if !errors.Is(err, errMocked) {
		t.Fatal("not the error we expected", err)
	}
	if resp != nil {
		t.Fatal("expected nil response")
	}
	if loginAPI.CountCall != 1 {
		t.Fatal("invalid loginAPI.CountCall")
	}
	if registerAPI.CountCall != 1 {
		t.Fatal("invalid registerAPI.CountCall")
	}
}

func TestPsiphonConfigReadStateDecodeFailure(t *testing.T) {
	ff := &fakeFill{}
	var expect apimodel.PsiphonConfigResponse
	ff.fill(&expect)
	errMocked := errors.New("mocked error")
	login := &withLoginPsiphonConfigAPI{
		KVStore:   &MemKVStore{},
		JSONCodec: &FakeCodec{DecodeErr: errMocked},
	}
	ls := &loginState{
		ClientID: "antani-antani",
		Expire:   time.Now().Add(-5 * time.Second),
		Token:    "antani-antani-token",
		Password: "antani-antani-password",
	}
	if err := login.writestate(ls); err != nil {
		t.Fatal(err)
	}
	out, err := login.forceLogin(context.Background())
	if !errors.Is(err, errMocked) {
		t.Fatal("not the error we expected", err)
	}
	if out != "" {
		t.Fatal("expected empty string here")
	}
}

func TestPsiphonConfigTheDatabaseIsReplacedThenFailure(t *testing.T) {
	ff := &fakeFill{}
	handler := &LoginHandler{t: t}
	srvr := httptest.NewServer(handler)
	defer srvr.Close()
	registerAPI := &simpleRegisterAPI{
		HTTPClient: &VerboseHTTPClient{T: t},
		BaseURL:    srvr.URL,
	}
	loginAPI := &simpleLoginAPI{
		HTTPClient: &VerboseHTTPClient{T: t},
		BaseURL:    srvr.URL,
	}
	baseAPI := &simplePsiphonConfigAPI{
		HTTPClient: &VerboseHTTPClient{T: t},
		BaseURL:    srvr.URL,
	}
	login := &withLoginPsiphonConfigAPI{
		API:         baseAPI,
		RegisterAPI: registerAPI,
		LoginAPI:    loginAPI,
		KVStore:     &MemKVStore{},
	}
	var req *apimodel.PsiphonConfigRequest
	ff.fill(&req)
	ctx := context.Background()
	// step 1: we register and login and use the token
	// inside a scope just to avoid mistakes
	{
		resp, err := login.Call(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if handler.logins != 1 {
			t.Fatal("invalid handler.logins")
		}
		if handler.registers != 1 {
			t.Fatal("invalid handler.registers")
		}
	}
	// step 2: we forget accounts and try again.
	// but registrations are also failing.
	handler.forgetLogins()
	handler.noRegister = true
	resp, err := login.Call(ctx, req)
	if !errors.Is(err, ErrHTTPFailure) {
		t.Fatal("not the error we expected", err)
	}
	if resp != nil {
		t.Fatal("expected nil response")
	}
	if handler.logins != 2 {
		t.Fatal("invalid handler.logins")
	}
	if handler.registers != 2 {
		t.Fatal("invalid handler.registers")
	}
}

func TestPsiphonConfigClockIsOffThenSuccess(t *testing.T) {
	ff := &fakeFill{}
	handler := &LoginHandler{t: t}
	srvr := httptest.NewServer(handler)
	defer srvr.Close()
	registerAPI := &simpleRegisterAPI{
		HTTPClient: &VerboseHTTPClient{T: t},
		BaseURL:    srvr.URL,
	}
	loginAPI := &simpleLoginAPI{
		HTTPClient: &VerboseHTTPClient{T: t},
		BaseURL:    srvr.URL,
	}
	baseAPI := &simplePsiphonConfigAPI{
		HTTPClient: &VerboseHTTPClient{T: t},
		BaseURL:    srvr.URL,
	}
	login := &withLoginPsiphonConfigAPI{
		API:         baseAPI,
		RegisterAPI: registerAPI,
		LoginAPI:    loginAPI,
		KVStore:     &MemKVStore{},
	}
	var req *apimodel.PsiphonConfigRequest
	ff.fill(&req)
	ctx := context.Background()
	// step 1: we register and login and use the token
	// inside a scope just to avoid mistakes
	{
		resp, err := login.Call(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if handler.logins != 1 {
			t.Fatal("invalid handler.logins")
		}
		if handler.registers != 1 {
			t.Fatal("invalid handler.registers")
		}
	}
	// step 2: we forget tokens and try again.
	// this should simulate the client clock
	// being off and considering a token still valid
	handler.forgetTokens()
	resp, err := login.Call(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if handler.logins != 2 {
		t.Fatal("invalid handler.logins")
	}
	if handler.registers != 1 {
		t.Fatal("invalid handler.registers")
	}
}

func TestPsiphonConfigClockIsOffThen401(t *testing.T) {
	ff := &fakeFill{}
	handler := &LoginHandler{t: t}
	srvr := httptest.NewServer(handler)
	defer srvr.Close()
	registerAPI := &simpleRegisterAPI{
		HTTPClient: &VerboseHTTPClient{T: t},
		BaseURL:    srvr.URL,
	}
	loginAPI := &simpleLoginAPI{
		HTTPClient: &VerboseHTTPClient{T: t},
		BaseURL:    srvr.URL,
	}
	baseAPI := &simplePsiphonConfigAPI{
		HTTPClient: &VerboseHTTPClient{T: t},
		BaseURL:    srvr.URL,
	}
	login := &withLoginPsiphonConfigAPI{
		API:         baseAPI,
		RegisterAPI: registerAPI,
		LoginAPI:    loginAPI,
		KVStore:     &MemKVStore{},
	}
	var req *apimodel.PsiphonConfigRequest
	ff.fill(&req)
	ctx := context.Background()
	// step 1: we register and login and use the token
	// inside a scope just to avoid mistakes
	{
		resp, err := login.Call(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if handler.logins != 1 {
			t.Fatal("invalid handler.logins")
		}
		if handler.registers != 1 {
			t.Fatal("invalid handler.registers")
		}
	}
	// step 2: we forget tokens and try again.
	// this should simulate the client clock
	// being off and considering a token still valid
	handler.forgetTokens()
	handler.failCallWith = []int{401, 401}
	resp, err := login.Call(ctx, req)
	if err != nil {
		t.Fatal("not the error we expected", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if handler.logins != 3 {
		t.Fatal("invalid handler.logins")
	}
	if handler.registers != 2 {
		t.Fatal("invalid handler.registers")
	}
}

func TestPsiphonConfigClockIsOffThen500(t *testing.T) {
	ff := &fakeFill{}
	handler := &LoginHandler{t: t}
	srvr := httptest.NewServer(handler)
	defer srvr.Close()
	registerAPI := &simpleRegisterAPI{
		HTTPClient: &VerboseHTTPClient{T: t},
		BaseURL:    srvr.URL,
	}
	loginAPI := &simpleLoginAPI{
		HTTPClient: &VerboseHTTPClient{T: t},
		BaseURL:    srvr.URL,
	}
	baseAPI := &simplePsiphonConfigAPI{
		HTTPClient: &VerboseHTTPClient{T: t},
		BaseURL:    srvr.URL,
	}
	login := &withLoginPsiphonConfigAPI{
		API:         baseAPI,
		RegisterAPI: registerAPI,
		LoginAPI:    loginAPI,
		KVStore:     &MemKVStore{},
	}
	var req *apimodel.PsiphonConfigRequest
	ff.fill(&req)
	ctx := context.Background()
	// step 1: we register and login and use the token
	// inside a scope just to avoid mistakes
	{
		resp, err := login.Call(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if handler.logins != 1 {
			t.Fatal("invalid handler.logins")
		}
		if handler.registers != 1 {
			t.Fatal("invalid handler.registers")
		}
	}
	// step 2: we forget tokens and try again.
	// this should simulate the client clock
	// being off and considering a token still valid
	handler.forgetTokens()
	handler.failCallWith = []int{401, 500}
	resp, err := login.Call(ctx, req)
	if !errors.Is(err, ErrHTTPFailure) {
		t.Fatal("not the error we expected", err)
	}
	if resp != nil {
		t.Fatal("expected nil response")
	}
	if handler.logins != 2 {
		t.Fatal("invalid handler.logins")
	}
	if handler.registers != 1 {
		t.Fatal("invalid handler.registers")
	}
}

func TestRegisterAndLoginTorTargetsSuccess(t *testing.T) {
	ff := &fakeFill{}
	var expect apimodel.TorTargetsResponse
	ff.fill(&expect)
	registerAPI := &FakeRegisterAPI{
		Response: &apimodel.RegisterResponse{
			ClientID: "antani-antani",
		},
	}
	loginAPI := &FakeLoginAPI{
		Response: &apimodel.LoginResponse{
			Expire: time.Now().Add(3600 * time.Second),
			Token:  "antani-antani-token",
		},
	}
	login := &withLoginTorTargetsAPI{
		API: &FakeTorTargetsAPI{
			WithResult: &FakeTorTargetsAPI{
				Response: expect,
			},
		},
		RegisterAPI: registerAPI,
		LoginAPI:    loginAPI,
		KVStore:     &MemKVStore{},
	}
	var req *apimodel.TorTargetsRequest
	ff.fill(&req)
	ctx := context.Background()
	resp, err := login.Call(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if diff := cmp.Diff(expect, resp); diff != "" {
		t.Fatal(diff)
	}
	if loginAPI.CountCall != 1 {
		t.Fatal("invalid loginAPI.CountCall")
	}
	if registerAPI.CountCall != 1 {
		t.Fatal("invalid registerAPI.CountCall")
	}
}

func TestTorTargetsContinueUsingToken(t *testing.T) {
	ff := &fakeFill{}
	var expect apimodel.TorTargetsResponse
	ff.fill(&expect)
	registerAPI := &FakeRegisterAPI{
		Response: &apimodel.RegisterResponse{
			ClientID: "antani-antani",
		},
	}
	loginAPI := &FakeLoginAPI{
		Response: &apimodel.LoginResponse{
			Expire: time.Now().Add(3600 * time.Second),
			Token:  "antani-antani-token",
		},
	}
	login := &withLoginTorTargetsAPI{
		API: &FakeTorTargetsAPI{
			WithResult: &FakeTorTargetsAPI{
				Response: expect,
			},
		},
		RegisterAPI: registerAPI,
		LoginAPI:    loginAPI,
		KVStore:     &MemKVStore{},
	}
	var req *apimodel.TorTargetsRequest
	ff.fill(&req)
	ctx := context.Background()
	// step 1: we register and login and use the token
	// inside a scope just to avoid mistakes
	{
		resp, err := login.Call(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if diff := cmp.Diff(expect, resp); diff != "" {
			t.Fatal(diff)
		}
		if loginAPI.CountCall != 1 {
			t.Fatal("invalid loginAPI.CountCall")
		}
		if registerAPI.CountCall != 1 {
			t.Fatal("invalid registerAPI.CountCall")
		}
	}
	// step 2: we disable register and login but we
	// should be okay because of the token
	errMocked := errors.New("mocked error")
	registerAPI.Err = errMocked
	registerAPI.Response = nil
	loginAPI.Err = errMocked
	loginAPI.Response = nil
	resp, err := login.Call(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if diff := cmp.Diff(expect, resp); diff != "" {
		t.Fatal(diff)
	}
	if loginAPI.CountCall != 1 {
		t.Fatal("invalid loginAPI.CountCall")
	}
	if registerAPI.CountCall != 1 {
		t.Fatal("invalid registerAPI.CountCall")
	}
}

func TestTorTargetsWithValidButExpiredToken(t *testing.T) {
	ff := &fakeFill{}
	var expect apimodel.TorTargetsResponse
	ff.fill(&expect)
	errMocked := errors.New("mocked error")
	registerAPI := &FakeRegisterAPI{
		Err: errMocked,
	}
	loginAPI := &FakeLoginAPI{
		Response: &apimodel.LoginResponse{
			Expire: time.Now().Add(3600 * time.Second),
			Token:  "antani-antani-token",
		},
	}
	login := &withLoginTorTargetsAPI{
		API: &FakeTorTargetsAPI{
			WithResult: &FakeTorTargetsAPI{
				Response: expect,
			},
		},
		RegisterAPI: registerAPI,
		LoginAPI:    loginAPI,
		KVStore:     &MemKVStore{},
	}
	ls := &loginState{
		ClientID: "antani-antani",
		Expire:   time.Now().Add(-5 * time.Second),
		Token:    "antani-antani-token",
		Password: "antani-antani-password",
	}
	if err := login.writestate(ls); err != nil {
		t.Fatal(err)
	}
	var req *apimodel.TorTargetsRequest
	ff.fill(&req)
	ctx := context.Background()
	resp, err := login.Call(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if diff := cmp.Diff(expect, resp); diff != "" {
		t.Fatal(diff)
	}
	if loginAPI.CountCall != 1 {
		t.Fatal("invalid loginAPI.CountCall")
	}
	if registerAPI.CountCall != 0 {
		t.Fatal("invalid registerAPI.CountCall")
	}
}

func TestTorTargetsWithRegisterAPIError(t *testing.T) {
	ff := &fakeFill{}
	var expect apimodel.TorTargetsResponse
	ff.fill(&expect)
	errMocked := errors.New("mocked error")
	registerAPI := &FakeRegisterAPI{
		Err: errMocked,
	}
	login := &withLoginTorTargetsAPI{
		API: &FakeTorTargetsAPI{
			WithResult: &FakeTorTargetsAPI{
				Response: expect,
			},
		},
		RegisterAPI: registerAPI,
		KVStore:     &MemKVStore{},
	}
	var req *apimodel.TorTargetsRequest
	ff.fill(&req)
	ctx := context.Background()
	resp, err := login.Call(ctx, req)
	if !errors.Is(err, errMocked) {
		t.Fatal("not the error we expected", err)
	}
	if resp != nil {
		t.Fatal("expected nil response")
	}
	if registerAPI.CountCall != 1 {
		t.Fatal("invalid registerAPI.CountCall")
	}
}

func TestTorTargetsWithLoginFailure(t *testing.T) {
	ff := &fakeFill{}
	var expect apimodel.TorTargetsResponse
	ff.fill(&expect)
	registerAPI := &FakeRegisterAPI{
		Response: &apimodel.RegisterResponse{
			ClientID: "antani-antani",
		},
	}
	errMocked := errors.New("mocked error")
	loginAPI := &FakeLoginAPI{
		Err: errMocked,
	}
	login := &withLoginTorTargetsAPI{
		API: &FakeTorTargetsAPI{
			WithResult: &FakeTorTargetsAPI{
				Response: expect,
			},
		},
		RegisterAPI: registerAPI,
		LoginAPI:    loginAPI,
		KVStore:     &MemKVStore{},
	}
	var req *apimodel.TorTargetsRequest
	ff.fill(&req)
	ctx := context.Background()
	resp, err := login.Call(ctx, req)
	if !errors.Is(err, errMocked) {
		t.Fatal("not the error we expected", err)
	}
	if resp != nil {
		t.Fatal("expected nil response")
	}
	if loginAPI.CountCall != 1 {
		t.Fatal("invalid loginAPI.CountCall")
	}
	if registerAPI.CountCall != 1 {
		t.Fatal("invalid registerAPI.CountCall")
	}
}

func TestRegisterAndLoginTorTargetsThenFail(t *testing.T) {
	ff := &fakeFill{}
	var expect apimodel.TorTargetsResponse
	ff.fill(&expect)
	registerAPI := &FakeRegisterAPI{
		Response: &apimodel.RegisterResponse{
			ClientID: "antani-antani",
		},
	}
	loginAPI := &FakeLoginAPI{
		Response: &apimodel.LoginResponse{
			Expire: time.Now().Add(3600 * time.Second),
			Token:  "antani-antani-token",
		},
	}
	errMocked := errors.New("mocked error")
	login := &withLoginTorTargetsAPI{
		API: &FakeTorTargetsAPI{
			WithResult: &FakeTorTargetsAPI{
				Err: errMocked,
			},
		},
		RegisterAPI: registerAPI,
		LoginAPI:    loginAPI,
		KVStore:     &MemKVStore{},
	}
	var req *apimodel.TorTargetsRequest
	ff.fill(&req)
	ctx := context.Background()
	resp, err := login.Call(ctx, req)
	if !errors.Is(err, errMocked) {
		t.Fatal("not the error we expected", err)
	}
	if resp != nil {
		t.Fatal("expected nil response")
	}
	if loginAPI.CountCall != 1 {
		t.Fatal("invalid loginAPI.CountCall")
	}
	if registerAPI.CountCall != 1 {
		t.Fatal("invalid registerAPI.CountCall")
	}
}

func TestTorTargetsTheDatabaseIsReplaced(t *testing.T) {
	ff := &fakeFill{}
	handler := &LoginHandler{t: t}
	srvr := httptest.NewServer(handler)
	defer srvr.Close()
	registerAPI := &simpleRegisterAPI{
		HTTPClient: &VerboseHTTPClient{T: t},
		BaseURL:    srvr.URL,
	}
	loginAPI := &simpleLoginAPI{
		HTTPClient: &VerboseHTTPClient{T: t},
		BaseURL:    srvr.URL,
	}
	baseAPI := &simpleTorTargetsAPI{
		HTTPClient: &VerboseHTTPClient{T: t},
		BaseURL:    srvr.URL,
	}
	login := &withLoginTorTargetsAPI{
		API:         baseAPI,
		RegisterAPI: registerAPI,
		LoginAPI:    loginAPI,
		KVStore:     &MemKVStore{},
	}
	var req *apimodel.TorTargetsRequest
	ff.fill(&req)
	ctx := context.Background()
	// step 1: we register and login and use the token
	// inside a scope just to avoid mistakes
	{
		resp, err := login.Call(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if handler.logins != 1 {
			t.Fatal("invalid handler.logins")
		}
		if handler.registers != 1 {
			t.Fatal("invalid handler.registers")
		}
	}
	// step 2: we forget accounts and try again.
	handler.forgetLogins()
	resp, err := login.Call(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if handler.logins != 3 {
		t.Fatal("invalid handler.logins")
	}
	if handler.registers != 2 {
		t.Fatal("invalid handler.registers")
	}
}

func TestRegisterAndLoginTorTargetsCannotWriteState(t *testing.T) {
	ff := &fakeFill{}
	var expect apimodel.TorTargetsResponse
	ff.fill(&expect)
	registerAPI := &FakeRegisterAPI{
		Response: &apimodel.RegisterResponse{
			ClientID: "antani-antani",
		},
	}
	loginAPI := &FakeLoginAPI{
		Response: &apimodel.LoginResponse{
			Expire: time.Now().Add(3600 * time.Second),
			Token:  "antani-antani-token",
		},
	}
	errMocked := errors.New("mocked error")
	login := &withLoginTorTargetsAPI{
		API: &FakeTorTargetsAPI{
			WithResult: &FakeTorTargetsAPI{
				Response: expect,
			},
		},
		RegisterAPI: registerAPI,
		LoginAPI:    loginAPI,
		KVStore:     &MemKVStore{},
		JSONCodec: &FakeCodec{
			EncodeErr: errMocked,
		},
	}
	var req *apimodel.TorTargetsRequest
	ff.fill(&req)
	ctx := context.Background()
	resp, err := login.Call(ctx, req)
	if !errors.Is(err, errMocked) {
		t.Fatal("not the error we expected", err)
	}
	if resp != nil {
		t.Fatal("expected nil response")
	}
	if loginAPI.CountCall != 1 {
		t.Fatal("invalid loginAPI.CountCall")
	}
	if registerAPI.CountCall != 1 {
		t.Fatal("invalid registerAPI.CountCall")
	}
}

func TestTorTargetsReadStateDecodeFailure(t *testing.T) {
	ff := &fakeFill{}
	var expect apimodel.TorTargetsResponse
	ff.fill(&expect)
	errMocked := errors.New("mocked error")
	login := &withLoginTorTargetsAPI{
		KVStore:   &MemKVStore{},
		JSONCodec: &FakeCodec{DecodeErr: errMocked},
	}
	ls := &loginState{
		ClientID: "antani-antani",
		Expire:   time.Now().Add(-5 * time.Second),
		Token:    "antani-antani-token",
		Password: "antani-antani-password",
	}
	if err := login.writestate(ls); err != nil {
		t.Fatal(err)
	}
	out, err := login.forceLogin(context.Background())
	if !errors.Is(err, errMocked) {
		t.Fatal("not the error we expected", err)
	}
	if out != "" {
		t.Fatal("expected empty string here")
	}
}

func TestTorTargetsTheDatabaseIsReplacedThenFailure(t *testing.T) {
	ff := &fakeFill{}
	handler := &LoginHandler{t: t}
	srvr := httptest.NewServer(handler)
	defer srvr.Close()
	registerAPI := &simpleRegisterAPI{
		HTTPClient: &VerboseHTTPClient{T: t},
		BaseURL:    srvr.URL,
	}
	loginAPI := &simpleLoginAPI{
		HTTPClient: &VerboseHTTPClient{T: t},
		BaseURL:    srvr.URL,
	}
	baseAPI := &simpleTorTargetsAPI{
		HTTPClient: &VerboseHTTPClient{T: t},
		BaseURL:    srvr.URL,
	}
	login := &withLoginTorTargetsAPI{
		API:         baseAPI,
		RegisterAPI: registerAPI,
		LoginAPI:    loginAPI,
		KVStore:     &MemKVStore{},
	}
	var req *apimodel.TorTargetsRequest
	ff.fill(&req)
	ctx := context.Background()
	// step 1: we register and login and use the token
	// inside a scope just to avoid mistakes
	{
		resp, err := login.Call(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if handler.logins != 1 {
			t.Fatal("invalid handler.logins")
		}
		if handler.registers != 1 {
			t.Fatal("invalid handler.registers")
		}
	}
	// step 2: we forget accounts and try again.
	// but registrations are also failing.
	handler.forgetLogins()
	handler.noRegister = true
	resp, err := login.Call(ctx, req)
	if !errors.Is(err, ErrHTTPFailure) {
		t.Fatal("not the error we expected", err)
	}
	if resp != nil {
		t.Fatal("expected nil response")
	}
	if handler.logins != 2 {
		t.Fatal("invalid handler.logins")
	}
	if handler.registers != 2 {
		t.Fatal("invalid handler.registers")
	}
}

func TestTorTargetsClockIsOffThenSuccess(t *testing.T) {
	ff := &fakeFill{}
	handler := &LoginHandler{t: t}
	srvr := httptest.NewServer(handler)
	defer srvr.Close()
	registerAPI := &simpleRegisterAPI{
		HTTPClient: &VerboseHTTPClient{T: t},
		BaseURL:    srvr.URL,
	}
	loginAPI := &simpleLoginAPI{
		HTTPClient: &VerboseHTTPClient{T: t},
		BaseURL:    srvr.URL,
	}
	baseAPI := &simpleTorTargetsAPI{
		HTTPClient: &VerboseHTTPClient{T: t},
		BaseURL:    srvr.URL,
	}
	login := &withLoginTorTargetsAPI{
		API:         baseAPI,
		RegisterAPI: registerAPI,
		LoginAPI:    loginAPI,
		KVStore:     &MemKVStore{},
	}
	var req *apimodel.TorTargetsRequest
	ff.fill(&req)
	ctx := context.Background()
	// step 1: we register and login and use the token
	// inside a scope just to avoid mistakes
	{
		resp, err := login.Call(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if handler.logins != 1 {
			t.Fatal("invalid handler.logins")
		}
		if handler.registers != 1 {
			t.Fatal("invalid handler.registers")
		}
	}
	// step 2: we forget tokens and try again.
	// this should simulate the client clock
	// being off and considering a token still valid
	handler.forgetTokens()
	resp, err := login.Call(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if handler.logins != 2 {
		t.Fatal("invalid handler.logins")
	}
	if handler.registers != 1 {
		t.Fatal("invalid handler.registers")
	}
}

func TestTorTargetsClockIsOffThen401(t *testing.T) {
	ff := &fakeFill{}
	handler := &LoginHandler{t: t}
	srvr := httptest.NewServer(handler)
	defer srvr.Close()
	registerAPI := &simpleRegisterAPI{
		HTTPClient: &VerboseHTTPClient{T: t},
		BaseURL:    srvr.URL,
	}
	loginAPI := &simpleLoginAPI{
		HTTPClient: &VerboseHTTPClient{T: t},
		BaseURL:    srvr.URL,
	}
	baseAPI := &simpleTorTargetsAPI{
		HTTPClient: &VerboseHTTPClient{T: t},
		BaseURL:    srvr.URL,
	}
	login := &withLoginTorTargetsAPI{
		API:         baseAPI,
		RegisterAPI: registerAPI,
		LoginAPI:    loginAPI,
		KVStore:     &MemKVStore{},
	}
	var req *apimodel.TorTargetsRequest
	ff.fill(&req)
	ctx := context.Background()
	// step 1: we register and login and use the token
	// inside a scope just to avoid mistakes
	{
		resp, err := login.Call(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if handler.logins != 1 {
			t.Fatal("invalid handler.logins")
		}
		if handler.registers != 1 {
			t.Fatal("invalid handler.registers")
		}
	}
	// step 2: we forget tokens and try again.
	// this should simulate the client clock
	// being off and considering a token still valid
	handler.forgetTokens()
	handler.failCallWith = []int{401, 401}
	resp, err := login.Call(ctx, req)
	if err != nil {
		t.Fatal("not the error we expected", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if handler.logins != 3 {
		t.Fatal("invalid handler.logins")
	}
	if handler.registers != 2 {
		t.Fatal("invalid handler.registers")
	}
}

func TestTorTargetsClockIsOffThen500(t *testing.T) {
	ff := &fakeFill{}
	handler := &LoginHandler{t: t}
	srvr := httptest.NewServer(handler)
	defer srvr.Close()
	registerAPI := &simpleRegisterAPI{
		HTTPClient: &VerboseHTTPClient{T: t},
		BaseURL:    srvr.URL,
	}
	loginAPI := &simpleLoginAPI{
		HTTPClient: &VerboseHTTPClient{T: t},
		BaseURL:    srvr.URL,
	}
	baseAPI := &simpleTorTargetsAPI{
		HTTPClient: &VerboseHTTPClient{T: t},
		BaseURL:    srvr.URL,
	}
	login := &withLoginTorTargetsAPI{
		API:         baseAPI,
		RegisterAPI: registerAPI,
		LoginAPI:    loginAPI,
		KVStore:     &MemKVStore{},
	}
	var req *apimodel.TorTargetsRequest
	ff.fill(&req)
	ctx := context.Background()
	// step 1: we register and login and use the token
	// inside a scope just to avoid mistakes
	{
		resp, err := login.Call(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if handler.logins != 1 {
			t.Fatal("invalid handler.logins")
		}
		if handler.registers != 1 {
			t.Fatal("invalid handler.registers")
		}
	}
	// step 2: we forget tokens and try again.
	// this should simulate the client clock
	// being off and considering a token still valid
	handler.forgetTokens()
	handler.failCallWith = []int{401, 500}
	resp, err := login.Call(ctx, req)
	if !errors.Is(err, ErrHTTPFailure) {
		t.Fatal("not the error we expected", err)
	}
	if resp != nil {
		t.Fatal("expected nil response")
	}
	if handler.logins != 2 {
		t.Fatal("invalid handler.logins")
	}
	if handler.registers != 1 {
		t.Fatal("invalid handler.registers")
	}
}
