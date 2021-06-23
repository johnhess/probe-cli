// Code generated by go generate; DO NOT EDIT.
// 2021-06-15 10:55:58.234786 +0200 CEST m=+0.000218167

package ooapi

//go:generate go run ./internal/generator -file fakeapi_test.go

import (
	"context"

	"github.com/ooni/probe-cli/v3/internal/atomicx"
	"github.com/ooni/probe-cli/v3/internal/ooapi/apimodel"
)

type FakeCheckReportIDAPI struct {
	Err       error
	Response  *apimodel.CheckReportIDResponse
	CountCall *atomicx.Int64
}

func (fapi *FakeCheckReportIDAPI) Call(ctx context.Context, req *apimodel.CheckReportIDRequest) (*apimodel.CheckReportIDResponse, error) {
	if fapi.CountCall != nil {
		fapi.CountCall.Add(1)
	}
	return fapi.Response, fapi.Err
}

var (
	_ callerForCheckReportIDAPI = &FakeCheckReportIDAPI{}
)

type FakeCheckInAPI struct {
	Err       error
	Response  *apimodel.CheckInResponse
	CountCall *atomicx.Int64
}

func (fapi *FakeCheckInAPI) Call(ctx context.Context, req *apimodel.CheckInRequest) (*apimodel.CheckInResponse, error) {
	if fapi.CountCall != nil {
		fapi.CountCall.Add(1)
	}
	return fapi.Response, fapi.Err
}

var (
	_ callerForCheckInAPI = &FakeCheckInAPI{}
)

type FakeLoginAPI struct {
	Err       error
	Response  *apimodel.LoginResponse
	CountCall *atomicx.Int64
}

func (fapi *FakeLoginAPI) Call(ctx context.Context, req *apimodel.LoginRequest) (*apimodel.LoginResponse, error) {
	if fapi.CountCall != nil {
		fapi.CountCall.Add(1)
	}
	return fapi.Response, fapi.Err
}

var (
	_ callerForLoginAPI = &FakeLoginAPI{}
)

type FakeMeasurementMetaAPI struct {
	Err       error
	Response  *apimodel.MeasurementMetaResponse
	CountCall *atomicx.Int64
}

func (fapi *FakeMeasurementMetaAPI) Call(ctx context.Context, req *apimodel.MeasurementMetaRequest) (*apimodel.MeasurementMetaResponse, error) {
	if fapi.CountCall != nil {
		fapi.CountCall.Add(1)
	}
	return fapi.Response, fapi.Err
}

var (
	_ callerForMeasurementMetaAPI = &FakeMeasurementMetaAPI{}
)

type FakeRegisterAPI struct {
	Err       error
	Response  *apimodel.RegisterResponse
	CountCall *atomicx.Int64
}

func (fapi *FakeRegisterAPI) Call(ctx context.Context, req *apimodel.RegisterRequest) (*apimodel.RegisterResponse, error) {
	if fapi.CountCall != nil {
		fapi.CountCall.Add(1)
	}
	return fapi.Response, fapi.Err
}

var (
	_ callerForRegisterAPI = &FakeRegisterAPI{}
)

type FakeTestHelpersAPI struct {
	Err       error
	Response  apimodel.TestHelpersResponse
	CountCall *atomicx.Int64
}

func (fapi *FakeTestHelpersAPI) Call(ctx context.Context, req *apimodel.TestHelpersRequest) (apimodel.TestHelpersResponse, error) {
	if fapi.CountCall != nil {
		fapi.CountCall.Add(1)
	}
	return fapi.Response, fapi.Err
}

var (
	_ callerForTestHelpersAPI = &FakeTestHelpersAPI{}
)

type FakePsiphonConfigAPI struct {
	WithResult callerForPsiphonConfigAPI
	Err        error
	Response   apimodel.PsiphonConfigResponse
	CountCall  *atomicx.Int64
}

func (fapi *FakePsiphonConfigAPI) Call(ctx context.Context, req *apimodel.PsiphonConfigRequest) (apimodel.PsiphonConfigResponse, error) {
	if fapi.CountCall != nil {
		fapi.CountCall.Add(1)
	}
	return fapi.Response, fapi.Err
}

func (fapi *FakePsiphonConfigAPI) WithToken(token string) callerForPsiphonConfigAPI {
	return fapi.WithResult
}

var (
	_ callerForPsiphonConfigAPI = &FakePsiphonConfigAPI{}
	_ clonerForPsiphonConfigAPI = &FakePsiphonConfigAPI{}
)

type FakeTorTargetsAPI struct {
	WithResult callerForTorTargetsAPI
	Err        error
	Response   apimodel.TorTargetsResponse
	CountCall  *atomicx.Int64
}

func (fapi *FakeTorTargetsAPI) Call(ctx context.Context, req *apimodel.TorTargetsRequest) (apimodel.TorTargetsResponse, error) {
	if fapi.CountCall != nil {
		fapi.CountCall.Add(1)
	}
	return fapi.Response, fapi.Err
}

func (fapi *FakeTorTargetsAPI) WithToken(token string) callerForTorTargetsAPI {
	return fapi.WithResult
}

var (
	_ callerForTorTargetsAPI = &FakeTorTargetsAPI{}
	_ clonerForTorTargetsAPI = &FakeTorTargetsAPI{}
)

type FakeURLsAPI struct {
	Err       error
	Response  *apimodel.URLsResponse
	CountCall *atomicx.Int64
}

func (fapi *FakeURLsAPI) Call(ctx context.Context, req *apimodel.URLsRequest) (*apimodel.URLsResponse, error) {
	if fapi.CountCall != nil {
		fapi.CountCall.Add(1)
	}
	return fapi.Response, fapi.Err
}

var (
	_ callerForURLsAPI = &FakeURLsAPI{}
)

type FakeOpenReportAPI struct {
	Err       error
	Response  *apimodel.OpenReportResponse
	CountCall *atomicx.Int64
}

func (fapi *FakeOpenReportAPI) Call(ctx context.Context, req *apimodel.OpenReportRequest) (*apimodel.OpenReportResponse, error) {
	if fapi.CountCall != nil {
		fapi.CountCall.Add(1)
	}
	return fapi.Response, fapi.Err
}

var (
	_ callerForOpenReportAPI = &FakeOpenReportAPI{}
)

type FakeSubmitMeasurementAPI struct {
	Err       error
	Response  *apimodel.SubmitMeasurementResponse
	CountCall *atomicx.Int64
}

func (fapi *FakeSubmitMeasurementAPI) Call(ctx context.Context, req *apimodel.SubmitMeasurementRequest) (*apimodel.SubmitMeasurementResponse, error) {
	if fapi.CountCall != nil {
		fapi.CountCall.Add(1)
	}
	return fapi.Response, fapi.Err
}

var (
	_ callerForSubmitMeasurementAPI = &FakeSubmitMeasurementAPI{}
)