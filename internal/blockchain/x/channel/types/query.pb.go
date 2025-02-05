// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: channel/query.proto

package types

import (
	context "context"
	fmt "fmt"
	query "github.com/cosmos/cosmos-sdk/types/query"
	_ "github.com/gogo/protobuf/gogoproto"
	grpc1 "github.com/gogo/protobuf/grpc"
	proto "github.com/gogo/protobuf/proto"
	types "github.com/sonr-io/sonr/internal/blockchain/x/registry/types"
	_ "google.golang.org/genproto/googleapis/api/annotations"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	io "io"
	math "math"
	math_bits "math/bits"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

// QueryParamsRequest is request type for the Query/Params RPC method.
type QueryParamsRequest struct {
}

func (m *QueryParamsRequest) Reset()         { *m = QueryParamsRequest{} }
func (m *QueryParamsRequest) String() string { return proto.CompactTextString(m) }
func (*QueryParamsRequest) ProtoMessage()    {}
func (*QueryParamsRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_722e713ae4954217, []int{0}
}
func (m *QueryParamsRequest) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *QueryParamsRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_QueryParamsRequest.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *QueryParamsRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_QueryParamsRequest.Merge(m, src)
}
func (m *QueryParamsRequest) XXX_Size() int {
	return m.Size()
}
func (m *QueryParamsRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_QueryParamsRequest.DiscardUnknown(m)
}

var xxx_messageInfo_QueryParamsRequest proto.InternalMessageInfo

// QueryParamsResponse is response type for the Query/Params RPC method.
type QueryParamsResponse struct {
	// params holds all the parameters of this module.
	Params Params `protobuf:"bytes,1,opt,name=params,proto3" json:"params"`
}

func (m *QueryParamsResponse) Reset()         { *m = QueryParamsResponse{} }
func (m *QueryParamsResponse) String() string { return proto.CompactTextString(m) }
func (*QueryParamsResponse) ProtoMessage()    {}
func (*QueryParamsResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_722e713ae4954217, []int{1}
}
func (m *QueryParamsResponse) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *QueryParamsResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_QueryParamsResponse.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *QueryParamsResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_QueryParamsResponse.Merge(m, src)
}
func (m *QueryParamsResponse) XXX_Size() int {
	return m.Size()
}
func (m *QueryParamsResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_QueryParamsResponse.DiscardUnknown(m)
}

var xxx_messageInfo_QueryParamsResponse proto.InternalMessageInfo

func (m *QueryParamsResponse) GetParams() Params {
	if m != nil {
		return m.Params
	}
	return Params{}
}

type QueryHowIsRequest struct {
	Did     string         `protobuf:"bytes,1,opt,name=did,proto3" json:"did,omitempty"`
	Session *types.Session `protobuf:"bytes,2,opt,name=session,proto3" json:"session,omitempty"`
}

func (m *QueryHowIsRequest) Reset()         { *m = QueryHowIsRequest{} }
func (m *QueryHowIsRequest) String() string { return proto.CompactTextString(m) }
func (*QueryHowIsRequest) ProtoMessage()    {}
func (*QueryHowIsRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_722e713ae4954217, []int{2}
}
func (m *QueryHowIsRequest) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *QueryHowIsRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_QueryHowIsRequest.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *QueryHowIsRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_QueryHowIsRequest.Merge(m, src)
}
func (m *QueryHowIsRequest) XXX_Size() int {
	return m.Size()
}
func (m *QueryHowIsRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_QueryHowIsRequest.DiscardUnknown(m)
}

var xxx_messageInfo_QueryHowIsRequest proto.InternalMessageInfo

func (m *QueryHowIsRequest) GetDid() string {
	if m != nil {
		return m.Did
	}
	return ""
}

func (m *QueryHowIsRequest) GetSession() *types.Session {
	if m != nil {
		return m.Session
	}
	return nil
}

type QueryHowIsResponse struct {
	HowIs HowIs `protobuf:"bytes,1,opt,name=how_is,json=howIs,proto3" json:"how_is"`
}

func (m *QueryHowIsResponse) Reset()         { *m = QueryHowIsResponse{} }
func (m *QueryHowIsResponse) String() string { return proto.CompactTextString(m) }
func (*QueryHowIsResponse) ProtoMessage()    {}
func (*QueryHowIsResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_722e713ae4954217, []int{3}
}
func (m *QueryHowIsResponse) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *QueryHowIsResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_QueryHowIsResponse.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *QueryHowIsResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_QueryHowIsResponse.Merge(m, src)
}
func (m *QueryHowIsResponse) XXX_Size() int {
	return m.Size()
}
func (m *QueryHowIsResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_QueryHowIsResponse.DiscardUnknown(m)
}

var xxx_messageInfo_QueryHowIsResponse proto.InternalMessageInfo

func (m *QueryHowIsResponse) GetHowIs() HowIs {
	if m != nil {
		return m.HowIs
	}
	return HowIs{}
}

type QueryAllHowIsRequest struct {
	Pagination *query.PageRequest `protobuf:"bytes,1,opt,name=pagination,proto3" json:"pagination,omitempty"`
	Session    *types.Session     `protobuf:"bytes,2,opt,name=session,proto3" json:"session,omitempty"`
}

func (m *QueryAllHowIsRequest) Reset()         { *m = QueryAllHowIsRequest{} }
func (m *QueryAllHowIsRequest) String() string { return proto.CompactTextString(m) }
func (*QueryAllHowIsRequest) ProtoMessage()    {}
func (*QueryAllHowIsRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_722e713ae4954217, []int{4}
}
func (m *QueryAllHowIsRequest) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *QueryAllHowIsRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_QueryAllHowIsRequest.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *QueryAllHowIsRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_QueryAllHowIsRequest.Merge(m, src)
}
func (m *QueryAllHowIsRequest) XXX_Size() int {
	return m.Size()
}
func (m *QueryAllHowIsRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_QueryAllHowIsRequest.DiscardUnknown(m)
}

var xxx_messageInfo_QueryAllHowIsRequest proto.InternalMessageInfo

func (m *QueryAllHowIsRequest) GetPagination() *query.PageRequest {
	if m != nil {
		return m.Pagination
	}
	return nil
}

func (m *QueryAllHowIsRequest) GetSession() *types.Session {
	if m != nil {
		return m.Session
	}
	return nil
}

type QueryAllHowIsResponse struct {
	HowIs      []HowIs             `protobuf:"bytes,1,rep,name=how_is,json=howIs,proto3" json:"how_is"`
	Pagination *query.PageResponse `protobuf:"bytes,2,opt,name=pagination,proto3" json:"pagination,omitempty"`
}

func (m *QueryAllHowIsResponse) Reset()         { *m = QueryAllHowIsResponse{} }
func (m *QueryAllHowIsResponse) String() string { return proto.CompactTextString(m) }
func (*QueryAllHowIsResponse) ProtoMessage()    {}
func (*QueryAllHowIsResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_722e713ae4954217, []int{5}
}
func (m *QueryAllHowIsResponse) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *QueryAllHowIsResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_QueryAllHowIsResponse.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *QueryAllHowIsResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_QueryAllHowIsResponse.Merge(m, src)
}
func (m *QueryAllHowIsResponse) XXX_Size() int {
	return m.Size()
}
func (m *QueryAllHowIsResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_QueryAllHowIsResponse.DiscardUnknown(m)
}

var xxx_messageInfo_QueryAllHowIsResponse proto.InternalMessageInfo

func (m *QueryAllHowIsResponse) GetHowIs() []HowIs {
	if m != nil {
		return m.HowIs
	}
	return nil
}

func (m *QueryAllHowIsResponse) GetPagination() *query.PageResponse {
	if m != nil {
		return m.Pagination
	}
	return nil
}

func init() {
	proto.RegisterType((*QueryParamsRequest)(nil), "sonrio.sonr.channel.QueryParamsRequest")
	proto.RegisterType((*QueryParamsResponse)(nil), "sonrio.sonr.channel.QueryParamsResponse")
	proto.RegisterType((*QueryHowIsRequest)(nil), "sonrio.sonr.channel.QueryHowIsRequest")
	proto.RegisterType((*QueryHowIsResponse)(nil), "sonrio.sonr.channel.QueryHowIsResponse")
	proto.RegisterType((*QueryAllHowIsRequest)(nil), "sonrio.sonr.channel.QueryAllHowIsRequest")
	proto.RegisterType((*QueryAllHowIsResponse)(nil), "sonrio.sonr.channel.QueryAllHowIsResponse")
}

func init() { proto.RegisterFile("channel/query.proto", fileDescriptor_722e713ae4954217) }

var fileDescriptor_722e713ae4954217 = []byte{
	// 538 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x9c, 0x54, 0xcf, 0x6e, 0xd3, 0x30,
	0x18, 0xaf, 0x57, 0x5a, 0xc0, 0x5c, 0xc0, 0xed, 0xa4, 0x29, 0xdb, 0x02, 0x0a, 0xd3, 0x3a, 0x2a,
	0xcd, 0xd6, 0xc6, 0x61, 0xe2, 0xb8, 0x1d, 0x18, 0x1c, 0x90, 0x4a, 0xb9, 0x71, 0x00, 0x39, 0xa9,
	0x95, 0x58, 0xa4, 0x76, 0x16, 0xa7, 0x94, 0x0a, 0x21, 0x21, 0x84, 0xc4, 0x15, 0x89, 0x03, 0x42,
	0xbc, 0xd0, 0x8e, 0x93, 0xb8, 0x70, 0x42, 0xa8, 0xe5, 0x41, 0x50, 0x6c, 0xa7, 0x34, 0xa5, 0xa3,
	0xc0, 0x29, 0xa9, 0xfd, 0xfb, 0xab, 0xef, 0x6b, 0x60, 0x23, 0x88, 0xa8, 0x10, 0x2c, 0x26, 0x27,
	0x03, 0x96, 0x8e, 0x70, 0x92, 0xca, 0x4c, 0xa2, 0x86, 0x92, 0x22, 0xe5, 0x12, 0xe7, 0x0f, 0x6c,
	0x01, 0x4e, 0x33, 0x94, 0xa1, 0xd4, 0xf7, 0x24, 0x7f, 0x33, 0x50, 0x67, 0x23, 0x94, 0x32, 0x8c,
	0x19, 0xa1, 0x09, 0x27, 0x54, 0x08, 0x99, 0xd1, 0x8c, 0x4b, 0xa1, 0xec, 0x6d, 0x3b, 0x90, 0xaa,
	0x2f, 0x15, 0xf1, 0xa9, 0x62, 0xc6, 0x81, 0x3c, 0xdf, 0xf3, 0x59, 0x46, 0xf7, 0x48, 0x42, 0x43,
	0x2e, 0x34, 0xd8, 0x62, 0x9b, 0x45, 0x92, 0x84, 0xa6, 0xb4, 0x5f, 0x28, 0xac, 0xa6, 0x2c, 0xe4,
	0x2a, 0x4b, 0x47, 0x64, 0x18, 0xc9, 0xa7, 0x5c, 0xcd, 0x83, 0x23, 0x39, 0x9c, 0x9e, 0x7a, 0x4d,
	0x88, 0x1e, 0xe6, 0x26, 0x1d, 0xad, 0xd0, 0x65, 0x27, 0x03, 0xa6, 0x32, 0xaf, 0x03, 0x1b, 0xa5,
	0x53, 0x95, 0x48, 0xa1, 0x18, 0xba, 0x03, 0xeb, 0xc6, 0x69, 0x0d, 0xdc, 0x00, 0x3b, 0x57, 0xf6,
	0xd7, 0xf1, 0x82, 0xd6, 0xd8, 0x90, 0x8e, 0x2e, 0x9c, 0x7e, 0xbb, 0x5e, 0xe9, 0x5a, 0x82, 0xf7,
	0x04, 0x5e, 0xd3, 0x8a, 0xf7, 0xe4, 0xf0, 0x7e, 0x61, 0x83, 0xae, 0xc2, 0x6a, 0x8f, 0xf7, 0xb4,
	0xd8, 0xe5, 0x6e, 0xfe, 0x8a, 0x0e, 0xe0, 0x45, 0xc5, 0x94, 0xe2, 0x52, 0xac, 0xad, 0x68, 0x8b,
	0xcd, 0x92, 0x45, 0xd1, 0x0c, 0x3f, 0x32, 0xa0, 0x6e, 0x81, 0xf6, 0x1e, 0xd8, 0x1e, 0x56, 0xdf,
	0x06, 0x3e, 0x80, 0x75, 0xd3, 0xd6, 0x06, 0x76, 0x16, 0x06, 0xd6, 0x1c, 0x9b, 0xb7, 0x16, 0xe5,
	0x3f, 0xbc, 0x8f, 0x00, 0x36, 0xb5, 0xde, 0x61, 0x1c, 0x97, 0x22, 0xdf, 0x85, 0xf0, 0xd7, 0x18,
	0xac, 0xea, 0x36, 0x36, 0x33, 0xc3, 0xf9, 0xcc, 0xb0, 0xd9, 0x0a, 0x3b, 0x33, 0xdc, 0xa1, 0x21,
	0xb3, 0xdc, 0xee, 0x0c, 0xf3, 0xff, 0x8b, 0x7e, 0x02, 0x70, 0x75, 0x2e, 0xd9, 0x82, 0xb2, 0xd5,
	0x7f, 0x28, 0x8b, 0x8e, 0x4b, 0x9d, 0x4c, 0x9c, 0xd6, 0xd2, 0x4e, 0xc6, 0x75, 0xb6, 0xd4, 0xfe,
	0xe7, 0x2a, 0xac, 0xe9, 0x6c, 0xe8, 0x35, 0x80, 0x75, 0xb3, 0x07, 0xa8, 0xb5, 0x30, 0xc6, 0xef,
	0x4b, 0xe7, 0xec, 0x2c, 0x07, 0x1a, 0x4f, 0xef, 0xe6, 0x9b, 0x2f, 0x3f, 0x3e, 0xac, 0x6c, 0xa2,
	0x75, 0x62, 0x18, 0xfa, 0x41, 0xca, 0x7f, 0x06, 0xf4, 0x16, 0xc0, 0x9a, 0x2e, 0x8b, 0xb6, 0xcf,
	0x17, 0x9e, 0x9d, 0xad, 0xd3, 0x5a, 0x8a, 0xb3, 0xfe, 0x6d, 0xed, 0xbf, 0x85, 0x3c, 0x6d, 0xbc,
	0x3b, 0x1f, 0xc0, 0x4c, 0x81, 0xbc, 0xec, 0xf1, 0xde, 0x2b, 0xf4, 0x0e, 0xc0, 0x4b, 0x9a, 0x7d,
	0x18, 0xc7, 0xe8, 0xd6, 0xf9, 0x0e, 0x73, 0x8b, 0xe6, 0xb4, 0xff, 0x06, 0x6a, 0xf3, 0x6c, 0xe9,
	0x3c, 0x2e, 0xda, 0xf8, 0x53, 0x9e, 0xa3, 0xe3, 0xd3, 0xb1, 0x0b, 0xce, 0xc6, 0x2e, 0xf8, 0x3e,
	0x76, 0xc1, 0xfb, 0x89, 0x5b, 0x39, 0x9b, 0xb8, 0x95, 0xaf, 0x13, 0xb7, 0xf2, 0x78, 0x37, 0xe4,
	0x59, 0x34, 0xf0, 0x71, 0x20, 0xfb, 0x53, 0x05, 0x3f, 0x96, 0xc1, 0xb3, 0x20, 0xa2, 0x5c, 0x90,
	0x17, 0x53, 0xa5, 0x6c, 0x94, 0x30, 0xe5, 0xd7, 0xf5, 0xa7, 0xe3, 0xf6, 0xcf, 0x00, 0x00, 0x00,
	0xff, 0xff, 0x8e, 0xe0, 0x02, 0x7c, 0x09, 0x05, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// QueryClient is the client API for Query service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type QueryClient interface {
	// Params
	//
	// Parameters queries the parameters of the module.
	Params(ctx context.Context, in *QueryParamsRequest, opts ...grpc.CallOption) (*QueryParamsResponse, error)
	// HowIs
	//
	// Queries a HowIs by did.
	HowIs(ctx context.Context, in *QueryHowIsRequest, opts ...grpc.CallOption) (*QueryHowIsResponse, error)
	// HowIsAll
	//
	// Queries a list of HowIs items.
	HowIsAll(ctx context.Context, in *QueryAllHowIsRequest, opts ...grpc.CallOption) (*QueryAllHowIsResponse, error)
}

type queryClient struct {
	cc grpc1.ClientConn
}

func NewQueryClient(cc grpc1.ClientConn) QueryClient {
	return &queryClient{cc}
}

func (c *queryClient) Params(ctx context.Context, in *QueryParamsRequest, opts ...grpc.CallOption) (*QueryParamsResponse, error) {
	out := new(QueryParamsResponse)
	err := c.cc.Invoke(ctx, "/sonrio.sonr.channel.Query/Params", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *queryClient) HowIs(ctx context.Context, in *QueryHowIsRequest, opts ...grpc.CallOption) (*QueryHowIsResponse, error) {
	out := new(QueryHowIsResponse)
	err := c.cc.Invoke(ctx, "/sonrio.sonr.channel.Query/HowIs", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *queryClient) HowIsAll(ctx context.Context, in *QueryAllHowIsRequest, opts ...grpc.CallOption) (*QueryAllHowIsResponse, error) {
	out := new(QueryAllHowIsResponse)
	err := c.cc.Invoke(ctx, "/sonrio.sonr.channel.Query/HowIsAll", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// QueryServer is the server API for Query service.
type QueryServer interface {
	// Params
	//
	// Parameters queries the parameters of the module.
	Params(context.Context, *QueryParamsRequest) (*QueryParamsResponse, error)
	// HowIs
	//
	// Queries a HowIs by did.
	HowIs(context.Context, *QueryHowIsRequest) (*QueryHowIsResponse, error)
	// HowIsAll
	//
	// Queries a list of HowIs items.
	HowIsAll(context.Context, *QueryAllHowIsRequest) (*QueryAllHowIsResponse, error)
}

// UnimplementedQueryServer can be embedded to have forward compatible implementations.
type UnimplementedQueryServer struct {
}

func (*UnimplementedQueryServer) Params(ctx context.Context, req *QueryParamsRequest) (*QueryParamsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Params not implemented")
}
func (*UnimplementedQueryServer) HowIs(ctx context.Context, req *QueryHowIsRequest) (*QueryHowIsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method HowIs not implemented")
}
func (*UnimplementedQueryServer) HowIsAll(ctx context.Context, req *QueryAllHowIsRequest) (*QueryAllHowIsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method HowIsAll not implemented")
}

func RegisterQueryServer(s grpc1.Server, srv QueryServer) {
	s.RegisterService(&_Query_serviceDesc, srv)
}

func _Query_Params_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(QueryParamsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(QueryServer).Params(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/sonrio.sonr.channel.Query/Params",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(QueryServer).Params(ctx, req.(*QueryParamsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Query_HowIs_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(QueryHowIsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(QueryServer).HowIs(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/sonrio.sonr.channel.Query/HowIs",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(QueryServer).HowIs(ctx, req.(*QueryHowIsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Query_HowIsAll_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(QueryAllHowIsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(QueryServer).HowIsAll(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/sonrio.sonr.channel.Query/HowIsAll",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(QueryServer).HowIsAll(ctx, req.(*QueryAllHowIsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _Query_serviceDesc = grpc.ServiceDesc{
	ServiceName: "sonrio.sonr.channel.Query",
	HandlerType: (*QueryServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Params",
			Handler:    _Query_Params_Handler,
		},
		{
			MethodName: "HowIs",
			Handler:    _Query_HowIs_Handler,
		},
		{
			MethodName: "HowIsAll",
			Handler:    _Query_HowIsAll_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "channel/query.proto",
}

func (m *QueryParamsRequest) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *QueryParamsRequest) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *QueryParamsRequest) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	return len(dAtA) - i, nil
}

func (m *QueryParamsResponse) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *QueryParamsResponse) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *QueryParamsResponse) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	{
		size, err := m.Params.MarshalToSizedBuffer(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = encodeVarintQuery(dAtA, i, uint64(size))
	}
	i--
	dAtA[i] = 0xa
	return len(dAtA) - i, nil
}

func (m *QueryHowIsRequest) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *QueryHowIsRequest) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *QueryHowIsRequest) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.Session != nil {
		{
			size, err := m.Session.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintQuery(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x12
	}
	if len(m.Did) > 0 {
		i -= len(m.Did)
		copy(dAtA[i:], m.Did)
		i = encodeVarintQuery(dAtA, i, uint64(len(m.Did)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *QueryHowIsResponse) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *QueryHowIsResponse) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *QueryHowIsResponse) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	{
		size, err := m.HowIs.MarshalToSizedBuffer(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = encodeVarintQuery(dAtA, i, uint64(size))
	}
	i--
	dAtA[i] = 0xa
	return len(dAtA) - i, nil
}

func (m *QueryAllHowIsRequest) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *QueryAllHowIsRequest) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *QueryAllHowIsRequest) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.Session != nil {
		{
			size, err := m.Session.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintQuery(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x12
	}
	if m.Pagination != nil {
		{
			size, err := m.Pagination.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintQuery(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *QueryAllHowIsResponse) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *QueryAllHowIsResponse) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *QueryAllHowIsResponse) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.Pagination != nil {
		{
			size, err := m.Pagination.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintQuery(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x12
	}
	if len(m.HowIs) > 0 {
		for iNdEx := len(m.HowIs) - 1; iNdEx >= 0; iNdEx-- {
			{
				size, err := m.HowIs[iNdEx].MarshalToSizedBuffer(dAtA[:i])
				if err != nil {
					return 0, err
				}
				i -= size
				i = encodeVarintQuery(dAtA, i, uint64(size))
			}
			i--
			dAtA[i] = 0xa
		}
	}
	return len(dAtA) - i, nil
}

func encodeVarintQuery(dAtA []byte, offset int, v uint64) int {
	offset -= sovQuery(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *QueryParamsRequest) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	return n
}

func (m *QueryParamsResponse) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = m.Params.Size()
	n += 1 + l + sovQuery(uint64(l))
	return n
}

func (m *QueryHowIsRequest) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.Did)
	if l > 0 {
		n += 1 + l + sovQuery(uint64(l))
	}
	if m.Session != nil {
		l = m.Session.Size()
		n += 1 + l + sovQuery(uint64(l))
	}
	return n
}

func (m *QueryHowIsResponse) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = m.HowIs.Size()
	n += 1 + l + sovQuery(uint64(l))
	return n
}

func (m *QueryAllHowIsRequest) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Pagination != nil {
		l = m.Pagination.Size()
		n += 1 + l + sovQuery(uint64(l))
	}
	if m.Session != nil {
		l = m.Session.Size()
		n += 1 + l + sovQuery(uint64(l))
	}
	return n
}

func (m *QueryAllHowIsResponse) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if len(m.HowIs) > 0 {
		for _, e := range m.HowIs {
			l = e.Size()
			n += 1 + l + sovQuery(uint64(l))
		}
	}
	if m.Pagination != nil {
		l = m.Pagination.Size()
		n += 1 + l + sovQuery(uint64(l))
	}
	return n
}

func sovQuery(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozQuery(x uint64) (n int) {
	return sovQuery(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *QueryParamsRequest) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowQuery
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: QueryParamsRequest: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: QueryParamsRequest: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		default:
			iNdEx = preIndex
			skippy, err := skipQuery(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthQuery
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *QueryParamsResponse) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowQuery
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: QueryParamsResponse: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: QueryParamsResponse: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Params", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowQuery
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthQuery
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthQuery
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.Params.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipQuery(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthQuery
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *QueryHowIsRequest) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowQuery
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: QueryHowIsRequest: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: QueryHowIsRequest: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Did", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowQuery
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthQuery
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthQuery
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Did = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Session", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowQuery
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthQuery
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthQuery
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Session == nil {
				m.Session = &types.Session{}
			}
			if err := m.Session.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipQuery(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthQuery
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *QueryHowIsResponse) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowQuery
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: QueryHowIsResponse: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: QueryHowIsResponse: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field HowIs", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowQuery
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthQuery
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthQuery
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.HowIs.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipQuery(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthQuery
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *QueryAllHowIsRequest) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowQuery
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: QueryAllHowIsRequest: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: QueryAllHowIsRequest: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Pagination", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowQuery
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthQuery
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthQuery
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Pagination == nil {
				m.Pagination = &query.PageRequest{}
			}
			if err := m.Pagination.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Session", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowQuery
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthQuery
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthQuery
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Session == nil {
				m.Session = &types.Session{}
			}
			if err := m.Session.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipQuery(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthQuery
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *QueryAllHowIsResponse) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowQuery
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: QueryAllHowIsResponse: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: QueryAllHowIsResponse: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field HowIs", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowQuery
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthQuery
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthQuery
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.HowIs = append(m.HowIs, HowIs{})
			if err := m.HowIs[len(m.HowIs)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Pagination", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowQuery
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthQuery
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthQuery
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Pagination == nil {
				m.Pagination = &query.PageResponse{}
			}
			if err := m.Pagination.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipQuery(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthQuery
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipQuery(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowQuery
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowQuery
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
		case 1:
			iNdEx += 8
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowQuery
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthQuery
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupQuery
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthQuery
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthQuery        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowQuery          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupQuery = fmt.Errorf("proto: unexpected end of group")
)
