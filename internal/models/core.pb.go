// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.23.0
// 	protoc        v3.14.0
// source: core.proto

package models

import (
	proto "github.com/golang/protobuf/proto"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

type CallbackType int32

const (
	CallbackType_REFRESHED CallbackType = 0
	CallbackType_QUEUED    CallbackType = 1
	CallbackType_INVITED   CallbackType = 2
	CallbackType_RESPONDED CallbackType = 3
	CallbackType_COMPLETED CallbackType = 5
)

// Enum value maps for CallbackType.
var (
	CallbackType_name = map[int32]string{
		0: "REFRESHED",
		1: "QUEUED",
		2: "INVITED",
		3: "RESPONDED",
		5: "COMPLETED",
	}
	CallbackType_value = map[string]int32{
		"REFRESHED": 0,
		"QUEUED":    1,
		"INVITED":   2,
		"RESPONDED": 3,
		"COMPLETED": 5,
	}
)

func (x CallbackType) Enum() *CallbackType {
	p := new(CallbackType)
	*p = x
	return p
}

func (x CallbackType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (CallbackType) Descriptor() protoreflect.EnumDescriptor {
	return file_core_proto_enumTypes[0].Descriptor()
}

func (CallbackType) Type() protoreflect.EnumType {
	return &file_core_proto_enumTypes[0]
}

func (x CallbackType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use CallbackType.Descriptor instead.
func (CallbackType) EnumDescriptor() ([]byte, []int) {
	return file_core_proto_rawDescGZIP(), []int{0}
}

type LobbyEvent_Event int32

const (
	LobbyEvent_NONE   LobbyEvent_Event = 0
	LobbyEvent_JOIN   LobbyEvent_Event = 1
	LobbyEvent_UPDATE LobbyEvent_Event = 2
	LobbyEvent_EXIT   LobbyEvent_Event = 3
)

// Enum value maps for LobbyEvent_Event.
var (
	LobbyEvent_Event_name = map[int32]string{
		0: "NONE",
		1: "JOIN",
		2: "UPDATE",
		3: "EXIT",
	}
	LobbyEvent_Event_value = map[string]int32{
		"NONE":   0,
		"JOIN":   1,
		"UPDATE": 2,
		"EXIT":   3,
	}
)

func (x LobbyEvent_Event) Enum() *LobbyEvent_Event {
	p := new(LobbyEvent_Event)
	*p = x
	return p
}

func (x LobbyEvent_Event) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (LobbyEvent_Event) Descriptor() protoreflect.EnumDescriptor {
	return file_core_proto_enumTypes[1].Descriptor()
}

func (LobbyEvent_Event) Type() protoreflect.EnumType {
	return &file_core_proto_enumTypes[1]
}

func (x LobbyEvent_Event) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use LobbyEvent_Event.Descriptor instead.
func (LobbyEvent_Event) EnumDescriptor() ([]byte, []int) {
	return file_core_proto_rawDescGZIP(), []int{0, 0}
}

// [CORE]
// Message Sent when peer messages Lobby Topic
type LobbyEvent struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Event LobbyEvent_Event `protobuf:"varint,1,opt,name=event,proto3,enum=core.LobbyEvent_Event" json:"event,omitempty"`
	Peer  *Peer            `protobuf:"bytes,2,opt,name=peer,proto3" json:"peer,omitempty"`
	Id    string           `protobuf:"bytes,3,opt,name=id,proto3" json:"id,omitempty"` // Optional used for remove
}

func (x *LobbyEvent) Reset() {
	*x = LobbyEvent{}
	if protoimpl.UnsafeEnabled {
		mi := &file_core_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *LobbyEvent) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LobbyEvent) ProtoMessage() {}

func (x *LobbyEvent) ProtoReflect() protoreflect.Message {
	mi := &file_core_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LobbyEvent.ProtoReflect.Descriptor instead.
func (*LobbyEvent) Descriptor() ([]byte, []int) {
	return file_core_proto_rawDescGZIP(), []int{0}
}

func (x *LobbyEvent) GetEvent() LobbyEvent_Event {
	if x != nil {
		return x.Event
	}
	return LobbyEvent_NONE
}

func (x *LobbyEvent) GetPeer() *Peer {
	if x != nil {
		return x.Peer
	}
	return nil
}

func (x *LobbyEvent) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

// Define Chunk Type: Sent on Data Transfer
type Chunk struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	B64    string `protobuf:"bytes,1,opt,name=b64,proto3" json:"b64,omitempty"`
	Buffer []byte `protobuf:"bytes,2,opt,name=buffer,proto3" json:"buffer,omitempty"`
	Size   int32  `protobuf:"varint,3,opt,name=size,proto3" json:"size,omitempty"`
	Total  int32  `protobuf:"varint,4,opt,name=total,proto3" json:"total,omitempty"`
}

func (x *Chunk) Reset() {
	*x = Chunk{}
	if protoimpl.UnsafeEnabled {
		mi := &file_core_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Chunk) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Chunk) ProtoMessage() {}

func (x *Chunk) ProtoReflect() protoreflect.Message {
	mi := &file_core_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Chunk.ProtoReflect.Descriptor instead.
func (*Chunk) Descriptor() ([]byte, []int) {
	return file_core_proto_rawDescGZIP(), []int{1}
}

func (x *Chunk) GetB64() string {
	if x != nil {
		return x.B64
	}
	return ""
}

func (x *Chunk) GetBuffer() []byte {
	if x != nil {
		return x.Buffer
	}
	return nil
}

func (x *Chunk) GetSize() int32 {
	if x != nil {
		return x.Size
	}
	return 0
}

func (x *Chunk) GetTotal() int32 {
	if x != nil {
		return x.Total
	}
	return 0
}

var File_core_proto protoreflect.FileDescriptor

var file_core_proto_rawDesc = []byte{
	0x0a, 0x0a, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x04, 0x63, 0x6f,
	0x72, 0x65, 0x1a, 0x0a, 0x64, 0x61, 0x74, 0x61, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x98,
	0x01, 0x0a, 0x0a, 0x4c, 0x6f, 0x62, 0x62, 0x79, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x12, 0x2c, 0x0a,
	0x05, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x16, 0x2e, 0x63,
	0x6f, 0x72, 0x65, 0x2e, 0x4c, 0x6f, 0x62, 0x62, 0x79, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x2e, 0x45,
	0x76, 0x65, 0x6e, 0x74, 0x52, 0x05, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x12, 0x19, 0x0a, 0x04, 0x70,
	0x65, 0x65, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x05, 0x2e, 0x50, 0x65, 0x65, 0x72,
	0x52, 0x04, 0x70, 0x65, 0x65, 0x72, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x22, 0x31, 0x0a, 0x05, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x12,
	0x08, 0x0a, 0x04, 0x4e, 0x4f, 0x4e, 0x45, 0x10, 0x00, 0x12, 0x08, 0x0a, 0x04, 0x4a, 0x4f, 0x49,
	0x4e, 0x10, 0x01, 0x12, 0x0a, 0x0a, 0x06, 0x55, 0x50, 0x44, 0x41, 0x54, 0x45, 0x10, 0x02, 0x12,
	0x08, 0x0a, 0x04, 0x45, 0x58, 0x49, 0x54, 0x10, 0x03, 0x22, 0x5b, 0x0a, 0x05, 0x43, 0x68, 0x75,
	0x6e, 0x6b, 0x12, 0x10, 0x0a, 0x03, 0x62, 0x36, 0x34, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x03, 0x62, 0x36, 0x34, 0x12, 0x16, 0x0a, 0x06, 0x62, 0x75, 0x66, 0x66, 0x65, 0x72, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x06, 0x62, 0x75, 0x66, 0x66, 0x65, 0x72, 0x12, 0x12, 0x0a, 0x04,
	0x73, 0x69, 0x7a, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x05, 0x52, 0x04, 0x73, 0x69, 0x7a, 0x65,
	0x12, 0x14, 0x0a, 0x05, 0x74, 0x6f, 0x74, 0x61, 0x6c, 0x18, 0x04, 0x20, 0x01, 0x28, 0x05, 0x52,
	0x05, 0x74, 0x6f, 0x74, 0x61, 0x6c, 0x2a, 0x54, 0x0a, 0x0c, 0x43, 0x61, 0x6c, 0x6c, 0x62, 0x61,
	0x63, 0x6b, 0x54, 0x79, 0x70, 0x65, 0x12, 0x0d, 0x0a, 0x09, 0x52, 0x45, 0x46, 0x52, 0x45, 0x53,
	0x48, 0x45, 0x44, 0x10, 0x00, 0x12, 0x0a, 0x0a, 0x06, 0x51, 0x55, 0x45, 0x55, 0x45, 0x44, 0x10,
	0x01, 0x12, 0x0b, 0x0a, 0x07, 0x49, 0x4e, 0x56, 0x49, 0x54, 0x45, 0x44, 0x10, 0x02, 0x12, 0x0d,
	0x0a, 0x09, 0x52, 0x45, 0x53, 0x50, 0x4f, 0x4e, 0x44, 0x45, 0x44, 0x10, 0x03, 0x12, 0x0d, 0x0a,
	0x09, 0x43, 0x4f, 0x4d, 0x50, 0x4c, 0x45, 0x54, 0x45, 0x44, 0x10, 0x05, 0x42, 0x0a, 0x5a, 0x08,
	0x2e, 0x3b, 0x6d, 0x6f, 0x64, 0x65, 0x6c, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_core_proto_rawDescOnce sync.Once
	file_core_proto_rawDescData = file_core_proto_rawDesc
)

func file_core_proto_rawDescGZIP() []byte {
	file_core_proto_rawDescOnce.Do(func() {
		file_core_proto_rawDescData = protoimpl.X.CompressGZIP(file_core_proto_rawDescData)
	})
	return file_core_proto_rawDescData
}

var file_core_proto_enumTypes = make([]protoimpl.EnumInfo, 2)
var file_core_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_core_proto_goTypes = []interface{}{
	(CallbackType)(0),     // 0: core.CallbackType
	(LobbyEvent_Event)(0), // 1: core.LobbyEvent.Event
	(*LobbyEvent)(nil),    // 2: core.LobbyEvent
	(*Chunk)(nil),         // 3: core.Chunk
	(*Peer)(nil),          // 4: Peer
}
var file_core_proto_depIdxs = []int32{
	1, // 0: core.LobbyEvent.event:type_name -> core.LobbyEvent.Event
	4, // 1: core.LobbyEvent.peer:type_name -> Peer
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_core_proto_init() }
func file_core_proto_init() {
	if File_core_proto != nil {
		return
	}
	file_data_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_core_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*LobbyEvent); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_core_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Chunk); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_core_proto_rawDesc,
			NumEnums:      2,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_core_proto_goTypes,
		DependencyIndexes: file_core_proto_depIdxs,
		EnumInfos:         file_core_proto_enumTypes,
		MessageInfos:      file_core_proto_msgTypes,
	}.Build()
	File_core_proto = out.File
	file_core_proto_rawDesc = nil
	file_core_proto_goTypes = nil
	file_core_proto_depIdxs = nil
}
