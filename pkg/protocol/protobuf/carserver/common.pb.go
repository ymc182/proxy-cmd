// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v3.21.9
// source: common.proto

package carserver

import (
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

type Invalid int32

const (
	Invalid_INVALID Invalid = 0
)

// Enum value maps for Invalid.
var (
	Invalid_name = map[int32]string{
		0: "INVALID",
	}
	Invalid_value = map[string]int32{
		"INVALID": 0,
	}
)

func (x Invalid) Enum() *Invalid {
	p := new(Invalid)
	*p = x
	return p
}

func (x Invalid) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Invalid) Descriptor() protoreflect.EnumDescriptor {
	return file_common_proto_enumTypes[0].Descriptor()
}

func (Invalid) Type() protoreflect.EnumType {
	return &file_common_proto_enumTypes[0]
}

func (x Invalid) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Invalid.Descriptor instead.
func (Invalid) EnumDescriptor() ([]byte, []int) {
	return file_common_proto_rawDescGZIP(), []int{0}
}

type Void struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *Void) Reset() {
	*x = Void{}
	if protoimpl.UnsafeEnabled {
		mi := &file_common_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Void) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Void) ProtoMessage() {}

func (x *Void) ProtoReflect() protoreflect.Message {
	mi := &file_common_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Void.ProtoReflect.Descriptor instead.
func (*Void) Descriptor() ([]byte, []int) {
	return file_common_proto_rawDescGZIP(), []int{0}
}

type LatLong struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Latitude  float32 `protobuf:"fixed32,1,opt,name=latitude,proto3" json:"latitude,omitempty"`
	Longitude float32 `protobuf:"fixed32,2,opt,name=longitude,proto3" json:"longitude,omitempty"`
}

func (x *LatLong) Reset() {
	*x = LatLong{}
	if protoimpl.UnsafeEnabled {
		mi := &file_common_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *LatLong) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LatLong) ProtoMessage() {}

func (x *LatLong) ProtoReflect() protoreflect.Message {
	mi := &file_common_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LatLong.ProtoReflect.Descriptor instead.
func (*LatLong) Descriptor() ([]byte, []int) {
	return file_common_proto_rawDescGZIP(), []int{1}
}

func (x *LatLong) GetLatitude() float32 {
	if x != nil {
		return x.Latitude
	}
	return 0
}

func (x *LatLong) GetLongitude() float32 {
	if x != nil {
		return x.Longitude
	}
	return 0
}

type PreconditioningTimes struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Times:
	//
	//	*PreconditioningTimes_AllWeek
	//	*PreconditioningTimes_Weekdays
	Times isPreconditioningTimes_Times `protobuf_oneof:"times"`
}

func (x *PreconditioningTimes) Reset() {
	*x = PreconditioningTimes{}
	if protoimpl.UnsafeEnabled {
		mi := &file_common_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PreconditioningTimes) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PreconditioningTimes) ProtoMessage() {}

func (x *PreconditioningTimes) ProtoReflect() protoreflect.Message {
	mi := &file_common_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PreconditioningTimes.ProtoReflect.Descriptor instead.
func (*PreconditioningTimes) Descriptor() ([]byte, []int) {
	return file_common_proto_rawDescGZIP(), []int{2}
}

func (m *PreconditioningTimes) GetTimes() isPreconditioningTimes_Times {
	if m != nil {
		return m.Times
	}
	return nil
}

func (x *PreconditioningTimes) GetAllWeek() *Void {
	if x, ok := x.GetTimes().(*PreconditioningTimes_AllWeek); ok {
		return x.AllWeek
	}
	return nil
}

func (x *PreconditioningTimes) GetWeekdays() *Void {
	if x, ok := x.GetTimes().(*PreconditioningTimes_Weekdays); ok {
		return x.Weekdays
	}
	return nil
}

type isPreconditioningTimes_Times interface {
	isPreconditioningTimes_Times()
}

type PreconditioningTimes_AllWeek struct {
	AllWeek *Void `protobuf:"bytes,1,opt,name=all_week,json=allWeek,proto3,oneof"`
}

type PreconditioningTimes_Weekdays struct {
	Weekdays *Void `protobuf:"bytes,2,opt,name=weekdays,proto3,oneof"`
}

func (*PreconditioningTimes_AllWeek) isPreconditioningTimes_Times() {}

func (*PreconditioningTimes_Weekdays) isPreconditioningTimes_Times() {}

type OffPeakChargingTimes struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Times:
	//
	//	*OffPeakChargingTimes_AllWeek
	//	*OffPeakChargingTimes_Weekdays
	Times isOffPeakChargingTimes_Times `protobuf_oneof:"times"`
}

func (x *OffPeakChargingTimes) Reset() {
	*x = OffPeakChargingTimes{}
	if protoimpl.UnsafeEnabled {
		mi := &file_common_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *OffPeakChargingTimes) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*OffPeakChargingTimes) ProtoMessage() {}

func (x *OffPeakChargingTimes) ProtoReflect() protoreflect.Message {
	mi := &file_common_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use OffPeakChargingTimes.ProtoReflect.Descriptor instead.
func (*OffPeakChargingTimes) Descriptor() ([]byte, []int) {
	return file_common_proto_rawDescGZIP(), []int{3}
}

func (m *OffPeakChargingTimes) GetTimes() isOffPeakChargingTimes_Times {
	if m != nil {
		return m.Times
	}
	return nil
}

func (x *OffPeakChargingTimes) GetAllWeek() *Void {
	if x, ok := x.GetTimes().(*OffPeakChargingTimes_AllWeek); ok {
		return x.AllWeek
	}
	return nil
}

func (x *OffPeakChargingTimes) GetWeekdays() *Void {
	if x, ok := x.GetTimes().(*OffPeakChargingTimes_Weekdays); ok {
		return x.Weekdays
	}
	return nil
}

type isOffPeakChargingTimes_Times interface {
	isOffPeakChargingTimes_Times()
}

type OffPeakChargingTimes_AllWeek struct {
	AllWeek *Void `protobuf:"bytes,1,opt,name=all_week,json=allWeek,proto3,oneof"`
}

type OffPeakChargingTimes_Weekdays struct {
	Weekdays *Void `protobuf:"bytes,2,opt,name=weekdays,proto3,oneof"`
}

func (*OffPeakChargingTimes_AllWeek) isOffPeakChargingTimes_Times() {}

func (*OffPeakChargingTimes_Weekdays) isOffPeakChargingTimes_Times() {}

type ChargeSchedule struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id           uint64  `protobuf:"varint,1,opt,name=id,proto3" json:"id,omitempty"` // datetime in epoch time
	Name         string  `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	DaysOfWeek   int32   `protobuf:"varint,3,opt,name=days_of_week,json=daysOfWeek,proto3" json:"days_of_week,omitempty"`
	StartEnabled bool    `protobuf:"varint,4,opt,name=start_enabled,json=startEnabled,proto3" json:"start_enabled,omitempty"`
	StartTime    int32   `protobuf:"varint,5,opt,name=start_time,json=startTime,proto3" json:"start_time,omitempty"` // 24h in minutes
	EndEnabled   bool    `protobuf:"varint,6,opt,name=end_enabled,json=endEnabled,proto3" json:"end_enabled,omitempty"`
	EndTime      int32   `protobuf:"varint,7,opt,name=end_time,json=endTime,proto3" json:"end_time,omitempty"` // 24h in minutes
	OneTime      bool    `protobuf:"varint,8,opt,name=one_time,json=oneTime,proto3" json:"one_time,omitempty"`
	Enabled      bool    `protobuf:"varint,9,opt,name=enabled,proto3" json:"enabled,omitempty"`
	Latitude     float32 `protobuf:"fixed32,10,opt,name=latitude,proto3" json:"latitude,omitempty"`
	Longitude    float32 `protobuf:"fixed32,11,opt,name=longitude,proto3" json:"longitude,omitempty"`
}

func (x *ChargeSchedule) Reset() {
	*x = ChargeSchedule{}
	if protoimpl.UnsafeEnabled {
		mi := &file_common_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ChargeSchedule) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ChargeSchedule) ProtoMessage() {}

func (x *ChargeSchedule) ProtoReflect() protoreflect.Message {
	mi := &file_common_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ChargeSchedule.ProtoReflect.Descriptor instead.
func (*ChargeSchedule) Descriptor() ([]byte, []int) {
	return file_common_proto_rawDescGZIP(), []int{4}
}

func (x *ChargeSchedule) GetId() uint64 {
	if x != nil {
		return x.Id
	}
	return 0
}

func (x *ChargeSchedule) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *ChargeSchedule) GetDaysOfWeek() int32 {
	if x != nil {
		return x.DaysOfWeek
	}
	return 0
}

func (x *ChargeSchedule) GetStartEnabled() bool {
	if x != nil {
		return x.StartEnabled
	}
	return false
}

func (x *ChargeSchedule) GetStartTime() int32 {
	if x != nil {
		return x.StartTime
	}
	return 0
}

func (x *ChargeSchedule) GetEndEnabled() bool {
	if x != nil {
		return x.EndEnabled
	}
	return false
}

func (x *ChargeSchedule) GetEndTime() int32 {
	if x != nil {
		return x.EndTime
	}
	return 0
}

func (x *ChargeSchedule) GetOneTime() bool {
	if x != nil {
		return x.OneTime
	}
	return false
}

func (x *ChargeSchedule) GetEnabled() bool {
	if x != nil {
		return x.Enabled
	}
	return false
}

func (x *ChargeSchedule) GetLatitude() float32 {
	if x != nil {
		return x.Latitude
	}
	return 0
}

func (x *ChargeSchedule) GetLongitude() float32 {
	if x != nil {
		return x.Longitude
	}
	return 0
}

type PreconditionSchedule struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id               uint64  `protobuf:"varint,1,opt,name=id,proto3" json:"id,omitempty"` // datetime in epoch time
	Name             string  `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	DaysOfWeek       int32   `protobuf:"varint,3,opt,name=days_of_week,json=daysOfWeek,proto3" json:"days_of_week,omitempty"`
	PreconditionTime int32   `protobuf:"varint,4,opt,name=precondition_time,json=preconditionTime,proto3" json:"precondition_time,omitempty"` // 24h in minutes
	OneTime          bool    `protobuf:"varint,5,opt,name=one_time,json=oneTime,proto3" json:"one_time,omitempty"`
	Enabled          bool    `protobuf:"varint,6,opt,name=enabled,proto3" json:"enabled,omitempty"`
	Latitude         float32 `protobuf:"fixed32,7,opt,name=latitude,proto3" json:"latitude,omitempty"`
	Longitude        float32 `protobuf:"fixed32,8,opt,name=longitude,proto3" json:"longitude,omitempty"`
}

func (x *PreconditionSchedule) Reset() {
	*x = PreconditionSchedule{}
	if protoimpl.UnsafeEnabled {
		mi := &file_common_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PreconditionSchedule) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PreconditionSchedule) ProtoMessage() {}

func (x *PreconditionSchedule) ProtoReflect() protoreflect.Message {
	mi := &file_common_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PreconditionSchedule.ProtoReflect.Descriptor instead.
func (*PreconditionSchedule) Descriptor() ([]byte, []int) {
	return file_common_proto_rawDescGZIP(), []int{5}
}

func (x *PreconditionSchedule) GetId() uint64 {
	if x != nil {
		return x.Id
	}
	return 0
}

func (x *PreconditionSchedule) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *PreconditionSchedule) GetDaysOfWeek() int32 {
	if x != nil {
		return x.DaysOfWeek
	}
	return 0
}

func (x *PreconditionSchedule) GetPreconditionTime() int32 {
	if x != nil {
		return x.PreconditionTime
	}
	return 0
}

func (x *PreconditionSchedule) GetOneTime() bool {
	if x != nil {
		return x.OneTime
	}
	return false
}

func (x *PreconditionSchedule) GetEnabled() bool {
	if x != nil {
		return x.Enabled
	}
	return false
}

func (x *PreconditionSchedule) GetLatitude() float32 {
	if x != nil {
		return x.Latitude
	}
	return 0
}

func (x *PreconditionSchedule) GetLongitude() float32 {
	if x != nil {
		return x.Longitude
	}
	return 0
}

var File_common_proto protoreflect.FileDescriptor

var file_common_proto_rawDesc = []byte{
	0x0a, 0x0c, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x09,
	0x43, 0x61, 0x72, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x22, 0x06, 0x0a, 0x04, 0x56, 0x6f, 0x69,
	0x64, 0x22, 0x43, 0x0a, 0x07, 0x4c, 0x61, 0x74, 0x4c, 0x6f, 0x6e, 0x67, 0x12, 0x1a, 0x0a, 0x08,
	0x6c, 0x61, 0x74, 0x69, 0x74, 0x75, 0x64, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x02, 0x52, 0x08,
	0x6c, 0x61, 0x74, 0x69, 0x74, 0x75, 0x64, 0x65, 0x12, 0x1c, 0x0a, 0x09, 0x6c, 0x6f, 0x6e, 0x67,
	0x69, 0x74, 0x75, 0x64, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x02, 0x52, 0x09, 0x6c, 0x6f, 0x6e,
	0x67, 0x69, 0x74, 0x75, 0x64, 0x65, 0x22, 0x7c, 0x0a, 0x14, 0x50, 0x72, 0x65, 0x63, 0x6f, 0x6e,
	0x64, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x69, 0x6e, 0x67, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x12, 0x2c,
	0x0a, 0x08, 0x61, 0x6c, 0x6c, 0x5f, 0x77, 0x65, 0x65, 0x6b, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x0f, 0x2e, 0x43, 0x61, 0x72, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x2e, 0x56, 0x6f, 0x69,
	0x64, 0x48, 0x00, 0x52, 0x07, 0x61, 0x6c, 0x6c, 0x57, 0x65, 0x65, 0x6b, 0x12, 0x2d, 0x0a, 0x08,
	0x77, 0x65, 0x65, 0x6b, 0x64, 0x61, 0x79, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0f,
	0x2e, 0x43, 0x61, 0x72, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x2e, 0x56, 0x6f, 0x69, 0x64, 0x48,
	0x00, 0x52, 0x08, 0x77, 0x65, 0x65, 0x6b, 0x64, 0x61, 0x79, 0x73, 0x42, 0x07, 0x0a, 0x05, 0x74,
	0x69, 0x6d, 0x65, 0x73, 0x22, 0x7c, 0x0a, 0x14, 0x4f, 0x66, 0x66, 0x50, 0x65, 0x61, 0x6b, 0x43,
	0x68, 0x61, 0x72, 0x67, 0x69, 0x6e, 0x67, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x12, 0x2c, 0x0a, 0x08,
	0x61, 0x6c, 0x6c, 0x5f, 0x77, 0x65, 0x65, 0x6b, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0f,
	0x2e, 0x43, 0x61, 0x72, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x2e, 0x56, 0x6f, 0x69, 0x64, 0x48,
	0x00, 0x52, 0x07, 0x61, 0x6c, 0x6c, 0x57, 0x65, 0x65, 0x6b, 0x12, 0x2d, 0x0a, 0x08, 0x77, 0x65,
	0x65, 0x6b, 0x64, 0x61, 0x79, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0f, 0x2e, 0x43,
	0x61, 0x72, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x2e, 0x56, 0x6f, 0x69, 0x64, 0x48, 0x00, 0x52,
	0x08, 0x77, 0x65, 0x65, 0x6b, 0x64, 0x61, 0x79, 0x73, 0x42, 0x07, 0x0a, 0x05, 0x74, 0x69, 0x6d,
	0x65, 0x73, 0x22, 0xc5, 0x02, 0x0a, 0x0e, 0x43, 0x68, 0x61, 0x72, 0x67, 0x65, 0x53, 0x63, 0x68,
	0x65, 0x64, 0x75, 0x6c, 0x65, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x04, 0x52, 0x02, 0x69, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x20, 0x0a, 0x0c, 0x64, 0x61, 0x79,
	0x73, 0x5f, 0x6f, 0x66, 0x5f, 0x77, 0x65, 0x65, 0x6b, 0x18, 0x03, 0x20, 0x01, 0x28, 0x05, 0x52,
	0x0a, 0x64, 0x61, 0x79, 0x73, 0x4f, 0x66, 0x57, 0x65, 0x65, 0x6b, 0x12, 0x23, 0x0a, 0x0d, 0x73,
	0x74, 0x61, 0x72, 0x74, 0x5f, 0x65, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x64, 0x18, 0x04, 0x20, 0x01,
	0x28, 0x08, 0x52, 0x0c, 0x73, 0x74, 0x61, 0x72, 0x74, 0x45, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x64,
	0x12, 0x1d, 0x0a, 0x0a, 0x73, 0x74, 0x61, 0x72, 0x74, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x05,
	0x20, 0x01, 0x28, 0x05, 0x52, 0x09, 0x73, 0x74, 0x61, 0x72, 0x74, 0x54, 0x69, 0x6d, 0x65, 0x12,
	0x1f, 0x0a, 0x0b, 0x65, 0x6e, 0x64, 0x5f, 0x65, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x64, 0x18, 0x06,
	0x20, 0x01, 0x28, 0x08, 0x52, 0x0a, 0x65, 0x6e, 0x64, 0x45, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x64,
	0x12, 0x19, 0x0a, 0x08, 0x65, 0x6e, 0x64, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x07, 0x20, 0x01,
	0x28, 0x05, 0x52, 0x07, 0x65, 0x6e, 0x64, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x19, 0x0a, 0x08, 0x6f,
	0x6e, 0x65, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x08, 0x20, 0x01, 0x28, 0x08, 0x52, 0x07, 0x6f,
	0x6e, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x65, 0x6e, 0x61, 0x62, 0x6c, 0x65,
	0x64, 0x18, 0x09, 0x20, 0x01, 0x28, 0x08, 0x52, 0x07, 0x65, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x64,
	0x12, 0x1a, 0x0a, 0x08, 0x6c, 0x61, 0x74, 0x69, 0x74, 0x75, 0x64, 0x65, 0x18, 0x0a, 0x20, 0x01,
	0x28, 0x02, 0x52, 0x08, 0x6c, 0x61, 0x74, 0x69, 0x74, 0x75, 0x64, 0x65, 0x12, 0x1c, 0x0a, 0x09,
	0x6c, 0x6f, 0x6e, 0x67, 0x69, 0x74, 0x75, 0x64, 0x65, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x02, 0x52,
	0x09, 0x6c, 0x6f, 0x6e, 0x67, 0x69, 0x74, 0x75, 0x64, 0x65, 0x22, 0xf8, 0x01, 0x0a, 0x14, 0x50,
	0x72, 0x65, 0x63, 0x6f, 0x6e, 0x64, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x53, 0x63, 0x68, 0x65, 0x64,
	0x75, 0x6c, 0x65, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x04, 0x52,
	0x02, 0x69, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x20, 0x0a, 0x0c, 0x64, 0x61, 0x79, 0x73, 0x5f,
	0x6f, 0x66, 0x5f, 0x77, 0x65, 0x65, 0x6b, 0x18, 0x03, 0x20, 0x01, 0x28, 0x05, 0x52, 0x0a, 0x64,
	0x61, 0x79, 0x73, 0x4f, 0x66, 0x57, 0x65, 0x65, 0x6b, 0x12, 0x2b, 0x0a, 0x11, 0x70, 0x72, 0x65,
	0x63, 0x6f, 0x6e, 0x64, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x04,
	0x20, 0x01, 0x28, 0x05, 0x52, 0x10, 0x70, 0x72, 0x65, 0x63, 0x6f, 0x6e, 0x64, 0x69, 0x74, 0x69,
	0x6f, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x19, 0x0a, 0x08, 0x6f, 0x6e, 0x65, 0x5f, 0x74, 0x69,
	0x6d, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x08, 0x52, 0x07, 0x6f, 0x6e, 0x65, 0x54, 0x69, 0x6d,
	0x65, 0x12, 0x18, 0x0a, 0x07, 0x65, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x64, 0x18, 0x06, 0x20, 0x01,
	0x28, 0x08, 0x52, 0x07, 0x65, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x64, 0x12, 0x1a, 0x0a, 0x08, 0x6c,
	0x61, 0x74, 0x69, 0x74, 0x75, 0x64, 0x65, 0x18, 0x07, 0x20, 0x01, 0x28, 0x02, 0x52, 0x08, 0x6c,
	0x61, 0x74, 0x69, 0x74, 0x75, 0x64, 0x65, 0x12, 0x1c, 0x0a, 0x09, 0x6c, 0x6f, 0x6e, 0x67, 0x69,
	0x74, 0x75, 0x64, 0x65, 0x18, 0x08, 0x20, 0x01, 0x28, 0x02, 0x52, 0x09, 0x6c, 0x6f, 0x6e, 0x67,
	0x69, 0x74, 0x75, 0x64, 0x65, 0x2a, 0x16, 0x0a, 0x07, 0x49, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64,
	0x12, 0x0b, 0x0a, 0x07, 0x49, 0x4e, 0x56, 0x41, 0x4c, 0x49, 0x44, 0x10, 0x00, 0x42, 0x6e, 0x0a,
	0x24, 0x63, 0x6f, 0x6d, 0x2e, 0x74, 0x65, 0x73, 0x6c, 0x61, 0x2e, 0x67, 0x65, 0x6e, 0x65, 0x72,
	0x61, 0x74, 0x65, 0x64, 0x2e, 0x63, 0x61, 0x72, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x2e, 0x63,
	0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x5a, 0x46, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f,
	0x6d, 0x2f, 0x74, 0x65, 0x73, 0x6c, 0x61, 0x6d, 0x6f, 0x74, 0x6f, 0x72, 0x73, 0x2f, 0x76, 0x65,
	0x68, 0x69, 0x63, 0x6c, 0x65, 0x2d, 0x63, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x2f, 0x70, 0x6b,
	0x67, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2f, 0x63, 0x61, 0x72, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_common_proto_rawDescOnce sync.Once
	file_common_proto_rawDescData = file_common_proto_rawDesc
)

func file_common_proto_rawDescGZIP() []byte {
	file_common_proto_rawDescOnce.Do(func() {
		file_common_proto_rawDescData = protoimpl.X.CompressGZIP(file_common_proto_rawDescData)
	})
	return file_common_proto_rawDescData
}

var file_common_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_common_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_common_proto_goTypes = []interface{}{
	(Invalid)(0),                 // 0: CarServer.Invalid
	(*Void)(nil),                 // 1: CarServer.Void
	(*LatLong)(nil),              // 2: CarServer.LatLong
	(*PreconditioningTimes)(nil), // 3: CarServer.PreconditioningTimes
	(*OffPeakChargingTimes)(nil), // 4: CarServer.OffPeakChargingTimes
	(*ChargeSchedule)(nil),       // 5: CarServer.ChargeSchedule
	(*PreconditionSchedule)(nil), // 6: CarServer.PreconditionSchedule
}
var file_common_proto_depIdxs = []int32{
	1, // 0: CarServer.PreconditioningTimes.all_week:type_name -> CarServer.Void
	1, // 1: CarServer.PreconditioningTimes.weekdays:type_name -> CarServer.Void
	1, // 2: CarServer.OffPeakChargingTimes.all_week:type_name -> CarServer.Void
	1, // 3: CarServer.OffPeakChargingTimes.weekdays:type_name -> CarServer.Void
	4, // [4:4] is the sub-list for method output_type
	4, // [4:4] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_common_proto_init() }
func file_common_proto_init() {
	if File_common_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_common_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Void); i {
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
		file_common_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*LatLong); i {
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
		file_common_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PreconditioningTimes); i {
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
		file_common_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*OffPeakChargingTimes); i {
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
		file_common_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ChargeSchedule); i {
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
		file_common_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PreconditionSchedule); i {
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
	file_common_proto_msgTypes[2].OneofWrappers = []interface{}{
		(*PreconditioningTimes_AllWeek)(nil),
		(*PreconditioningTimes_Weekdays)(nil),
	}
	file_common_proto_msgTypes[3].OneofWrappers = []interface{}{
		(*OffPeakChargingTimes_AllWeek)(nil),
		(*OffPeakChargingTimes_Weekdays)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_common_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_common_proto_goTypes,
		DependencyIndexes: file_common_proto_depIdxs,
		EnumInfos:         file_common_proto_enumTypes,
		MessageInfos:      file_common_proto_msgTypes,
	}.Build()
	File_common_proto = out.File
	file_common_proto_rawDesc = nil
	file_common_proto_goTypes = nil
	file_common_proto_depIdxs = nil
}
