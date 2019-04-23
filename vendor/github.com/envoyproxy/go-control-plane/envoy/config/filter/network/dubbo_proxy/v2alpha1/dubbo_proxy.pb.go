// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: envoy/config/filter/network/dubbo_proxy/v2alpha1/dubbo_proxy.proto

package v2

import (
	fmt "fmt"
	io "io"
	math "math"

	_ "github.com/envoyproxy/protoc-gen-validate/validate"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	types "github.com/gogo/protobuf/types"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion2 // please upgrade the proto package

type ProtocolType int32

const (
	ProtocolType_Dubbo ProtocolType = 0
)

var ProtocolType_name = map[int32]string{
	0: "Dubbo",
}

var ProtocolType_value = map[string]int32{
	"Dubbo": 0,
}

func (x ProtocolType) String() string {
	return proto.EnumName(ProtocolType_name, int32(x))
}

func (ProtocolType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_8ee9c82d7d1be64c, []int{0}
}

type SerializationType int32

const (
	SerializationType_Hessian2 SerializationType = 0
)

var SerializationType_name = map[int32]string{
	0: "Hessian2",
}

var SerializationType_value = map[string]int32{
	"Hessian2": 0,
}

func (x SerializationType) String() string {
	return proto.EnumName(SerializationType_name, int32(x))
}

func (SerializationType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_8ee9c82d7d1be64c, []int{1}
}

// [#protodoc-title: Dubbo Proxy]
// Dubbo Proxy filter configuration.
type DubboProxy struct {
	// The human readable prefix to use when emitting statistics.
	StatPrefix string `protobuf:"bytes,1,opt,name=stat_prefix,json=statPrefix,proto3" json:"stat_prefix,omitempty"`
	// Configure the protocol used.
	ProtocolType ProtocolType `protobuf:"varint,2,opt,name=protocol_type,json=protocolType,proto3,enum=envoy.config.filter.network.dubbo_proxy.v2alpha1.ProtocolType" json:"protocol_type,omitempty"`
	// Configure the serialization protocol used.
	SerializationType SerializationType `protobuf:"varint,3,opt,name=serialization_type,json=serializationType,proto3,enum=envoy.config.filter.network.dubbo_proxy.v2alpha1.SerializationType" json:"serialization_type,omitempty"`
	// The route table for the connection manager is static and is specified in this property.
	RouteConfig []*RouteConfiguration `protobuf:"bytes,4,rep,name=route_config,json=routeConfig,proto3" json:"route_config,omitempty"`
	// A list of individual Dubbo filters that make up the filter chain for requests made to the
	// Dubbo proxy. Order matters as the filters are processed sequentially. For backwards
	// compatibility, if no dubbo_filters are specified, a default Dubbo router filter
	// (`envoy.filters.dubbo.router`) is used.
	DubboFilters         []*DubboFilter `protobuf:"bytes,5,rep,name=dubbo_filters,json=dubboFilters,proto3" json:"dubbo_filters,omitempty"`
	XXX_NoUnkeyedLiteral struct{}       `json:"-"`
	XXX_unrecognized     []byte         `json:"-"`
	XXX_sizecache        int32          `json:"-"`
}

func (m *DubboProxy) Reset()         { *m = DubboProxy{} }
func (m *DubboProxy) String() string { return proto.CompactTextString(m) }
func (*DubboProxy) ProtoMessage()    {}
func (*DubboProxy) Descriptor() ([]byte, []int) {
	return fileDescriptor_8ee9c82d7d1be64c, []int{0}
}
func (m *DubboProxy) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *DubboProxy) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_DubboProxy.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalTo(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *DubboProxy) XXX_Merge(src proto.Message) {
	xxx_messageInfo_DubboProxy.Merge(m, src)
}
func (m *DubboProxy) XXX_Size() int {
	return m.Size()
}
func (m *DubboProxy) XXX_DiscardUnknown() {
	xxx_messageInfo_DubboProxy.DiscardUnknown(m)
}

var xxx_messageInfo_DubboProxy proto.InternalMessageInfo

func (m *DubboProxy) GetStatPrefix() string {
	if m != nil {
		return m.StatPrefix
	}
	return ""
}

func (m *DubboProxy) GetProtocolType() ProtocolType {
	if m != nil {
		return m.ProtocolType
	}
	return ProtocolType_Dubbo
}

func (m *DubboProxy) GetSerializationType() SerializationType {
	if m != nil {
		return m.SerializationType
	}
	return SerializationType_Hessian2
}

func (m *DubboProxy) GetRouteConfig() []*RouteConfiguration {
	if m != nil {
		return m.RouteConfig
	}
	return nil
}

func (m *DubboProxy) GetDubboFilters() []*DubboFilter {
	if m != nil {
		return m.DubboFilters
	}
	return nil
}

// DubboFilter configures a Dubbo filter.
// [#comment:next free field: 3]
type DubboFilter struct {
	// The name of the filter to instantiate. The name must match a supported
	// filter.
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// Filter specific configuration which depends on the filter being
	// instantiated. See the supported filters for further documentation.
	Config               *types.Any `protobuf:"bytes,2,opt,name=config,proto3" json:"config,omitempty"`
	XXX_NoUnkeyedLiteral struct{}   `json:"-"`
	XXX_unrecognized     []byte     `json:"-"`
	XXX_sizecache        int32      `json:"-"`
}

func (m *DubboFilter) Reset()         { *m = DubboFilter{} }
func (m *DubboFilter) String() string { return proto.CompactTextString(m) }
func (*DubboFilter) ProtoMessage()    {}
func (*DubboFilter) Descriptor() ([]byte, []int) {
	return fileDescriptor_8ee9c82d7d1be64c, []int{1}
}
func (m *DubboFilter) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *DubboFilter) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_DubboFilter.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalTo(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *DubboFilter) XXX_Merge(src proto.Message) {
	xxx_messageInfo_DubboFilter.Merge(m, src)
}
func (m *DubboFilter) XXX_Size() int {
	return m.Size()
}
func (m *DubboFilter) XXX_DiscardUnknown() {
	xxx_messageInfo_DubboFilter.DiscardUnknown(m)
}

var xxx_messageInfo_DubboFilter proto.InternalMessageInfo

func (m *DubboFilter) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *DubboFilter) GetConfig() *types.Any {
	if m != nil {
		return m.Config
	}
	return nil
}

func init() {
	proto.RegisterEnum("envoy.config.filter.network.dubbo_proxy.v2alpha1.ProtocolType", ProtocolType_name, ProtocolType_value)
	proto.RegisterEnum("envoy.config.filter.network.dubbo_proxy.v2alpha1.SerializationType", SerializationType_name, SerializationType_value)
	proto.RegisterType((*DubboProxy)(nil), "envoy.config.filter.network.dubbo_proxy.v2alpha1.DubboProxy")
	proto.RegisterType((*DubboFilter)(nil), "envoy.config.filter.network.dubbo_proxy.v2alpha1.DubboFilter")
}

func init() {
	proto.RegisterFile("envoy/config/filter/network/dubbo_proxy/v2alpha1/dubbo_proxy.proto", fileDescriptor_8ee9c82d7d1be64c)
}

var fileDescriptor_8ee9c82d7d1be64c = []byte{
	// 455 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x94, 0x92, 0x3d, 0x8f, 0xd3, 0x30,
	0x18, 0xc7, 0xcf, 0x7d, 0x39, 0xd1, 0x27, 0x39, 0xe8, 0x59, 0x27, 0xd1, 0xab, 0x44, 0x55, 0x6e,
	0xaa, 0x2a, 0x64, 0x43, 0x58, 0xe1, 0x24, 0x72, 0x27, 0xc4, 0x58, 0x05, 0xa6, 0x5b, 0x2a, 0xa7,
	0x75, 0x83, 0x45, 0xb0, 0x23, 0xc7, 0x2d, 0x0d, 0x03, 0x03, 0x1f, 0x8b, 0x89, 0x91, 0x91, 0x8f,
	0x80, 0xba, 0xf1, 0x05, 0x98, 0x51, 0xec, 0x54, 0x8d, 0xae, 0x53, 0x36, 0xe7, 0xf9, 0x3f, 0xf9,
	0xff, 0x9e, 0x37, 0x08, 0xb9, 0xdc, 0xa8, 0x82, 0x2e, 0x94, 0x5c, 0x89, 0x84, 0xae, 0x44, 0x6a,
	0xb8, 0xa6, 0x92, 0x9b, 0x2f, 0x4a, 0x7f, 0xa2, 0xcb, 0x75, 0x1c, 0xab, 0x79, 0xa6, 0xd5, 0xb6,
	0xa0, 0x9b, 0x80, 0xa5, 0xd9, 0x47, 0xf6, 0xa2, 0x1e, 0x24, 0x99, 0x56, 0x46, 0xe1, 0xe7, 0xd6,
	0x83, 0x38, 0x0f, 0xe2, 0x3c, 0x48, 0xe5, 0x41, 0xea, 0xe9, 0x7b, 0x8f, 0xe1, 0xab, 0xc6, 0x54,
	0xad, 0xd6, 0x86, 0x3b, 0xde, 0xf0, 0x32, 0x51, 0x2a, 0x49, 0x39, 0xb5, 0x5f, 0xf1, 0x7a, 0x45,
	0x99, 0xac, 0x4a, 0x19, 0x3e, 0xde, 0xb0, 0x54, 0x2c, 0x99, 0xe1, 0x74, 0xff, 0xa8, 0x84, 0x8b,
	0x44, 0x25, 0xca, 0x3e, 0x69, 0xf9, 0x72, 0xd1, 0xab, 0x7f, 0x6d, 0x80, 0xdb, 0x12, 0x37, 0x2b,
	0x69, 0x78, 0x0a, 0x5e, 0x6e, 0x98, 0x99, 0x67, 0x9a, 0xaf, 0xc4, 0x76, 0x80, 0xc6, 0x68, 0xd2,
	0x0b, 0x7b, 0x3f, 0xfe, 0xfe, 0x6c, 0x77, 0x74, 0x6b, 0x8c, 0x22, 0x28, 0xd5, 0x99, 0x15, 0xb1,
	0x82, 0x33, 0xeb, 0xb1, 0x50, 0xe9, 0xdc, 0x14, 0x19, 0x1f, 0xb4, 0xc6, 0x68, 0xf2, 0x30, 0xb8,
	0x26, 0x4d, 0x87, 0x41, 0x66, 0x95, 0xcd, 0x87, 0x22, 0xe3, 0x21, 0x94, 0xb4, 0xee, 0x77, 0xd4,
	0xea, 0xa3, 0xc8, 0xcf, 0x6a, 0x0a, 0xfe, 0x06, 0x38, 0xe7, 0x5a, 0xb0, 0x54, 0x7c, 0x65, 0x46,
	0x28, 0xe9, 0xa8, 0x6d, 0x4b, 0xbd, 0x69, 0x4e, 0x7d, 0x5f, 0xf7, 0x3a, 0x42, 0x9f, 0xe7, 0xf7,
	0x65, 0x9c, 0x80, 0x6f, 0x97, 0x30, 0x77, 0x90, 0x41, 0x67, 0xdc, 0x9e, 0x78, 0xc1, 0x6d, 0x73,
	0x72, 0x54, 0xba, 0xdc, 0xd8, 0xfc, 0xb5, 0xb6, 0xfe, 0x91, 0xa7, 0x0f, 0x31, 0x1c, 0xc3, 0x99,
	0xfb, 0xcf, 0x99, 0xe5, 0x83, 0xae, 0x25, 0xbd, 0x6e, 0x4e, 0xb2, 0xab, 0x7d, 0x6b, 0x13, 0x23,
	0x7f, 0x79, 0xf8, 0xc8, 0xaf, 0xee, 0xc0, 0xab, 0x89, 0xf8, 0x09, 0x74, 0x24, 0xfb, 0xcc, 0x8f,
	0x37, 0x6e, 0xc3, 0xf8, 0x19, 0x9c, 0x56, 0x4d, 0x97, 0x4b, 0xf6, 0x82, 0x0b, 0xe2, 0x2e, 0x90,
	0xec, 0x2f, 0x90, 0xbc, 0x91, 0x45, 0x54, 0xe5, 0x4c, 0x2f, 0xc1, 0xaf, 0xaf, 0x14, 0xf7, 0xa0,
	0x6b, 0x59, 0xfd, 0x93, 0xe9, 0x53, 0x38, 0x3f, 0x9a, 0x3b, 0xf6, 0xe1, 0xc1, 0x3b, 0x9e, 0xe7,
	0x82, 0xc9, 0xa0, 0x7f, 0x12, 0x2e, 0x7e, 0xed, 0x46, 0xe8, 0xf7, 0x6e, 0x84, 0xfe, 0xec, 0x46,
	0x08, 0xae, 0x85, 0x72, 0x6d, 0xbb, 0xce, 0x9a, 0x4e, 0x20, 0x7c, 0x74, 0xb8, 0x6e, 0x5b, 0xd3,
	0x0c, 0xdd, 0xb5, 0x36, 0x41, 0x7c, 0x6a, 0x0b, 0x7f, 0xf9, 0x3f, 0x00, 0x00, 0xff, 0xff, 0xd8,
	0xe0, 0x88, 0x5f, 0xfe, 0x03, 0x00, 0x00,
}

func (m *DubboProxy) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *DubboProxy) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if len(m.StatPrefix) > 0 {
		dAtA[i] = 0xa
		i++
		i = encodeVarintDubboProxy(dAtA, i, uint64(len(m.StatPrefix)))
		i += copy(dAtA[i:], m.StatPrefix)
	}
	if m.ProtocolType != 0 {
		dAtA[i] = 0x10
		i++
		i = encodeVarintDubboProxy(dAtA, i, uint64(m.ProtocolType))
	}
	if m.SerializationType != 0 {
		dAtA[i] = 0x18
		i++
		i = encodeVarintDubboProxy(dAtA, i, uint64(m.SerializationType))
	}
	if len(m.RouteConfig) > 0 {
		for _, msg := range m.RouteConfig {
			dAtA[i] = 0x22
			i++
			i = encodeVarintDubboProxy(dAtA, i, uint64(msg.Size()))
			n, err := msg.MarshalTo(dAtA[i:])
			if err != nil {
				return 0, err
			}
			i += n
		}
	}
	if len(m.DubboFilters) > 0 {
		for _, msg := range m.DubboFilters {
			dAtA[i] = 0x2a
			i++
			i = encodeVarintDubboProxy(dAtA, i, uint64(msg.Size()))
			n, err := msg.MarshalTo(dAtA[i:])
			if err != nil {
				return 0, err
			}
			i += n
		}
	}
	if m.XXX_unrecognized != nil {
		i += copy(dAtA[i:], m.XXX_unrecognized)
	}
	return i, nil
}

func (m *DubboFilter) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *DubboFilter) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if len(m.Name) > 0 {
		dAtA[i] = 0xa
		i++
		i = encodeVarintDubboProxy(dAtA, i, uint64(len(m.Name)))
		i += copy(dAtA[i:], m.Name)
	}
	if m.Config != nil {
		dAtA[i] = 0x12
		i++
		i = encodeVarintDubboProxy(dAtA, i, uint64(m.Config.Size()))
		n1, err := m.Config.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n1
	}
	if m.XXX_unrecognized != nil {
		i += copy(dAtA[i:], m.XXX_unrecognized)
	}
	return i, nil
}

func encodeVarintDubboProxy(dAtA []byte, offset int, v uint64) int {
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return offset + 1
}
func (m *DubboProxy) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.StatPrefix)
	if l > 0 {
		n += 1 + l + sovDubboProxy(uint64(l))
	}
	if m.ProtocolType != 0 {
		n += 1 + sovDubboProxy(uint64(m.ProtocolType))
	}
	if m.SerializationType != 0 {
		n += 1 + sovDubboProxy(uint64(m.SerializationType))
	}
	if len(m.RouteConfig) > 0 {
		for _, e := range m.RouteConfig {
			l = e.Size()
			n += 1 + l + sovDubboProxy(uint64(l))
		}
	}
	if len(m.DubboFilters) > 0 {
		for _, e := range m.DubboFilters {
			l = e.Size()
			n += 1 + l + sovDubboProxy(uint64(l))
		}
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *DubboFilter) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.Name)
	if l > 0 {
		n += 1 + l + sovDubboProxy(uint64(l))
	}
	if m.Config != nil {
		l = m.Config.Size()
		n += 1 + l + sovDubboProxy(uint64(l))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func sovDubboProxy(x uint64) (n int) {
	for {
		n++
		x >>= 7
		if x == 0 {
			break
		}
	}
	return n
}
func sozDubboProxy(x uint64) (n int) {
	return sovDubboProxy(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *DubboProxy) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowDubboProxy
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
			return fmt.Errorf("proto: DubboProxy: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: DubboProxy: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field StatPrefix", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowDubboProxy
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
				return ErrInvalidLengthDubboProxy
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthDubboProxy
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.StatPrefix = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field ProtocolType", wireType)
			}
			m.ProtocolType = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowDubboProxy
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.ProtocolType |= ProtocolType(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 3:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field SerializationType", wireType)
			}
			m.SerializationType = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowDubboProxy
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.SerializationType |= SerializationType(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field RouteConfig", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowDubboProxy
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
				return ErrInvalidLengthDubboProxy
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthDubboProxy
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.RouteConfig = append(m.RouteConfig, &RouteConfiguration{})
			if err := m.RouteConfig[len(m.RouteConfig)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 5:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field DubboFilters", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowDubboProxy
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
				return ErrInvalidLengthDubboProxy
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthDubboProxy
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.DubboFilters = append(m.DubboFilters, &DubboFilter{})
			if err := m.DubboFilters[len(m.DubboFilters)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipDubboProxy(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthDubboProxy
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthDubboProxy
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			m.XXX_unrecognized = append(m.XXX_unrecognized, dAtA[iNdEx:iNdEx+skippy]...)
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *DubboFilter) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowDubboProxy
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
			return fmt.Errorf("proto: DubboFilter: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: DubboFilter: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Name", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowDubboProxy
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
				return ErrInvalidLengthDubboProxy
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthDubboProxy
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Name = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Config", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowDubboProxy
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
				return ErrInvalidLengthDubboProxy
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthDubboProxy
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Config == nil {
				m.Config = &types.Any{}
			}
			if err := m.Config.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipDubboProxy(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthDubboProxy
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthDubboProxy
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			m.XXX_unrecognized = append(m.XXX_unrecognized, dAtA[iNdEx:iNdEx+skippy]...)
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipDubboProxy(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowDubboProxy
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
					return 0, ErrIntOverflowDubboProxy
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
			return iNdEx, nil
		case 1:
			iNdEx += 8
			return iNdEx, nil
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowDubboProxy
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
				return 0, ErrInvalidLengthDubboProxy
			}
			iNdEx += length
			if iNdEx < 0 {
				return 0, ErrInvalidLengthDubboProxy
			}
			return iNdEx, nil
		case 3:
			for {
				var innerWire uint64
				var start int = iNdEx
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return 0, ErrIntOverflowDubboProxy
					}
					if iNdEx >= l {
						return 0, io.ErrUnexpectedEOF
					}
					b := dAtA[iNdEx]
					iNdEx++
					innerWire |= (uint64(b) & 0x7F) << shift
					if b < 0x80 {
						break
					}
				}
				innerWireType := int(innerWire & 0x7)
				if innerWireType == 4 {
					break
				}
				next, err := skipDubboProxy(dAtA[start:])
				if err != nil {
					return 0, err
				}
				iNdEx = start + next
				if iNdEx < 0 {
					return 0, ErrInvalidLengthDubboProxy
				}
			}
			return iNdEx, nil
		case 4:
			return iNdEx, nil
		case 5:
			iNdEx += 4
			return iNdEx, nil
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
	}
	panic("unreachable")
}

var (
	ErrInvalidLengthDubboProxy = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowDubboProxy   = fmt.Errorf("proto: integer overflow")
)
