package server

import (
	"time"

	"github.com/bamchoh/uastack/ua"
	"github.com/bamchoh/uastack/ua/id"
)

func nid(i uint32) ua.NodeId { return ua.NewNumericNodeId(0, i) }

func (s *Server) setStatic(i uint32, v any) {
	if n := s.as.Node(nid(i)); n != nil {
		n.value = ua.DataValue{Value: ua.NewVariant(v), SourceTimestamp: s.startTime, ServerTimestamp: s.startTime}
	}
}

func (s *Server) setDynamic(i uint32, f func() any) {
	if n := s.as.Node(nid(i)); n != nil {
		n.OnRead = func(ReadContext) ua.DataValue {
			now := time.Now()
			return ua.DataValue{Value: ua.NewVariant(f()), SourceTimestamp: now, ServerTimestamp: now}
		}
	}
}

func (s *Server) buildInfo() ua.BuildInfo {
	return ua.BuildInfo{
		ProductUri: s.cfg.ProductURI, ManufacturerName: s.cfg.ManufacturerName, ProductName: s.cfg.ProductName,
		SoftwareVersion: s.cfg.SoftwareVersion, BuildNumber: s.cfg.BuildNumber, BuildDate: s.startTime,
	}
}

func (s *Server) setupServerObject() {
	s.setDynamic(id.Server_NamespaceArray, func() any { return s.as.NamespaceArray() })
	s.setStatic(id.Server_ServerArray, []string{s.cfg.ApplicationURI})
	s.setStatic(id.Server_ServiceLevel, byte(255))
	s.setStatic(id.Server_Auditing, false)
	s.setStatic(id.Server_EstimatedReturnTime, time.Time{})

	bi := s.buildInfo()
	s.setDynamic(id.Server_ServerStatus, func() any {
		return &ua.ServerStatusDataType{
			StartTime: s.startTime, CurrentTime: time.Now(), State: ua.ServerStateRunning, BuildInfo: bi,
		}
	})
	s.setStatic(id.Server_ServerStatus_StartTime, s.startTime)
	s.setDynamic(id.Server_ServerStatus_CurrentTime, func() any { return time.Now() })
	s.setStatic(id.Server_ServerStatus_State, int32(ua.ServerStateRunning))
	s.setStatic(id.Server_ServerStatus_BuildInfo, &bi)
	s.setStatic(id.Server_ServerStatus_BuildInfo_ProductUri, bi.ProductUri)
	s.setStatic(id.Server_ServerStatus_BuildInfo_ManufacturerName, bi.ManufacturerName)
	s.setStatic(id.Server_ServerStatus_BuildInfo_ProductName, bi.ProductName)
	s.setStatic(id.Server_ServerStatus_BuildInfo_SoftwareVersion, bi.SoftwareVersion)
	s.setStatic(id.Server_ServerStatus_BuildInfo_BuildNumber, bi.BuildNumber)
	s.setStatic(id.Server_ServerStatus_BuildInfo_BuildDate, bi.BuildDate)
	s.setStatic(id.Server_ServerStatus_SecondsTillShutdown, uint32(0))
	s.setStatic(id.Server_ServerStatus_ShutdownReason, ua.LocalizedText{})

	s.setStatic(id.Server_ServerCapabilities_ServerProfileArray, []string{
		"http://opcfoundation.org/UA-Profile/Server/MicroEmbeddedDevice",
		"http://opcfoundation.org/UA-Profile/Server/EmbeddedDataChangeSubscription",
	})
	s.setStatic(id.Server_ServerCapabilities_LocaleIdArray, []string{"en"})
	s.setStatic(id.Server_ServerCapabilities_MinSupportedSampleRate, float64(s.cfg.MinSamplingInterval/time.Millisecond))
	s.setStatic(id.Server_ServerCapabilities_MaxBrowseContinuationPoints, uint16(s.cfg.MaxContinuationPts))
	s.setStatic(id.Server_ServerCapabilities_MaxQueryContinuationPoints, uint16(0))
	s.setStatic(id.Server_ServerCapabilities_MaxHistoryContinuationPoints, uint16(0))
	s.setStatic(id.Server_ServerCapabilities_SoftwareCertificates, []ua.ExtensionObject{})
	s.setStatic(id.Server_ServerCapabilities_MaxArrayLength, uint32(ua.MaxArrayLength))
	s.setStatic(id.Server_ServerCapabilities_MaxStringLength, uint32(ua.MaxStringLength))
	s.setStatic(id.Server_ServerCapabilities_MaxByteStringLength, uint32(ua.MaxStringLength))
	ops := uint32(s.cfg.MaxOperationsPerCall)
	for _, i := range []uint32{
		id.Server_ServerCapabilities_OperationLimits_MaxNodesPerRead,
		id.Server_ServerCapabilities_OperationLimits_MaxNodesPerWrite,
		id.Server_ServerCapabilities_OperationLimits_MaxNodesPerMethodCall,
		id.Server_ServerCapabilities_OperationLimits_MaxNodesPerBrowse,
		id.Server_ServerCapabilities_OperationLimits_MaxNodesPerRegisterNodes,
		id.Server_ServerCapabilities_OperationLimits_MaxNodesPerTranslateBrowsePathsToNodeIds,
		id.Server_ServerCapabilities_OperationLimits_MaxMonitoredItemsPerCall,
	} {
		s.setStatic(i, ops)
	}
	for _, i := range []uint32{
		id.Server_ServerCapabilities_OperationLimits_MaxNodesPerHistoryReadData,
		id.Server_ServerCapabilities_OperationLimits_MaxNodesPerHistoryReadEvents,
		id.Server_ServerCapabilities_OperationLimits_MaxNodesPerHistoryUpdateData,
		id.Server_ServerCapabilities_OperationLimits_MaxNodesPerHistoryUpdateEvents,
		id.Server_ServerCapabilities_OperationLimits_MaxNodesPerNodeManagement,
	} {
		s.setStatic(i, uint32(0))
	}
	s.setStatic(id.Server_ServerDiagnostics_EnabledFlag, false)
	s.setStatic(id.Server_ServerRedundancy_RedundancySupport, int32(ua.RedundancySupportNone))
}
