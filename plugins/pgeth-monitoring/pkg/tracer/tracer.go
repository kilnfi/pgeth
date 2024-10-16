package tracer

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
)

type MonitoringTracer struct {
	Action Action
	Cursor Action
}

func (m *MonitoringTracer) Clear() {
	m.Action = nil
	m.Cursor = nil
}

func NewTracer() (*tracing.Hooks, *MonitoringTracer) {
	mt := &MonitoringTracer{}
	return &tracing.Hooks{
		OnTxStart: mt.OnTxStart,
		OnTxEnd:   mt.OnTxEnd,
		OnEnter:   mt.OnEnter,
		OnExit:    mt.OnExit,
		OnOpcode:  mt.OnOpcode,
	}, mt
}

func (m *MonitoringTracer) CaptureTxStart(gasLimit uint64) {
}

func (m *MonitoringTracer) CaptureTxEnd(restGas uint64) {
}

func (m *MonitoringTracer) OnTxStart(vm *tracing.VMContext, tx *types.Transaction, from common.Address) {
	copyInput := make([]byte, len(tx.Data()))
	usedValue := big.NewInt(0)
	if tx.Value() != nil {
		usedValue.Set(tx.Value())
	}
	copy(copyInput, tx.Data())
	to := common.Address{}
	if tx.To() != nil {
		to = *tx.To()
	}
	m.Action = &Call{
		CallType:      "initial_call",
		TypeValue:     "call",
		ChildrenValue: []Action{},
		ParentValue:   nil,
		DepthValue:    0,

		ContextValue: common.Address{},
		CodeValue:    common.Address{},

		ForwardedContext: to,
		ForwardedCode:    to,

		From:  from,
		To:    to,
		In:    copyInput,
		InHex: "0x" + hex.EncodeToString(copyInput),
		Value: "0x" + usedValue.Text(16),
	}
	m.Cursor = m.Action
}

func (m *MonitoringTracer) OnTxEnd(receipt *types.Receipt, err error) {
	output := m.Cursor.(*Call).Children()[0].(*Call).Out
	copyOutput := make([]byte, len(output))
	copy(copyOutput, output)
	m.Cursor.(*Call).Out = copyOutput
	m.Cursor.(*Call).OutHex = "0x" + hex.EncodeToString(copyOutput)
}

func (m *MonitoringTracer) OnEnter(depth int, typ byte, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
	callType := callOpcodeToString(typ)
	ctx, code := parentContextAndCode(m.Cursor)
	forwardedCode := to
	forwardedContext := to
	if callType == "delegatecall" {
		forwardedContext = from
	}
	usedValue := big.NewInt(0)
	if value != nil {
		usedValue.Set(value)
	}
	copyInput := make([]byte, len(input))
	copy(copyInput, input)
	call := &Call{
		CallType:      callType,
		TypeValue:     "call",
		ChildrenValue: []Action{},
		ParentValue:   m.Cursor,
		DepthValue:    m.Cursor.Depth() + 1,

		ForwardedContext: forwardedContext,
		ForwardedCode:    forwardedCode,
		ContextValue:     ctx,
		CodeValue:        code,
		From:             from,
		To:               to,
		In:               copyInput,
		InHex:            "0x" + hex.EncodeToString(copyInput),
		Value:            "0x" + usedValue.Text(16),
	}
	m.Cursor.AddChildren(call)
	m.Cursor = call
}

func (m *MonitoringTracer) OnExit(depth int, output []byte, gasUsed uint64, err error, reverted bool) {
	copyOutput := make([]byte, len(output))
	copy(copyOutput, output)
	m.Cursor.(*Call).Out = copyOutput
	m.Cursor.(*Call).OutHex = "0x" + hex.EncodeToString(copyOutput)
	m.Cursor = m.Cursor.Parent()
}

func (m *MonitoringTracer) OnOpcode(pc uint64, op byte, gas, cost uint64, scope tracing.OpContext, rData []byte, depth int, err error) {
	if op >= 160 && op <= 164 {
		stack := scope.StackData()
		stackLen := len(stack)
		var offset int64 = 0
		var size int64 = 0
		if stackLen >= 2 {
			offset = stack[stackLen-1].ToBig().Int64()
			size = stack[stackLen-2].ToBig().Int64()
		}
		fetchSize := size
		var data = []byte{}
		if int64(len(scope.MemoryData())) < offset {
			fetchSize = 0
			// generate zero array
		} else if int64(len(scope.MemoryData())) < offset+size {
			fetchSize -= (offset + size) - int64(len(scope.MemoryData()))
		}

		if fetchSize > 0 {
			data = make([]byte, fetchSize)
			copy(data, scope.MemoryData()[offset:offset+fetchSize])
		}

		if fetchSize < size {
			data = addZeros(data, size-fetchSize)
		}

		topics := []common.Hash{}
		for idx := 0; idx < int(op-160); idx++ {
			if stackLen-3-idx >= 0 {
				topics = append(topics, stack[stackLen-3-idx].Bytes32())
			}
		}

		ctx, code := parentContextAndCode(m.Cursor)

		m.Cursor.AddChildren(&Event{
			LogType:   fmt.Sprintf("log%d", op-160),
			TypeValue: "event",
			Data:      data,
			DataHex:   "0x" + hex.EncodeToString(data),
			Topics:    topics,
			From:      scope.Address(),

			ContextValue: ctx,
			CodeValue:    code,
			ParentValue:  m.Cursor,
			DepthValue:   m.Cursor.Depth() + 1,
		})
	}
	if op == 253 {
		errorType := "revert"
		data := []byte{}
		stack := scope.StackData()
		stackLen := len(stack)
		var offset int64 = 0
		var size int64 = 0
		if stackLen >= 2 {
			offset = stack[stackLen-1].ToBig().Int64()
			size = stack[stackLen-2].ToBig().Int64()
		}
		fetchSize := size
		if int64(len(scope.MemoryData())) < offset {
			fetchSize = 0
			// generate zero array
		} else if int64(len(scope.MemoryData())) < offset+size {
			fetchSize -= (offset + size) - int64(len(scope.MemoryData()))
		}

		if fetchSize > 0 {
			data = make([]byte, fetchSize)
			copy(data, scope.MemoryData()[offset:offset+fetchSize])
		}

		if fetchSize < size {
			data = addZeros(data, size-fetchSize)
		}

		ctx, code := parentContextAndCode(m.Cursor)

		m.Cursor.AddChildren(&Revert{
			ErrorType:    errorType,
			TypeValue:    "revert",
			Data:         data,
			DataHex:      "0x" + hex.EncodeToString(data),
			From:         scope.Address(),
			ContextValue: ctx,
			CodeValue:    code,
			ParentValue:  m.Cursor,
			DepthValue:   m.Cursor.Depth() + 1,
		})
	}
}

func (m *MonitoringTracer) OnFault(pc uint64, op byte, gas, cost uint64, scope tracing.OpContext, depth int, err error) {
	if op != 253 {
		ctx, code := parentContextAndCode(m.Cursor)
		m.Cursor.AddChildren(&Revert{
			ErrorType:    "panic",
			TypeValue:    "revert",
			Data:         []byte{},
			DataHex:      "0x" + hex.EncodeToString([]byte{}),
			From:         scope.Address(),
			ContextValue: ctx,
			CodeValue:    code,
			ParentValue:  m.Cursor,
			DepthValue:   m.Cursor.Depth() + 1,
		})
	}
}

func callOpcodeToString(c byte) string {
	switch c {
	case 241:
		return "call"
	case 244:
		return "delegatecall"
	case 250:
		return "staticcall"
	default:
		return fmt.Sprintf("unknown %d", c)
	}
}

func parentContextAndCode(p Action) (common.Address, common.Address) {
	if p != nil {
		return p.(*Call).ForwardedContext, p.(*Call).ForwardedCode
	}
	return common.Address{}, common.Address{}
}

func addZeros(arr []byte, zeros int64) []byte {
	return append(arr, make([]byte, zeros)...)
}
