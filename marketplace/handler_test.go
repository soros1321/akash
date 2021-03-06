package marketplace_test

import (
	"testing"

	"github.com/ovrclk/akash/marketplace"
	"github.com/ovrclk/akash/types"
	"github.com/stretchr/testify/assert"
)

func TestHandler(t *testing.T) {

	{
		called := false
		h := marketplace.NewBuilder().OnTxSend(func(_ *types.TxSend) {
			called = true
		}).Create()
		h.OnTxSend(nil)
		assert.True(t, called, "OnTxSend")
		called = false
		h.OnTxCreateProvider(nil)
		h.OnTxCreateDeployment(nil)
		h.OnTxUpdateDeployment(nil)
		h.OnTxCreateOrder(nil)
		h.OnTxCreateFulfillment(nil)
		h.OnTxCreateLease(nil)
		h.OnTxCloseDeployment(nil)
		h.OnTxCloseFulfillment(nil)
		h.OnTxCloseLease(nil)
		assert.False(t, called, "OnTxSend")
	}

	{
		called := false
		h := marketplace.NewBuilder().OnTxCreateProvider(func(_ *types.TxCreateProvider) {
			called = true
		}).Create()
		h.OnTxCreateProvider(nil)
		assert.True(t, called, "OnTxCreateProvider")
		called = false
		h.OnTxSend(nil)
		h.OnTxCreateDeployment(nil)
		h.OnTxUpdateDeployment(nil)
		h.OnTxCreateOrder(nil)
		h.OnTxCreateFulfillment(nil)
		h.OnTxCreateLease(nil)
		h.OnTxCloseDeployment(nil)
		h.OnTxCloseFulfillment(nil)
		h.OnTxCloseLease(nil)
		assert.False(t, called, "OnTxCreateProvider")
	}

	{
		called := false
		h := marketplace.NewBuilder().OnTxCreateDeployment(func(_ *types.TxCreateDeployment) {
			called = true
		}).Create()
		h.OnTxCreateDeployment(nil)
		assert.True(t, called, "OnTxCreateDeployment")
		called = false
		h.OnTxSend(nil)
		h.OnTxCreateProvider(nil)
		h.OnTxUpdateDeployment(nil)
		h.OnTxCreateOrder(nil)
		h.OnTxCreateFulfillment(nil)
		h.OnTxCreateLease(nil)
		h.OnTxCloseDeployment(nil)
		h.OnTxCloseFulfillment(nil)
		h.OnTxCloseLease(nil)
		assert.False(t, called, "OnTxCreateDeployment")
	}

	{
		called := false
		h := marketplace.NewBuilder().OnTxUpdateDeployment(func(_ *types.TxUpdateDeployment) {
			called = true
		}).Create()
		h.OnTxUpdateDeployment(nil)
		assert.True(t, called, "OnTxCreateDeployment")
		called = false
		h.OnTxSend(nil)
		h.OnTxCreateProvider(nil)
		h.OnTxCreateDeployment(nil)
		h.OnTxCreateOrder(nil)
		h.OnTxCreateFulfillment(nil)
		h.OnTxCreateLease(nil)
		h.OnTxCloseDeployment(nil)
		h.OnTxCloseFulfillment(nil)
		h.OnTxCloseLease(nil)
		assert.False(t, called, "OnTxCreateDeployment")
	}

	{
		called := false
		h := marketplace.NewBuilder().OnTxCreateOrder(func(_ *types.TxCreateOrder) {
			called = true
		}).Create()
		h.OnTxCreateOrder(nil)
		assert.True(t, called, "OnTxCreateOrder")
		called = false
		h.OnTxSend(nil)
		h.OnTxCreateProvider(nil)
		h.OnTxCreateDeployment(nil)
		h.OnTxUpdateDeployment(nil)
		h.OnTxCreateFulfillment(nil)
		h.OnTxCreateLease(nil)
		h.OnTxCloseDeployment(nil)
		h.OnTxCloseFulfillment(nil)
		h.OnTxCloseLease(nil)
		assert.False(t, called, "OnTxCreateOrder")
	}

	{
		called := false
		h := marketplace.NewBuilder().OnTxCreateFulfillment(func(_ *types.TxCreateFulfillment) {
			called = true
		}).Create()
		h.OnTxCreateFulfillment(nil)
		assert.True(t, called, "OnTxCreateFulfillment")
		called = false
		h.OnTxSend(nil)
		h.OnTxCreateProvider(nil)
		h.OnTxCreateDeployment(nil)
		h.OnTxUpdateDeployment(nil)
		h.OnTxCreateOrder(nil)
		h.OnTxCreateLease(nil)
		h.OnTxCloseDeployment(nil)
		h.OnTxCloseFulfillment(nil)
		h.OnTxCloseLease(nil)
		assert.False(t, called, "OnTxCreateFulfillment")
	}

	{
		called := false
		h := marketplace.NewBuilder().OnTxCreateLease(func(_ *types.TxCreateLease) {
			called = true
		}).Create()
		h.OnTxCreateLease(nil)
		assert.True(t, called, "OnTxCreateLease")
		called = false
		h.OnTxSend(nil)
		h.OnTxCreateProvider(nil)
		h.OnTxCreateDeployment(nil)
		h.OnTxUpdateDeployment(nil)
		h.OnTxCreateOrder(nil)
		h.OnTxCreateFulfillment(nil)
		h.OnTxCloseDeployment(nil)
		h.OnTxCloseFulfillment(nil)
		h.OnTxCloseLease(nil)
		assert.False(t, called, "OnTxCreateLease")
	}

	{
		called := false
		h := marketplace.NewBuilder().OnTxCloseDeployment(func(_ *types.TxCloseDeployment) {
			called = true
		}).Create()
		h.OnTxCloseDeployment(nil)
		assert.True(t, called, "OnTxCloseDeployment")
		called = false
		h.OnTxSend(nil)
		h.OnTxCreateProvider(nil)
		h.OnTxCreateDeployment(nil)
		h.OnTxUpdateDeployment(nil)
		h.OnTxCreateOrder(nil)
		h.OnTxCreateFulfillment(nil)
		h.OnTxCreateLease(nil)
		h.OnTxCloseFulfillment(nil)
		h.OnTxCloseLease(nil)
		assert.False(t, called, "OnTxCloseDeployment")
	}

	{
		called := false
		h := marketplace.NewBuilder().OnTxCloseFulfillment(func(_ *types.TxCloseFulfillment) {
			called = true
		}).Create()
		h.OnTxCloseFulfillment(nil)
		assert.True(t, called, "OnTxCloseFulfillment")
		called = false
		h.OnTxSend(nil)
		h.OnTxCreateProvider(nil)
		h.OnTxCreateDeployment(nil)
		h.OnTxUpdateDeployment(nil)
		h.OnTxCreateOrder(nil)
		h.OnTxCreateFulfillment(nil)
		h.OnTxCreateLease(nil)
		h.OnTxCloseDeployment(nil)
		h.OnTxCloseLease(nil)
		assert.False(t, called, "OnTxCloseFulfillment")
	}

	{
		called := false
		h := marketplace.NewBuilder().OnTxCloseLease(func(_ *types.TxCloseLease) {
			called = true
		}).Create()
		h.OnTxCloseLease(nil)
		assert.True(t, called, "OnTxCloseLease")
		called = false
		h.OnTxSend(nil)
		h.OnTxCreateProvider(nil)
		h.OnTxCreateDeployment(nil)
		h.OnTxUpdateDeployment(nil)
		h.OnTxCreateOrder(nil)
		h.OnTxCreateFulfillment(nil)
		h.OnTxCreateLease(nil)
		h.OnTxCloseDeployment(nil)
		h.OnTxCloseFulfillment(nil)
		assert.False(t, called, "OnTxCloseLease")
	}
}
