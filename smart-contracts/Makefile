
RPC_ARB_SEPOLIA="https://sepolia-rollup.arbitrum.io/rpc"

include .env
export

deploy:
	forge script script/PassTeePort.s.sol:Deploy --broadcast --private-key $(PRIVATE_KEY) -vvvv --ffi

verify:
	forge verify-contract \
	--rpc-url $(RPC_ARB_SEPOLIA) \
	--verifier blockscout \
	--verifier-url 'https://arbitrum-sepolia.blockscout.com/api/' \
	0x070d856cD94EA9a0e51ad35502Cf9e4329bF89ec \
	src/PassTeePort.sol:PassTeePort \
	--watch


