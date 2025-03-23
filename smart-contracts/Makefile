
# RPC_ARB_SEPOLIA="https://sepolia-rollup.arbitrum.io/rpc"
RPC_ARB_SEPOLIA="https://arbitrum-sepolia.drpc.org"

include .env
export

deploy:
	forge script script/PassTeePort.s.sol:Deploy --broadcast --private-key $(PRIVATE_KEY) -vvvv --ffi

add_signer:
	forge script script/PassTeePort.s.sol:AddSigner --broadcast --private-key $(PRIVATE_KEY)

verify:
	forge verify-contract \
	--rpc-url $(RPC_ARB_SEPOLIA) \
	--verifier blockscout \
	--verifier-url 'https://arbitrum-sepolia.blockscout.com/api/' \
	0x191bCA32826A10558BE5db63Cc658b8653F0f783 \
	src/PassTeePort.sol:PassTeePort \
	--watch


