"use client";

import { type ReactNode, createContext, useContext, useMemo } from "react";
import {
    http,
    type Address,
    type GetContractReturnType,
    type HttpTransport,
    type PublicClient,
    createPublicClient,
    getContract,
} from "viem";
import { arbitrumSepolia } from "viem/chains";
import deployedContract from "./abi.json";

/* -------------------------------------------------------------------------- */
/*                               Initialization                               */
/* -------------------------------------------------------------------------- */
const rpcUrl = process.env.NEXT_PUBLIC_RPC_URL as string;
const chain = arbitrumSepolia;

/* -------------------------------------------------------------------------- */
/*                               ContractContext                              */
/* -------------------------------------------------------------------------- */
type ClientType = PublicClient<HttpTransport, typeof arbitrumSepolia>;
type PassTeePortType = GetContractReturnType<typeof deployedContract, ClientType, Address>;
interface ContractContextType {
    PassTeePort: PassTeePortType;
}
const ContractContext = createContext<ContractContextType | undefined>(undefined);

/* -------------------------------------------------------------------------- */
/*                              ContractProvider                              */
/* -------------------------------------------------------------------------- */
interface ContractProviderProps {
    children: ReactNode;
}
export function ContractProvider({ children }: ContractProviderProps) {
    const PassTeePort = useMemo(() => {
        const client = createPublicClient({
            chain: chain,
            transport: http(rpcUrl),
        });

        return getContract({
            address: process.env.NEXT_PUBLIC_TEE_PORT_ADDRESS as `0x${string}`,
            abi: deployedContract,
            client,
        });
    }, []);

    return <ContractContext.Provider value={{ PassTeePort }}>{children}</ContractContext.Provider>;
}

/* -------------------------------------------------------------------------- */
/*                             useContractContext                             */
/* -------------------------------------------------------------------------- */
export function useContractContext(): ContractContextType {
    const context = useContext(ContractContext);

    if (!context) {
        throw new Error("useContractContext must be used within a ContractProvider");
    }

    return context;
}
