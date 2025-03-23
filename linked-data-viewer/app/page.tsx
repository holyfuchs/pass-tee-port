"use client";

import { siteConfig } from "@/config/site";
import { useContractContext } from "@/contract/contractProvider";
import { Alert, Button, Input, Spinner } from "@heroui/react";
import { useState } from "react";
import { isAddress } from "viem";

export default function Home() {
    const [verifiedData, setVerifiedData] = useState<string | null>(null);
    const [loading, setLoading] = useState<boolean | null>(null);
    const { PassTeePort } = useContractContext();

    const checkPassTeePort = async (e: React.FormEvent<HTMLFormElement>) => {
        e.preventDefault();
        setLoading(true);
        const formData = new FormData(e.target as HTMLFormElement);
        try {
            const walletAddress = formData.get("walletAddress") as string;
            const res = await PassTeePort.read.wallet_to_passport([walletAddress]);
            setVerifiedData(Buffer.from((res as string).slice(2), "hex").toString("utf8"));
        } catch (error) {
            console.error(error);
            setLoading(null);
        } finally {
            setLoading(false);
        }
    };

    const checkOtherWallet = async () => {
        setLoading(null);
    };

    return (
        <>
            <header className="absolute flex justify-between p-4 px-5 top-0 left-0 right-0">
                <div className="flex items-center gap-2">
                    <span className="font-semibold text-2xl sm:text-3xl">🪪 {siteConfig.name}</span>
                </div>
            </header>
            <main className="h-full w-full flex gap-3 flex-col items-center justify-center p-5">
                {loading && <Spinner size="lg" />}
                {loading === null && (
                    <form
                        className="w-full max-w-xl flex gap-3 flex-col items-center justify-center"
                        onSubmit={checkPassTeePort}
                    >
                        <Alert title="Enter your wallet address and click the button to check if it is verified by Pass-Tee-Port" />
                        <Input
                            name="walletAddress"
                            label="Wallet Address"
                            placeholder="Enter a wallet address"
                            type="text"
                            fullWidth={true}
                            validate={(value) => (isAddress(value) ? null : "Invalid ethereum address")}
                        />
                        <Button color="primary" variant="solid" fullWidth={true} type="submit">
                            Check
                        </Button>
                    </form>
                )}
                {loading === false && (
                    <div className="w-full max-w-xl flex gap-3 flex-col items-center justify-center">
                        {verifiedData && (
                            <Alert
                                color="success"
                                title="The wallet is verified by Pass-Tee-Port"
                                description={verifiedData}
                            />
                        )}
                        {!verifiedData && <Alert color="danger" title="The wallet is not verified by Pass-Tee-Port" />}
                        <Button variant="solid" fullWidth={true} onPress={checkOtherWallet}>
                            Check other wallet
                        </Button>
                    </div>
                )}
            </main>
        </>
    );
}
