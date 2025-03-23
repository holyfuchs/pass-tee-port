"use client";

import { siteConfig } from "@/config/site";
import { Alert, Button, Input, Spinner } from "@heroui/react";
import { useState } from "react";

export default function Home() {
	const [verifiedData, setVerifiedData] = useState<string | null>(null);
	const [walletAddress, setWalletAddress] = useState<string>("");
    const [loading, setLoading] = useState<boolean | null>(null);

    const checkPassTeePort = async () => {
        setLoading(true);
		console.log("checkPassTeePort", walletAddress);
        await new Promise((resolve) => setTimeout(resolve, 1000));
        // setVerifiedData("This is a test result");
        setVerifiedData(null);
        setLoading(false);
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
                    <div className="w-full max-w-xl flex gap-3 flex-col items-center justify-center">
                        <Alert title="Enter your wallet address and click the button to check if it is verified by Pass-Tee-Port" />
                        <Input
                            label="Wallet Address"
                            placeholder="Enter a wallet address"
                            type="text"
                            fullWidth={true}
							value={walletAddress}
							onChange={(e) => setWalletAddress(e.target.value)}
                        />
                        <Button color="primary" variant="solid" fullWidth={true} onClick={checkPassTeePort}>
                            Check
                        </Button>
                    </div>
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
